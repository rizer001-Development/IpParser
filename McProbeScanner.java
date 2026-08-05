import java.util.List;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Multithreaded Minecraft server scanner.
 *
 * THREE SEPARATE thread pools run simultaneously at maximum speed:
 *  - GENERATORS (CPU threads): expand the regex/CIDR octet lists into IP:port
 *    targets and push them into a bounded task queue (blocking put = natural
 *    backpressure, NO busy waiting and NO artificial sleeps).
 *  - NETWORK WORKERS (network threads): pull targets and run the Minecraft
 *    ping over the network (blocking I/O). These are NOT CPU threads: their
 *    count is independent of the CPU thread count and can go up to 1024.
 *  - PARSERS (CPU threads): pull raw probe results and run the callback
 *    (counting, stats, log formatting).
 *
 * Iteration order is IP-major: all ports of one IP are probed first, then the
 * next IP. Targets are generated lazily, so huge ranges never freeze the UI.
 */
public class McProbeScanner {

    public interface ScanCallback {
        void onResult(String ip, int port, McProbe.Result probe);
        void onProgress(long scanned, long total);
        void onFinished();
    }

    private static final int QUEUE_CAPACITY = 8192;

    private final AtomicBoolean running = new AtomicBoolean(false);
    private final AtomicBoolean generationDone = new AtomicBoolean(false);
    private final AtomicBoolean networkDone = new AtomicBoolean(false);
    private final AtomicInteger activeGenerators = new AtomicInteger(0);
    private final AtomicInteger activeNetwork = new AtomicInteger(0);
    private final AtomicLong scannedCount = new AtomicLong(0);
    private final LinkedBlockingQueue<Target> taskQueue = new LinkedBlockingQueue<>(QUEUE_CAPACITY);
    private final LinkedBlockingQueue<RawResult> resultQueue = new LinkedBlockingQueue<>(QUEUE_CAPACITY);

    private Thread[] generatorThreads = new Thread[0];
    private Thread[] networkThreads = new Thread[0];
    private Thread[] parserThreads = new Thread[0];

    /** One scan target (IP + port). */
    private static final class Target {
        final String ip;
        final int port;

        Target(String ip, int port) {
            this.ip = ip;
            this.port = port;
        }
    }

    /** A raw probe result waiting for CPU-side processing. */
    private static final class RawResult {
        final String ip;
        final int port;
        final McProbe.Result probe;

        RawResult(String ip, int port, McProbe.Result probe) {
            this.ip = ip;
            this.port = port;
            this.probe = probe;
        }
    }

    /**
     * Scans every IP produced by the syntax blocks with the Minecraft ping
     * protocol. Returns immediately; all work runs in background threads.
     *
     * @param blocks       list of address blocks, each 4 octet value lists
     *                     (from IpPattern.blocks)
     * @param parseThreads CPU threads that process results
     * @param genThreads   CPU threads that generate IPs from the blocks
     * @param netThreads   network threads that run the pings
     */
    public void startScan(List<List<List<Integer>>> blocks, int startPort, int endPort,
                          int timeoutMs, int parseThreads, int genThreads, int netThreads,
                          ScanCallback callback) {
        if (blocks == null || blocks.isEmpty()) {
            callback.onFinished();
            return;
        }
        running.set(true);
        generationDone.set(false);
        networkDone.set(false);
        scannedCount.set(0);
        taskQueue.clear();
        resultQueue.clear();

        long totalTargets = countTargets(blocks, startPort, endPort);
        if (totalTargets <= 0) {
            running.set(false);
            callback.onFinished();
            return;
        }
        long totalIps = countIps(blocks);

        int genCount = (int) Math.max(1, Math.min(genThreads, totalIps));
        int netCount = (int) Math.max(1, Math.min(netThreads, totalTargets));
        int parseCount = (int) Math.max(1, Math.min(parseThreads, totalTargets));
        activeGenerators.set(genCount);
        activeNetwork.set(netCount);

        generatorThreads = new Thread[genCount];
        for (int t = 0; t < genCount; t++) {
            final int slice = t;
            final long from = totalIps * slice / genCount;
            final long to = totalIps * (slice + 1) / genCount;
            generatorThreads[t] = new Thread(() ->
                            generateRange(blocks, from, to, startPort, endPort),
                    "mc-gen-" + t);
            generatorThreads[t].setDaemon(true);
        }

        networkThreads = new Thread[netCount];
        for (int t = 0; t < netCount; t++) {
            networkThreads[t] = new Thread(() -> networkLoop(timeoutMs), "mc-net-" + t);
            networkThreads[t].setDaemon(true);
        }

        parserThreads = new Thread[parseCount];
        for (int t = 0; t < parseCount; t++) {
            parserThreads[t] = new Thread(() -> parseLoop(callback, totalTargets), "mc-parser-" + t);
            parserThreads[t].setDaemon(true);
        }

        for (Thread g : generatorThreads) g.start();
        for (Thread n : networkThreads) n.start();
        for (Thread p : parserThreads) p.start();

        Thread finisher = new Thread(() -> {
            for (Thread g : generatorThreads) joinQuietly(g);
            for (Thread n : networkThreads) joinQuietly(n);
            for (Thread p : parserThreads) joinQuietly(p);
            callback.onFinished();
        }, "mc-finisher");
        finisher.setDaemon(true);
        finisher.start();
    }

    /** One CPU generator: walks IPs [from, to) (IP-major: all ports per IP), pushes targets. */
    private void generateRange(List<List<List<Integer>>> blocks, long from, long to,
                               int startPort, int endPort) {
        try {
            for (long idx = from; idx < to && running.get(); idx++) {
                int[] oct = decodeIndex(blocks, idx);
                String ip = oct[0] + "." + oct[1] + "." + oct[2] + "." + oct[3];
                for (int port = startPort; port <= endPort && running.get(); port++) {
                    try {
                        taskQueue.put(new Target(ip, port)); // blocks ONLY when full (backpressure)
                    } catch (InterruptedException e) {
                        return;
                    }
                }
            }
        } finally {
            if (activeGenerators.decrementAndGet() == 0) {
                generationDone.set(true);
            }
        }
    }

    /** One network worker: runs the Minecraft ping, hands raw results to the CPU parsers. */
    private void networkLoop(int timeoutMs) {
        try {
            while (running.get()) {
                Target t;
                try {
                    t = taskQueue.poll(50, TimeUnit.MILLISECONDS);
                } catch (InterruptedException e) {
                    return;
                }
                if (t == null) {
                    if (generationDone.get() && taskQueue.isEmpty()) {
                        return;
                    }
                    continue;
                }
                McProbe.Result probe = McProbe.ping(t.ip, t.port, timeoutMs);
                if (!running.get()) return; // stopped: drop the result
                try {
                    resultQueue.put(new RawResult(t.ip, t.port, probe));
                } catch (InterruptedException e) {
                    return;
                }
            }
        } finally {
            if (activeNetwork.decrementAndGet() == 0) {
                networkDone.set(true);
            }
        }
    }

    /** One CPU parser: processes raw results, counts progress. */
    private void parseLoop(ScanCallback callback, long totalTargets) {
        while (running.get()) {
            RawResult raw;
            try {
                raw = resultQueue.poll(50, TimeUnit.MILLISECONDS);
            } catch (InterruptedException e) {
                return;
            }
            if (raw == null) {
                if (networkDone.get() && resultQueue.isEmpty()) {
                    return;
                }
                continue;
            }
            callback.onResult(raw.ip, raw.port, raw.probe);
            long done = scannedCount.incrementAndGet();
            callback.onProgress(done, totalTargets);
        }
    }

    /**
     * Decodes a flat IP index (0..totalIps-1) across multiple address blocks
     * into 4 octet values. Blocks are concatenated in order.
     */
    private static int[] decodeIndex(List<List<List<Integer>>> blocks, long idx) {
        for (List<List<Integer>> octets : blocks) {
            long size = blockSize(octets);
            if (idx < size) {
                long rem = idx;
                int[] oct = new int[4];
                oct[3] = octets.get(3).get((int) (rem % octets.get(3).size()));
                rem /= octets.get(3).size();
                oct[2] = octets.get(2).get((int) (rem % octets.get(2).size()));
                rem /= octets.get(2).size();
                oct[1] = octets.get(1).get((int) (rem % octets.get(1).size()));
                rem /= octets.get(1).size();
                oct[0] = octets.get(0).get((int) rem);
                return oct;
            }
            idx -= size;
        }
        throw new IllegalStateException("IP index out of range");
    }

    private static long blockSize(List<List<Integer>> octets) {
        long total = 1;
        for (List<Integer> list : octets) {
            total *= list.size();
        }
        return total;
    }

    private static long countIps(List<List<List<Integer>>> blocks) {
        long total = 0;
        for (List<List<Integer>> octets : blocks) {
            total += blockSize(octets);
        }
        return total;
    }

    private long countTargets(List<List<List<Integer>>> blocks, int startPort, int endPort) {
        return countIps(blocks) * (long) (endPort - startPort + 1);
    }

    public void stop() {
        running.set(false);
        for (Thread g : generatorThreads) {
            if (g != null) g.interrupt();
        }
        for (Thread n : networkThreads) {
            if (n != null) n.interrupt();
        }
        for (Thread p : parserThreads) {
            if (p != null) p.interrupt();
        }
    }

    private static void joinQuietly(Thread t) {
        try {
            t.join();
        } catch (InterruptedException ignored) {
        }
    }
}
