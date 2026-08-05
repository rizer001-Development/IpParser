import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.List;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Multithreaded TCP port scanner.
 *
 * THREE SEPARATE thread pools run simultaneously at maximum speed:
 *  - GENERATORS (CPU threads): expand the regex/CIDR octet lists into IP:port
 *    targets and push them into a bounded task queue (blocking put = natural
 *    backpressure, NO busy waiting and NO artificial sleeps).
 *  - NETWORK WORKERS (network threads): pull targets and open the TCP sockets
 *    (blocking I/O). These are NOT CPU threads: their count is independent of
 *    the CPU thread count and can go up to 1024.
 *  - PARSERS (CPU threads): pull raw socket results and run the callback
 *    (counting, stats, log formatting).
 *
 * The three stages are decoupled by bounded queues, so generation never blocks
 * parsing and parsing always has work the moment results arrive. Memory stays
 * constant (bounded queues) no matter how large the range is, and the UI is
 * never blocked: all work runs in background daemon threads.
 * Iteration order is IP-major: all ports of one IP first, then the next IP.
 */
public class PortScanner {

    public enum Result {
        OPEN, CLOSED, TIMEOUT, ERROR
    }

    public interface ScanCallback {
        void onResult(String ip, int port, Result result, long timeMs);
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

    /** A raw socket result waiting for CPU-side processing. */
    private static final class RawResult {
        final String ip;
        final int port;
        final Result result;
        final long timeMs;

        RawResult(String ip, int port, Result result, long timeMs) {
            this.ip = ip;
            this.port = port;
            this.result = result;
            this.timeMs = timeMs;
        }
    }

    /**
     * Parses port specification.
     * Accepts: "2000" (single) or "2000-2010" (range, inclusive).
     * @return array of [startPort, endPort] inclusive
     */
    public static int[] parsePorts(String portSpec) {
        portSpec = portSpec.trim();
        if (portSpec.contains("-")) {
            String[] parts = portSpec.split("-");
            if (parts.length == 2) {
                try {
                    int start = Integer.parseInt(parts[0].trim());
                    int end = Integer.parseInt(parts[1].trim());
                    if (start > end) {
                        int tmp = start; start = end; end = tmp;
                    }
                    // Clamp to valid port range
                    start = Math.max(1, Math.min(65535, start));
                    end = Math.max(1, Math.min(65535, end));
                    return new int[]{start, end};
                } catch (NumberFormatException ignored) {
                }
            }
        }
        try {
            int port = Integer.parseInt(portSpec);
            port = Math.max(1, Math.min(65535, port));
            return new int[]{port, port};
        } catch (NumberFormatException e) {
            return new int[]{1, 1}; // fallback
        }
    }

    /**
     * Scans every IP produced by the syntax blocks, on every port in range.
     * Returns immediately; all work runs in background threads.
     *
     * @param blocks       list of address blocks, each 4 octet value lists
     *                     (from IpPattern.blocks)
     * @param parseThreads CPU threads that process results
     * @param genThreads   CPU threads that generate IPs from the blocks
     * @param netThreads   network threads that open the TCP sockets
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
                    "ip-gen-" + t);
            generatorThreads[t].setDaemon(true);
        }

        networkThreads = new Thread[netCount];
        for (int t = 0; t < netCount; t++) {
            networkThreads[t] = new Thread(() -> networkLoop(timeoutMs), "net-worker-" + t);
            networkThreads[t].setDaemon(true);
        }

        parserThreads = new Thread[parseCount];
        for (int t = 0; t < parseCount; t++) {
            parserThreads[t] = new Thread(() -> parseLoop(callback, totalTargets), "cpu-parser-" + t);
            parserThreads[t].setDaemon(true);
        }

        for (Thread g : generatorThreads) g.start();
        for (Thread n : networkThreads) n.start();
        for (Thread p : parserThreads) p.start();

        // Finisher: waits for all three pools, then reports done.
        Thread finisher = new Thread(() -> {
            for (Thread g : generatorThreads) joinQuietly(g);
            for (Thread n : networkThreads) joinQuietly(n);
            for (Thread p : parserThreads) joinQuietly(p);
            callback.onFinished();
        }, "scan-finisher");
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

    /** One network worker: opens TCP sockets, hands raw results to the CPU parsers. */
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
                RawResult raw = scanOne(t.ip, t.port, timeoutMs);
                if (raw == null) return; // stopped: drop the result
                try {
                    resultQueue.put(raw);
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
            callback.onResult(raw.ip, raw.port, raw.result, raw.timeMs);
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
        throw new IllegalStateException("IP index out of range: " + (idx + blockSize(blocks.get(0))));
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

    /** Opens the socket and produces a raw result (null when the scan was stopped). */
    private RawResult scanOne(String ip, int port, int timeoutMs) {
        long start = System.currentTimeMillis();
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(ip, port), timeoutMs);
            PerfMonitor.addSent(PerfMonitor.CONNECT_ESTIMATE);
            PerfMonitor.addRecv(PerfMonitor.CONNECT_ESTIMATE);
            if (!running.get()) return null; // stopped: skip noisy callbacks
            long elapsed = System.currentTimeMillis() - start;
            return new RawResult(ip, port, Result.OPEN, elapsed);
        } catch (IOException e) {
            PerfMonitor.addSent(PerfMonitor.CONNECT_ESTIMATE);
            PerfMonitor.addRecv(PerfMonitor.CONNECT_ESTIMATE);
            if (!running.get()) return null; // stopped: skip noisy callbacks
            long elapsed = System.currentTimeMillis() - start;
            String msg = e.getMessage() != null ? e.getMessage().toLowerCase() : "";
            if (msg.contains("timeout") || msg.contains("timed out")) {
                return new RawResult(ip, port, Result.TIMEOUT, elapsed);
            } else if (msg.contains("refused") || msg.contains("reset") || msg.contains("unreachable")) {
                return new RawResult(ip, port, Result.CLOSED, elapsed);
            } else {
                return new RawResult(ip, port, Result.ERROR, elapsed);
            }
        }
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
