package dev.ipparser.scanner;

import dev.ipparser.core.PerfMonitor;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;

/**
 * Multithreaded TCP port scanner (Telnet mode) built on the shared
 * {@link AbstractScanner} pipeline. Opens a plain TCP socket per target and
 * classifies the outcome as {@link Result}.
 */
public class PortScanner extends AbstractScanner<PortScanner.Raw> {

    /** Outcome of a single TCP probe. */
    public enum Result {
        OPEN, CLOSED, TIMEOUT, ERROR
    }

    /** A raw probe outcome plus its wall-clock time, handed to the listener. */
    public static final class Raw {
        public final Result result;
        public final long timeMs;

        public Raw(Result result, long timeMs) {
            this.result = result;
            this.timeMs = timeMs;
        }
    }

    public PortScanner() {
        super("telnet");
    }

    /**
     * Parses port specification.
     * Accepts: "2000" (single) or "2000-2010" (range, inclusive).
     * @return array of [startPort, endPort] inclusive
     */
    public static int[] parsePorts(String portSpec) {
        String s = portSpec == null ? "" : portSpec.trim();
        if (s.contains("-")) {
            String[] parts = s.split("-");
            if (parts.length == 2) {
                try {
                    int start = Integer.parseInt(parts[0].trim());
                    int end = Integer.parseInt(parts[1].trim());
                    if (start > end) {
                        int tmp = start; start = end; end = tmp;
                    }
                    start = Math.max(1, Math.min(65535, start));
                    end = Math.max(1, Math.min(65535, end));
                    return new int[]{start, end};
                } catch (NumberFormatException ignored) {
                }
            }
        }
        try {
            int port = Integer.parseInt(s);
            port = Math.max(1, Math.min(65535, port));
            return new int[]{port, port};
        } catch (NumberFormatException e) {
            return new int[]{1, 1}; // fallback
        }
    }

    /** Opens the socket and classifies the outcome. */
    @Override
    protected Raw probe(String ip, int port, int timeoutMs) {
        long start = System.currentTimeMillis();
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(ip, port), timeoutMs);
            PerfMonitor.addSent(PerfMonitor.CONNECT_ESTIMATE);
            PerfMonitor.addRecv(PerfMonitor.CONNECT_ESTIMATE);
            return new Raw(Result.OPEN, System.currentTimeMillis() - start);
        } catch (IOException e) {
            PerfMonitor.addSent(PerfMonitor.CONNECT_ESTIMATE);
            PerfMonitor.addRecv(PerfMonitor.CONNECT_ESTIMATE);
            long elapsed = System.currentTimeMillis() - start;
            String msg = e.getMessage() != null ? e.getMessage().toLowerCase() : "";
            if (msg.contains("timeout") || msg.contains("timed out")) {
                return new Raw(Result.TIMEOUT, elapsed);
            } else if (msg.contains("refused") || msg.contains("reset") || msg.contains("unreachable")) {
                return new Raw(Result.CLOSED, elapsed);
            } else {
                return new Raw(Result.ERROR, elapsed);
            }
        }
    }
}