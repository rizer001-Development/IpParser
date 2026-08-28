package dev.ipparser.core;

import com.sun.management.OperatingSystemMXBean;
import java.lang.management.ManagementFactory;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Real-time performance monitor for the parser process:
 *  - bytes sent/received by this app (instrumented at the socket level)
 *  - process CPU load
 *  - JVM heap (RAM) usage
 *
 * Implemented as a set of process-wide counters (a single instance per JVM is
 * what the app needs). {@code com.sun.management} is part of the standard JDK.
 */
public final class PerfMonitor {

    private static final OperatingSystemMXBean OS =
            (OperatingSystemMXBean) ManagementFactory.getOperatingSystemMXBean();

    /** Per-connection TCP handshake estimate (SYN / SYN-ACK+ACK / close),
     *  used by the telnet scanner where no application payload is exchanged. */
    public static final long CONNECT_ESTIMATE = 66;

    private static final AtomicLong sent = new AtomicLong(0);
    private static final AtomicLong recv = new AtomicLong(0);
    private static final AtomicLong lastSent = new AtomicLong(0);
    private static final AtomicLong lastRecv = new AtomicLong(0);
    private static volatile long sentRate; // bytes/sec
    private static volatile long recvRate;
    private static volatile long lastTickNanos = System.nanoTime();

    private PerfMonitor() {
    }

    public static void addSent(long bytes) {
        if (bytes > 0) sent.addAndGet(bytes);
    }

    public static void addRecv(long bytes) {
        if (bytes > 0) recv.addAndGet(bytes);
    }

    public static long getTotalSent() {
        return sent.get();
    }

    public static long getTotalRecv() {
        return recv.get();
    }

    /** Resets counters and rates (called at the start of each scan). */
    public static void reset() {
        sent.set(0);
        recv.set(0);
        lastSent.set(0);
        lastRecv.set(0);
        sentRate = 0;
        recvRate = 0;
        lastTickNanos = System.nanoTime();
    }

    /** Process CPU load in 0..1, or -1 if unavailable. */
    public static double getProcessCpuLoad() {
        try {
            double load = OS.getProcessCpuLoad();
            return load < 0 ? -1 : load;
        } catch (Throwable t) {
            return -1;
        }
    }

    /** Heap RAM currently used by this JVM, in MB. */
    public static long getHeapUsedMB() {
        Runtime rt = Runtime.getRuntime();
        return (rt.totalMemory() - rt.freeMemory()) / (1024L * 1024L);
    }

    /** Total heap of this JVM, in MB. */
    public static long getHeapTotalMB() {
        return Runtime.getRuntime().totalMemory() / (1024L * 1024L);
    }

    /** Call once per second: updates the bytes/sec rates. */
    public static void tickRates() {
        long now = System.nanoTime();
        long dtMs = (now - lastTickNanos) / 1_000_000L;
        lastTickNanos = now;
        long s = sent.get();
        long r = recv.get();
        if (dtMs > 0) {
            sentRate = ((s - lastSent.get()) * 1000L) / dtMs;
            recvRate = ((r - lastRecv.get()) * 1000L) / dtMs;
        }
        lastSent.set(s);
        lastRecv.set(r);
    }

    public static long getSentRate() {
        return sentRate;
    }

    public static long getRecvRate() {
        return recvRate;
    }
}