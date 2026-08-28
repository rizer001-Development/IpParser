package dev.ipparser.storage;

import dev.ipparser.core.AppPaths;
import dev.ipparser.core.Version;
import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * Simple, thread-safe file logger.
 *
 * Everything is written under {@code home/logs/} (the program's own directory,
 * never the CWD):
 *   ipparser-app.log        - application lifetime log
 *   scan-&lt;timestamp&gt;.log   - a dedicated log file per scan (created by beginScan)
 *
 * Lines are buffered and flushed on close; a flush is also performed on each
 * write when {@code enableFlush} is on so long scans can be followed live.
 */
public final class FileLog {

    private static final SimpleDateFormat FILE_TS = new SimpleDateFormat("yyyyMMdd-HHmmss");
    private static final SimpleDateFormat LINE_TS = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
    private static final int MAX_SCAN_LINES = 200_000; // guard against unbounded growth

    private final Object lock = new Object();

    private BufferedWriter appWriter;
    private BufferedWriter scanWriter;
    private long scanLineCount;
    private Path appPath;
    private Path currentScanPath;

    private final boolean enableFlush;

    private static final FileLog INSTANCE = new FileLog(true);

    public static FileLog get() {
        return INSTANCE;
    }

    private FileLog(boolean enableFlush) {
        this.enableFlush = enableFlush;
        openAppLog();
    }

    private void openAppLog() {
        try {
            AppPaths.logsDir();
            appPath = AppPaths.logsDir().resolve("ipparser-app.log");
            appWriter = Files.newBufferedWriter(appPath, StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
            app("INFO", "==== IP Parser v" + Version.VERSION + " starting ====");
        } catch (IOException e) {
            appWriter = null;
        }
    }

    /** Application-level line, written to ipparser-app.log. */
    public void app(String level, String msg) {
        String line = LINE_TS.format(new Date()) + "  [" + level + "]  " + msg;
        synchronized (lock) {
            if (appWriter == null) return;
            try {
                appWriter.write(line);
                appWriter.newLine();
                if (enableFlush) appWriter.flush();
            } catch (IOException ignored) {
            }
        }
    }

    public void info(String msg) { app("INFO", msg); }
    public void warn(String msg) { app("WARN", msg); }
    public void error(String msg) { app("ERROR", msg); }

    /**
     * Starts a new dedicated scan log file. Returns its path (null if the log
     * could not be created). Subsequent calls to {@link #scan(String,...)} write here.
     */
    public Path beginScan() {
        String name = "scan-" + FILE_TS.format(new Date()) + ".log";
        synchronized (lock) {
            closeQuietly(scanWriter);
            scanWriter = null;
            scanLineCount = 0;
            try {
                AppPaths.logsDir();
                currentScanPath = AppPaths.logsDir().resolve(name);
                scanWriter = Files.newBufferedWriter(currentScanPath, StandardCharsets.UTF_8,
                        StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
                scanLineCount = 0;
                return currentScanPath;
            } catch (IOException e) {
                currentScanPath = null;
                return null;
            }
        }
    }

    /** Path of the current scan log file, or null before beginScan / on error. */
    public Path currentScanPath() {
        synchronized (lock) {
            return currentScanPath;
        }
    }

    /**
     * Writes a line to the current scan log. With threshold auto-truncation so a
     * runaway scan cannot fill the disk.
     */
    public void scan(String line) {
        synchronized (lock) {
            if (scanWriter == null) return;
            if (scanLineCount >= MAX_SCAN_LINES) return;
            try {
                scanWriter.write(line);
                scanWriter.newLine();
                if (enableFlush) scanWriter.flush();
                scanLineCount++;
            } catch (IOException ignored) {
            }
        }
    }

    /** Writes the same line to both the scan log and the application log. */
    public void both(String level, String line) {
        scan(line);
        app(level, line);
    }

    /** Writes the scan-header describing a run. Buffer builds one line. */
    public void scanMode(String mode, String type, String inputMode, boolean cidr, long totalIps) {
        scan("=== Scan started ===");
        scan("Mode: " + mode + "   type=" + type + " input=" + inputMode.toLowerCase()
                + " CIDR=" + (cidr ? "on" : "off") + "   total IPs=" + totalIps);
    }

    public void closeScan() {
        synchronized (lock) {
            closeQuietly(scanWriter);
            scanWriter = null;
        }
    }

    public void close() {
        synchronized (lock) {
            closeQuietly(appWriter);
            closeQuietly(scanWriter);
            appWriter = null;
            scanWriter = null;
        }
    }

    private static void closeQuietly(BufferedWriter w) {
        if (w == null) return;
        try {
            w.flush();
            w.close();
        } catch (IOException ignored) {
        }
    }
}