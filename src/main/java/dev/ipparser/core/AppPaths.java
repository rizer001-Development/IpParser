package dev.ipparser.core;

import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Resolves the application's own home directory ("portable" root).
 *
 * The program NEVER writes to the current working directory. All persistent
 * artifacts land inside its own home:
 *   home/data/settings.db   — SQLite database with the user's settings
 *   home/logs/...           — application and scan-result log files
 *
 * Resolution order:
 *   1. System property {@code ipparser.home} (set by the run.bat/run.sh scripts).
 *   2. The directory containing the application jar (code source).
 *   3. Fallback to the current working directory.
 */
public final class AppPaths {

    private static final Path HOME;

    static {
        Path home = null;
        String prop = System.getProperty("ipparser.home");
        if (prop != null && !prop.isBlank()) {
            home = Paths.get(prop);
        }
        if (home == null) {
            home = jarDirectory();
        }
        if (home == null) {
            home = Paths.get("").toAbsolutePath();
        }
        HOME = home.toAbsolutePath().normalize();
    }

    private AppPaths() {
    }

    public static Path home() {
        return HOME;
    }

    /** Directory for persistent data (SQLite DB). Created on demand. */
    public static Path dataDir() {
        return ensureDir(HOME.resolve("data"));
    }

    /** Directory for log files. Created on demand. */
    public static Path logsDir() {
        return ensureDir(HOME.resolve("logs"));
    }

    /** Path of the SQLite settings database. */
    public static Path dbFile() {
        return dataDir().resolve("settings.db");
    }

    /**
     * The directory the running jar was loaded from, or {@code null} when the
     * application was started from class directories (e.g. a debug launcher).
     */
    private static Path jarDirectory() {
        try {
            File jar = new File(AppPaths.class.getProtectionDomain()
                    .getCodeSource().getLocation().toURI());
            if (jar.isFile() && jar.getName().toLowerCase().endsWith(".jar")) {
                return jar.getParentFile().toPath();
            }
        } catch (Exception ignored) {
            // fall through to the CWD fallback
        }
        return null;
    }

    private static Path ensureDir(Path dir) {
        try {
            java.nio.file.Files.createDirectories(dir);
        } catch (Exception ignored) {
            // best effort; the caller may still be able to write into an existing dir
        }
        return dir;
    }
}