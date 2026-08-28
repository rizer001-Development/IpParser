package dev.ipparser.storage;

import dev.ipparser.core.AppPaths;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.concurrent.locks.ReentrantLock;

/**
 * SQLite-backed key/value store for the application settings.
 *
 * Replaces the old plain-text {@code settings.txt}. The database lives at
 * {@code home/data/settings.db} (see {@link AppPaths}), so every portable copy
 * of the program keeps its own configuration.
 *
 * Thread-safe: all access is guarded by a single lock (settings are read and
 * written on the EDT; guard keeps the door open for background readers).
 */
public final class AppDb {

    private static final AppDb INSTANCE = new AppDb();

    private final ReentrantLock lock = new ReentrantLock();
    private Connection connection;

    private AppDb() {
    }

    public static AppDb get() {
        return INSTANCE;
    }

    /** Lazily initializes the database connection and schema. */
    private Connection conn() throws SQLException {
        Connection c = connection;
        if (c == null || c.isClosed()) {
            c = DriverManager.getConnection("jdbc:sqlite:" + AppPaths.dbFile().toString());
            try (Statement st = c.createStatement()) {
                st.executeUpdate("CREATE TABLE IF NOT EXISTS settings ("
                        + "key   TEXT PRIMARY KEY, "
                        + "value TEXT NOT NULL)");
            }
            connection = c;
        }
        return connection;
    }

    /** Returns the stored value for {@code key} or {@code def} when absent. */
    public String get(String key, String def) {
        lock.lock();
        try {
            try (PreparedStatement ps = conn().prepareStatement("SELECT value FROM settings WHERE key=?")) {
                ps.setString(1, key);
                try (ResultSet rs = ps.executeQuery()) {
                    if (rs.next()) {
                        return rs.getString(1);
                    }
                }
            } catch (SQLException ex) {
                // fall through to default
            }
            return def;
        } finally {
            lock.unlock();
        }
    }

    /** Convenience: boolean read. */
    public boolean getBool(String key, boolean def) {
        String v = get(key, null);
        return v == null ? def : "1".equals(v) || Boolean.parseBoolean(v);
    }

    /** Convenience: int read with a fallback. */
    public int getInt(String key, int def) {
        String v = get(key, null);
        if (v == null) return def;
        try {
            return Integer.parseInt(v);
        } catch (NumberFormatException e) {
            return def;
        }
    }

    /** Stores (or updates) a value. Returns true on success. */
    public boolean set(String key, String value) {
        lock.lock();
        try {
            try (PreparedStatement ps = conn().prepareStatement(
                    "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)")) {
                ps.setString(1, key);
                ps.setString(2, value == null ? "" : value);
                ps.executeUpdate();
                return true;
            } catch (SQLException ex) {
                return false;
            }
        } finally {
            lock.unlock();
        }
    }

    /** Closes the underlying database connection (releases the lock on the db file). */
    public void close() {
        lock.lock();
        try {
            if (connection != null) {
                try {
                    connection.close();
                } catch (SQLException ignored) {
                }
                connection = null;
            }
        } finally {
            lock.unlock();
        }
    }

    /** Convenience: boolean write. */
    public boolean setBool(String key, boolean value) {
        return set(key, value ? "1" : "0");
    }

    /** Convenience: int write. */
    public boolean setInt(String key, int value) {
        return set(key, Integer.toString(value));
    }

    /** A tiny builder so the GUI can batch several values in one style. */
    public Adapter adapter() {
        return new Adapter(this);
    }

    /** Fluent helper for grouped reads. */
    public static final class Adapter {
        private final AppDb db;

        Adapter(AppDb db) {
            this.db = db;
        }

        public String get(String key, String def) { return db.get(key, def); }
        public boolean getBool(String key, boolean def) { return db.getBool(key, def); }
        public int getInt(String key, int def) { return db.getInt(key, def); }
        public boolean set(String key, String value) { return db.set(key, value); }
        public boolean setBool(String key, boolean value) { return db.setBool(key, value); }
        public boolean setInt(String key, int value) { return db.setInt(key, value); }
    }
}