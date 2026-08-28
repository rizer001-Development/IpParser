package dev.ipparser.storage;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.ipparser.core.AppPaths;
import java.nio.file.Path;
import java.nio.file.Files;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class StorageTest {

    @TempDir
    static Path tmp;

    @BeforeAll
    static void pointHomeAtTemp() {
        // Must be set before the AppPaths/AppDb/FileLog singletons are touched.
        System.setProperty("ipparser.home", tmp.toString());
    }

    @AfterAll
    static void closeResources() {
        AppDb.get().close();
        FileLog.get().close();
    }

    @Test
    void appPathsResolveOwnDir() {
        Path home = AppPaths.home();
        assertTrue(home.toFile().isDirectory());
        // data + logs are under the own home
        assertTrue(AppPaths.dbFile().startsWith(home));
        assertEquals(AppPaths.home().resolve("data"), AppPaths.dataDir());
        assertEquals(AppPaths.home().resolve("logs"), AppPaths.logsDir());
    }

    @Test
    void sqliteRoundTripRequested() {
        AppDb.Adapter a = AppDb.get().adapter();
        a.set("k.int", "123");
        a.setBool("k.bool", true);
        a.set("k.str", "hello");

        assertEquals("123", a.get("k.int", "0"));
        assertEquals(123, a.getInt("k.int", 0));
        assertTrue(a.getBool("k.bool", false));
        assertEquals("hello", a.get("k.str", ""));
        assertEquals("missing_default", AppDb.get().get("nope", "missing_default"));
        // even-set file is on disk under data/
        assertTrue(Files.exists(AppPaths.dbFile()));
    }

    @Test
    void fileLogWritesAppAndScanFiles() {
        FileLog.get().both("INFO", "first-line");
        Path scan = FileLog.get().beginScan();
        assertNotNull(scan);
        FileLog.get().scan("target line");
        FileLog.get().closeScan();

        assertTrue(Files.exists(scan), "per-scan log created");
        String scanContent = read(scan);
        assertTrue(scanContent.contains("target line"));

        Path appLog = AppPaths.logsDir().resolve("ipparser-app.log");
        assertTrue(Files.exists(appLog));
        String appContent = read(appLog);
        assertTrue(appContent.contains("first-line"));
    }

    private static String read(Path p) {
        try {
            return new String(Files.readAllBytes(p), java.nio.charset.StandardCharsets.UTF_8);
        } catch (Exception e) {
            return "";
        }
    }
}