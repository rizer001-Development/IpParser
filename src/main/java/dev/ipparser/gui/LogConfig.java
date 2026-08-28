package dev.ipparser.gui;

import dev.ipparser.storage.AppDb;

/**
 * All "log settings" state that used to live as a pile of {@code volatile}
 * fields in the window class. Read by worker threads during a scan; written on
 * the EDT from the Log Settings dialog. Persisted to SQLite via {@link AppDb}.
 *
 * Changes are applied by mutating this object on the EDT; because each field is
 * a plain volatile reference read consistently enough for single-field checks,
 * the scanner threads observe whole-before-during-start values. Short-lived
 * races during a live scan are acceptable and were also present before.
 */
public final class LogConfig {

    // ----- what gets logged -----
    public volatile boolean logOpen = true;
    public volatile boolean logClosed;
    public volatile boolean logTimeout;
    public volatile boolean logError;
    public volatile boolean logActions = true;
    public volatile boolean external; // status 2 toggle

    // ----- MC-probe filters -----
    public final McFilters.Settings mc = new McFilters.Settings();

    private LogConfig() {
    }

    public static LogConfig load() {
        LogConfig c = new LogConfig();
        AppDb db = AppDb.get();
        c.logOpen = db.getBool("log.open", c.logOpen);
        c.logClosed = db.getBool("log.closed", c.logClosed);
        c.logTimeout = db.getBool("log.timeout", c.logTimeout);
        c.logError = db.getBool("log.error", c.logError);
        c.logActions = db.getBool("log.actions", c.logActions);
        c.external = db.getBool("syntax.external", c.external);

        c.mc.online = db.getBool("filter.online", c.mc.online);
        c.mc.onlineOp = db.get("filter.onlineOp", c.mc.onlineOp);
        c.mc.onlineVal = db.get("filter.onlineVal", c.mc.onlineVal);

        c.mc.version = db.getBool("filter.version", c.mc.version);
        c.mc.versionOp = db.get("filter.versionOp", c.mc.versionOp);
        c.mc.versionVal = db.get("filter.versionVal", c.mc.versionVal);

        c.mc.brand = db.getBool("filter.brand", c.mc.brand);
        c.mc.brandVal = db.get("filter.brandVal", c.mc.brandVal);

        c.mc.motd = db.getBool("filter.motd", c.mc.motd);
        c.mc.motdVal = db.get("filter.motdVal", c.mc.motdVal);

        c.mc.players = db.getBool("filter.players", c.mc.players);
        c.mc.playersVal = db.get("filter.playersVal", c.mc.playersVal);
        return c;
    }

    public void save() {
        AppDb.Adapter a = AppDb.get().adapter();
        a.setBool("log.open", logOpen);
        a.setBool("log.closed", logClosed);
        a.setBool("log.timeout", logTimeout);
        a.setBool("log.error", logError);
        a.setBool("log.actions", logActions);
        a.setBool("syntax.external", external);

        a.setBool("filter.online", mc.online);
        a.set("filter.onlineOp", mc.onlineOp);
        a.set("filter.onlineVal", mc.onlineVal);

        a.setBool("filter.version", mc.version);
        a.set("filter.versionOp", mc.versionOp);
        a.set("filter.versionVal", mc.versionVal);

        a.setBool("filter.brand", mc.brand);
        a.set("filter.brandVal", mc.brandVal);

        a.setBool("filter.motd", mc.motd);
        a.set("filter.motdVal", mc.motdVal);

        a.setBool("filter.players", mc.players);
        a.set("filter.playersVal", mc.playersVal);
    }
}