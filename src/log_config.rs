//! Port of the Java `LogConfig`: all "log settings" state that used to live in
//! the window class. Read by worker threads during a scan; written from the
//! Log Settings dialog. Persisted to SQLite via [`crate::storage`].

use crate::filters::FilterSettings;
use crate::storage as db;

/// Log/filter settings group.
#[derive(Debug, Clone)]
pub struct LogConfig {
    // ----- what gets logged -----
    pub log_open: bool,
    pub log_closed: bool,
    pub log_timeout: bool,
    pub log_error: bool,
    pub log_actions: bool,
    pub external: bool, // status 2 toggle

    // ----- MC-probe filters -----
    pub mc: FilterSettings,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            log_open: true,
            log_closed: false,
            log_timeout: false,
            log_error: false,
            log_actions: true,
            external: false,
            mc: FilterSettings::with_defaults(),
        }
    }
}

impl LogConfig {
    /// Loads the config from the SQLite settings store.
    pub fn load() -> Self {
        let d = Self::default();
        Self {
            log_open: db::get_bool("log.open", d.log_open),
            log_closed: db::get_bool("log.closed", d.log_closed),
            log_timeout: db::get_bool("log.timeout", d.log_timeout),
            log_error: db::get_bool("log.error", d.log_error),
            log_actions: db::get_bool("log.actions", d.log_actions),
            external: db::get_bool("syntax.external", d.external),
            mc: FilterSettings {
                online: db::get_bool("filter.online", false),
                online_op: db::get("filter.onlineOp", "is"),
                online_val: db::get("filter.onlineVal", ""),

                version: db::get_bool("filter.version", false),
                version_op: db::get("filter.versionOp", "is"),
                version_val: db::get("filter.versionVal", ""),

                brand: db::get_bool("filter.brand", false),
                brand_val: db::get("filter.brandVal", ""),

                motd: db::get_bool("filter.motd", false),
                motd_val: db::get("filter.motdVal", ""),

                players: db::get_bool("filter.players", false),
                players_val: db::get("filter.playersVal", ""),
            },
        }
    }

    /// Persists the config to the SQLite settings store.
    pub fn save(&self) {
        db::set_bool("log.open", self.log_open);
        db::set_bool("log.closed", self.log_closed);
        db::set_bool("log.timeout", self.log_timeout);
        db::set_bool("log.error", self.log_error);
        db::set_bool("log.actions", self.log_actions);
        db::set_bool("syntax.external", self.external);

        db::set_bool("filter.online", self.mc.online);
        db::set("filter.onlineOp", &self.mc.online_op);
        db::set("filter.onlineVal", &self.mc.online_val);

        db::set_bool("filter.version", self.mc.version);
        db::set("filter.versionOp", &self.mc.version_op);
        db::set("filter.versionVal", &self.mc.version_val);

        db::set_bool("filter.brand", self.mc.brand);
        db::set("filter.brandVal", &self.mc.brand_val);

        db::set_bool("filter.motd", self.mc.motd);
        db::set("filter.motdVal", &self.mc.motd_val);

        db::set_bool("filter.players", self.mc.players);
        db::set("filter.playersVal", &self.mc.players_val);
    }
}
