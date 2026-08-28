IP Parser - Portable Edition
=============================

WHAT'S HERE
  ip-parser-<version>-all.jar   the application (SQLite bundled inside)
  run.bat  /  run.sh            launcher scripts
  logs/                         application log files (per-scan, auto-created)
  data/                         SQLite database with your settings (auto-created)

RUNNING
  Windows : double-click run.bat
  Linux/macOS:  chmod +x run.sh && ./run.sh
  Requires Java 17 or newer (JRE is enough; JDK only if you want to build).

PORTABLE / OWN DIRECTORY
  The program NEVER saves anything to the current working directory.
  Its own home is the folder where the jar lives:
    * settings  -> data/settings.db   (SQLite)
    * logs      -> logs/ipparser-<timestamp>.log and a separate per-scan result log
  So you can move this whole folder to a USB stick and it keeps its own
  configuration and logs with it.

BUILDING (requires a JDK and internet once)
  ./gradlew build          -> compiles, runs tests, builds fat jar + portable layout
  ./gradlew assemblePortable  -> fill folder + zip only
  Output lands in build/.

NOTE
  Existing plain-text settings.txt (older versions) is no longer written.
  On first run your previous preferences are not migrated automatically;
  re-apply them in the two gear settings dialogs once.