#!/usr/bin/env bash
# ============================================================
#  IP Parser - portable launcher (Linux / macOS)
#  Runs from its own folder regardless of the working directory.
#  Settings (SQLite) and logs are stored next to the jar.
# ============================================================
set -e
cd "$(dirname "$0")"

JAR="$(ls ip-parser-*-all.jar 2>/dev/null | head -n1 || true)"
if [ -z "$JAR" ]; then
  echo "[error] ip-parser-*-all.jar not found in $(pwd)" >&2
  exit 1
fi

JAVA_BIN="java"
if [ -n "$JAVA_HOME" ] && [ -x "$JAVA_HOME/bin/java" ]; then
  JAVA_BIN="$JAVA_HOME/bin/java"
fi

mkdir -p logs data

exec "$JAVA_BIN" \
  -Dipparser.home="$PWD/" \
  -Xmx512m \
  -jar "$JAR" "$@"