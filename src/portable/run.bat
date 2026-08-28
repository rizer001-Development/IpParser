@echo off
rem ============================================================
rem  IP Parser - portable launcher (Windows)
rem  Runs from its own folder regardless of the working directory.
rem  Settings (SQLite) and logs are stored next to the jar.
rem ============================================================
setlocal
cd /d "%~dp0"

set "JAR="
for %%f in (ip-parser-*-all.jar) do set "JAR=%%f"
if not defined JAR (
  echo [error] ip-parser-*-all.jar not found in %~dp0
  pause
  exit /b 1
)

set "JAVA=java"
if defined JAVA_HOME (
  if exist "%JAVA_HOME%\bin\java.exe" set "JAVA=%JAVA_HOME%\bin\java.exe"
)

if not exist "logs" mkdir logs
if not exist "data"  mkdir data

start "" "%JAVA%" ^
  -Dipparser.home="%~dp0" ^
  -Xmx512m ^
  -jar "%JAR%" %*

exit /b %errorlevel%