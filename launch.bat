@echo off
REM ============================================
REM  IP Parser - launch the program
REM  Uses javaw (no console window) + start,
REM  so the console closes immediately.
REM ============================================
cd /d "%~dp0"

if not exist IpParserGUI.class (
    call build.bat
)

where javaw >nul 2>nul
if errorlevel 1 (
    where java >nul 2>nul
    if errorlevel 1 (
        echo [ERROR] Java not found.
        echo Install JRE/JDK: https://www.oracle.com/java/technologies/downloads/
        pause
        exit /b 1
    )
    start "" java -cp . IpParserGUI
    exit /b 0
)

start "" javaw -cp . IpParserGUI
