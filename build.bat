@echo off
REM ============================================
REM  IP Parser - build (compile) the project
REM  Requires an installed JDK (javac command)
REM ============================================
cd /d "%~dp0"

where javac >nul 2>nul
if errorlevel 1 (
    echo [ERROR] javac command not found.
    echo Install JDK: https://www.oracle.com/java/technologies/downloads/
    echo or set the path: set PATH=%%PATH%%;C:\Program Files\Java\jdk-XX\bin
    pause
    exit /b 1
)

echo Compiling...
javac -encoding UTF-8 -cp . IpPattern.java PortScanner.java IpUtils.java McProbe.java McProbeScanner.java PerfMonitor.java IpParserGUI.java

if errorlevel 1 (
    echo [ERROR] Compilation failed.
    pause
    exit /b 1
)

echo.
echo Done! All classes were compiled into the current folder.
echo Run launch.bat to start the program.
pause
