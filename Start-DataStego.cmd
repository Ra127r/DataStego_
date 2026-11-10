@echo off
setlocal
cd /d "%~dp0"
if not exist "build\datastego.exe" (
    echo DataStego has not been built. See README.md for build instructions.
    pause
    exit /b 1
)
start "" "build\datastego.exe"
endlocal
