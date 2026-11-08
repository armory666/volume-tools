@echo off
REM ---------------------------------------------------------------------------
REM VOLUME launcher for Windows.
REM
REM   run.bat            interactive console (auto layout)
REM   run.bat --pc       force the full dashboard
REM   run.bat --mobile   force the compact layout
REM   run.bat --list-modules
REM   run.bat --run domain_intel --arg domain=example.com --json
REM
REM The package is imported from its parent folder, so this script cds there.
REM ---------------------------------------------------------------------------
setlocal

cd /d "%~dp0.."

where python >nul 2>nul
if errorlevel 1 (
    echo [VOLUME] Python was not found on PATH.
    echo          Install Python 3.11+ from https://www.python.org/downloads/
    pause
    exit /b 1
)

python -m volume.main %*
set "CODE=%ERRORLEVEL%"

if not "%CODE%"=="0" (
    echo.
    echo [VOLUME] exited with code %CODE%.
    if "%~1"=="" pause
)
exit /b %CODE%
