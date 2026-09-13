@echo off
REM ============================================================
REM Lilith launcher for cmd.exe
REM
REM Usage:
REM     run.bat                 normal start (port 8000, opens browser)
REM     run.bat --fresh         nuke netmonitor.db on startup
REM     run.bat --port 8080     use a different port
REM     run.bat --no-browser    don't auto-open http://localhost:8000
REM
REM Runtime auto-detection:
REM     - If 'uv' is on PATH, it is used (recommended: uv sync + uv run).
REM     - Otherwise it falls back to plain Python + pip and installs the
REM       dependencies from requirements.txt on first run.
REM
REM If PowerShell scripts are blocked on your machine, use this.
REM For richer features (admin warning, job cleanup, -BindHost) use run.ps1.
REM ============================================================

setlocal EnableDelayedExpansion

set "FRESH="
set "PORT=8000"
set "NO_BROWSER="

:parse_args
if "%~1"=="" goto :check_env
if /i "%~1"=="--fresh"        set "FRESH=1"     & shift & goto :parse_args
if /i "%~1"=="--no-browser"   set "NO_BROWSER=1" & shift & goto :parse_args
if /i "%~1"=="--port" (
    if "%~2"=="" (
        echo [ERROR] --port requires a value
        exit /b 1
    )
    REM Reject flag-shaped values: copy arg2 into a helper var, then substring-read
    REM via delayed expansion. (Delayed expansion is enabled at the top.)
    set "_portArg=%~2"
    if "!_portArg:~0,2!"=="--" (
        echo [ERROR] --port requires a value, got flag "%~2" instead
        exit /b 1
    )
    set "PORT=%~2"
    shift
    shift
    goto :parse_args
)
echo [ERROR] Unknown argument: %~1
echo         Supported: --fresh --port N --no-browser
exit /b 1

:check_env
cd /d "%~dp0"
set "PYTHONDONTWRITEBYTECODE=1"
if defined FRESH set "LILITH_FRESH=1"

echo Starting Lilith on http://localhost:%PORT%  (Ctrl+C to stop)
if defined FRESH echo [!] Fresh mode: netmonitor.db will be deleted on startup

if not defined NO_BROWSER (
    REM Open browser ~1.5s later via PowerShell so we don't block the server.
    REM 1.5s is enough for uvicorn to bind and reduces the chance of a stale
    REM browser popup if the user Ctrl+C's during startup.
    start "" /b powershell -NoProfile -Command "Start-Sleep -Seconds 1.5; Start-Process http://localhost:%PORT%"
)

REM ---- Detect runtime: prefer uv, fall back to plain Python ----

where uv >nul 2>&1
if not errorlevel 1 goto :run_uv

set "PYCMD=python"
%PYCMD% --version >nul 2>&1
if errorlevel 1 set "PYCMD=py -3"
%PYCMD% --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Neither 'uv' nor Python was found on PATH.
    echo         Install uv with:  winget install astral-sh.uv
    echo         ...or Python 3.10+ from:  https://www.python.org/downloads/
    exit /b 1
)

REM Ensure runtime deps are installed (first run only).
%PYCMD% -c "import fastapi, uvicorn, psutil, requests" >nul 2>&1
if errorlevel 1 (
    echo [setup] Installing dependencies with pip (first run)...
    %PYCMD% -m pip install -r requirements.txt
    if errorlevel 1 (
        echo [ERROR] pip install failed. Check your internet connection and retry.
        exit /b 1
    )
)
echo [runtime] using %PYCMD%

REM Run uvicorn as a Python module instead of via uvicorn.exe. The latter
REM generates a trampoline under .venv\Scripts\ that fails canonicalization
REM on Windows when the project path has spaces ("F:\My new projects\...").
REM `python -m uvicorn` keeps everything self-contained.
%PYCMD% -m uvicorn lilith.app:app --port %PORT%
set "RC=%ERRORLEVEL%"
goto :stopped

:run_uv
echo [runtime] using uv
REM `uv run python -m uvicorn` rather than `uv run uvicorn` sidesteps the same
REM Windows trampoline bug with spaces in the project path. `uv run` also
REM auto-syncs dependencies when needed (first run = uv sync).
uv run python -m uvicorn lilith.app:app --port %PORT%
set "RC=%ERRORLEVEL%"

:stopped
echo.
echo Lilith stopped.
exit /b %RC%
