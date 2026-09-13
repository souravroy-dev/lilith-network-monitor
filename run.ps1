<#
.SYNOPSIS
    Launches the Lilith passive security monitor dashboard.

.DESCRIPTION
    Wraps the correct `uv run uvicorn app:app --port <PORT>` invocation
    so you don't have to remember the syntax (and don't accidentally
    type "-- port" which breaks uv's trampoline on Windows).

    Defaults mirror the README: port 8000, no fresh wipe, browser opens.

.PARAMETER Fresh
    Set the LILITH_FRESH=1 env var so app startup deletes netmonitor.db.

.PARAMETER Port
    TCP port to bind uvicorn on (default 8000).

.PARAMETER BindHost
    Interface to bind on (default 127.0.0.1).

.PARAMETER NoBrowser
    Skip the auto-launch of http://localhost:<Port>.

.EXAMPLE
    .\run.ps1
    .\run.ps1 -Fresh
    .\run.ps1 -Port 8080 -NoBrowser
    .\run.ps1 -Fresh -Port 8080

.NOTES
    - Best run from an elevated (Administrator) PowerShell so psutil
      can see every owning process. If not elevated you'll get a
      warning and a few rows will show proc_name = "unknown".
    - If your execution policy blocks .ps1 files, run this instead:
        powershell -ExecutionPolicy Bypass -File .\run.ps1
    - Requires uv OR plain Python 3.10+ (the launcher auto-detects and
      falls back to pip). First run with uv: `uv sync` (creates .venv).
#>

[CmdletBinding()]
param(
    [switch]$Fresh,
    [int]$Port = 8000,
    [string]$BindHost = '127.0.0.1',
    [switch]$NoBrowser
)

$ErrorActionPreference = 'Stop'

# Resolve to script directory so dashboard.html / netmonitor.db paths are stable.
Set-Location -Path $PSScriptRoot

# Suppress __pycache__ clutter (recommended in README under "Environment Variables").
$env:PYTHONDONTWRITEBYTECODE = '1'

if ($Fresh) {
    $env:LILITH_FRESH = '1'
    Write-Host '==> Fresh mode: netmonitor.db will be deleted on startup' -ForegroundColor Yellow
}

# ---- Pre-flight checks -------------------------------------------------------

# 1. Runtime detection: prefer uv, fall back to plain Python + pip.
$uv = Get-Command uv -ErrorAction SilentlyContinue
$pyCmd = $null
if (-not $uv) {
    if (Get-Command python -ErrorAction SilentlyContinue) {
        $pyCmd = 'python'
    }
    elseif (Get-Command py -ErrorAction SilentlyContinue) {
        $pyCmd = 'py -3'   # Windows Python launcher
    }
    if (-not $pyCmd) {
        Write-Host "[ERROR] Neither 'uv' nor Python was found on PATH." -ForegroundColor Red
        Write-Host "        Install uv with:  winget install astral-sh.uv" -ForegroundColor Red
        Write-Host "        ...or Python 3.10+ from:  https://www.python.org/downloads/" -ForegroundColor Red
        exit 1
    }
}

# 2. Administrator privileges (warn, don't block — user might be fine without)
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Warning 'Not running as Administrator. Some processes will show as "unknown". Re-launch PowerShell as Administrator for full visibility.'
}

# 3. Port collision (best-effort — Get-NetTCPConnection needs Win8+/PSv3+)
if (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) {
    $conflict = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
    if ($conflict) {
        Write-Warning "Port $Port is already in use. Pick another with -Port, or stop the holding process."
    }
}

# ---- Launch -----------------------------------------------------------------

Write-Host "==> Starting Lilith on http://localhost:$Port  (Ctrl+C to stop)" -ForegroundColor Cyan

# Auto-open browser after boot (background job so it doesn't block the server).
$browserJob = $null
if (-not $NoBrowser) {
    $browserJob = Start-Job -ScriptBlock {
        param($p)
        # 1.5s is enough for uvicorn to bind; smaller window avoids the race
        # where Ctrl+C during init still left the browser popping up post-shutdown.
        Start-Sleep -Seconds 1.5
        Start-Process "http://localhost:$p"
    } -ArgumentList $Port
}

try {
    if ($uv) {
        # Use `uv run python -m uvicorn` rather than `uv run uvicorn`. The latter
        # generates a uvicorn.exe trampoline under .venv\Scripts\ that has been
        # observed to fail canonicalization on Windows when the project path
        # contains spaces (e.g. "F:\My new projects\..."), surfacing as
        # "uv trampoline failed to canonicalize script path". Invoking uvicorn
        # via `python -m` sidesteps the broken .exe shim while keeping uv's
        # interpreter resolution and venv management. `uv run` also auto-syncs
        # dependencies on first run.
        Write-Host '==> runtime: uv' -ForegroundColor Cyan
        & uv run python -m uvicorn lilith.app:app --host $BindHost --port $Port
    }
    else {
        # Plain Python fallback — no uv needed. Install deps on first run.
        Write-Host "==> runtime: $pyCmd" -ForegroundColor Cyan
        & $pyCmd -c "import fastapi, uvicorn, psutil, requests" 2>$null | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Write-Host '==> Installing dependencies with pip (first run)...' -ForegroundColor Yellow
            & $pyCmd -m pip install -r requirements.txt
            if ($LASTEXITCODE -ne 0) {
                Write-Host '[ERROR] pip install failed. Check your internet connection and retry.' -ForegroundColor Red
                exit 1
            }
        }
        & $pyCmd -m uvicorn lilith.app:app --host $BindHost --port $Port
    }
}
finally {
    Write-Host ''
    Write-Host '==> Lilith stopped.' -ForegroundColor Cyan
    if ($browserJob) {
        Stop-Job $browserJob -ErrorAction SilentlyContinue | Out-Null
        Remove-Job $browserJob -ErrorAction SilentlyContinue | Out-Null
    }
}
