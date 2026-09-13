# 🛠️ Lilith — Setup & Transfer Instructions

> **Lilith** is a passive, system-wide network security monitor for **Windows**.
> It watches every outbound connection your PC makes, geolocates the remote IP,
> and runs each connection through a **4-stage rule-based pipeline** that flags
> suspicious activity as **low / medium / high**.
>
> ✅ **No LLM. No AI. No API keys.** Lilith is a pure **rules + reputation +
> behavior** monitor, in the spirit of classic pre-AI network analysis tools
> (Snort, TCPView, GlassWire, Little Snitch…). It runs entirely locally.

---

## 1. What you need

| Requirement | Notes |
|---|---|
| **Windows 10/11** | The app uses `psutil` + `taskkill` (Windows-specific) |
| **Python 3.10+** | 3.12 recommended. Download from [python.org](https://www.python.org/downloads/) |
| **`uv`** (optional, recommended) | Fast package manager — `winget install astral-sh.uv`. If absent, the launchers auto-fall-back to plain `pip` |
| **Administrator rights** (recommended) | Gives full process visibility (some rows show "unknown" without it) |
| **Internet** | Needed for IP geolocation (ip-api.com) and IP reputation (SANS DShield). Both fail silently if offline — the app still runs |

That's it. No LLM software, no model downloads, no API sign-ups.

---

## 2. Transfer the project to another PC

### Option A — Copy the folder (ZIP / USB / network)

1. Close Lilith (stop the server) if it is running.
2. Zip the project folder and copy it to the new PC.
3. **Do NOT copy these** (they are machine-specific / regenerated):
   - `.venv/` — the virtual environment (recreated on the new PC)
   - `__pycache__/` folders anywhere
   - `netmonitor.db` — the local database (optional: copy it if you want to keep old history, it's just SQLite)
4. Extract the folder anywhere, e.g. `C:\Users\You\lilith`.

### Option B — Git

```powershell
git clone <your-repo-url> lilith
cd lilith
```

> The repo is already set up with a correct `.gitignore`, so the venv,
> database and cache folders are never committed.

---

## 3. Install & run

### Option A — Recommended: with `uv`

```powershell
# 1. Install uv (one time)
winget install astral-sh.uv

# 2. Install dependencies (creates .venv)
uv sync

# 3. Run — from the project folder
.\run.ps1            # PowerShell launcher (admin check, opens browser)
# or
run.bat              # cmd.exe fallback
# or directly:
uv run python -m uvicorn lilith.app:app --port 8000
```

### Option B — Plain Python (no uv needed)

The launchers do this automatically, but manually it looks like:

```powershell
# 1. Install dependencies
python -m pip install -r requirements.txt

# 2. Run
python -m uvicorn lilith.app:app --port 8000
```

### 3.1 Open the dashboard

Visit **http://localhost:8000**

> **Tip:** run PowerShell **as Administrator** for full process visibility.
> Not running as admin only means some processes show as "unknown".

---

## 4. How the analysis works (4 stages, no AI)

Every connection goes through the pipeline. The **first stage that finds
something wins**; the rest are skipped for that connection:

1. **Whitelist** — IPs and processes you've approved are excluded.
2. **Heuristics** — 69 built-in rules: script interpreters & LOLBins
   (python / powershell / cmd / msiexec / wmic / curl on suspicious
   ports), system-process anomalies (lsass / services / csrss / smss
   outbound, masquerading from non-System32 paths), office macro C2,
   port mismatches (browser on SSH/RDP, Telnet / IRC / Tor / database
   ports), injected / masquerading processes, and known-safe apps
   (browsers, Steam, Discord, AV, VPN clients…).
3. **IP reputation** — checks the remote IP against **SANS DShield**
   (free community threat intel; no key, no signup).
4. **Behavior** — per-process anomaly detection in a rolling window:
   connection bursts, country spread, IP spread.

Connections that pass **all four** stages are marked **"clean"** — shown
as `clean` in the dashboard. Nothing is left "stuck" waiting for a
judgment stage.

The pipeline is **fully offline-capable**: without internet, only stages
3 (reputation) and IP geolocation are skipped; stages 1, 2 and 4 still
work normally.

---

## 5. Launchers at a glance

```powershell
.\run.ps1                  # PowerShell — admin warning, opens browser
.\run.ps1 -Fresh           # wipe netmonitor.db on startup
.\run.ps1 -Port 8080       # different port
.\run.ps1 -NoBrowser       # don't auto-open the browser

run.bat --fresh            # cmd.exe equivalent
run.bat --port 8080
```

Both launchers auto-detect the runtime: **uv** if installed, otherwise
**plain Python + pip** (deps are installed automatically on first run).

---

## 6. Configuration — environment variables

Set these **before** starting the app (`$env:VAR = "value"` in PowerShell,
or `set VAR=value` in cmd).

| Variable | Default | What it does |
|---|---|---|
| `LILITH_DB_PATH` | `<project>\netmonitor.db` | Move the SQLite database elsewhere |
| `LILITH_FRESH` | — | `1` deletes the database on startup (fresh session) |
| `PYTHONDONTWRITEBYTECODE` | — | `1` prevents `__pycache__` clutter (launchers set it) |

There are no LLM settings — there is no LLM.

---

## 7. Verifying the install

There are **no bundled test scripts** — the `tests/` directory was removed.
To sanity-check the install, start the app and watch the console for
`[triage]` pipeline messages; flagged connections will show in the
dashboard filtered by stage (heuristic / blocklist / reputation / behavior /
dns / long-lived).

---

## 8. Troubleshooting

| Problem | Solution |
|---|---|
| "Neither 'uv' nor Python found" | Install Python 3.10+ from python.org, or `winget install astral-sh.uv` |
| No connections appear | Run PowerShell as **Administrator** |
| Processes show as "unknown" | You need admin rights (see above) |
| Port 8000 in use | `.\run.ps1 -Port 8080` (or `--port 8080`) |
| Geolocation not working | ip-api.com has a 45 req/min limit — it backs off automatically; needs internet |
| Reputation never fires | DShield only reports IPs it has attack data for — results vary by IP |
| Everything shows "clean" | That's expected for normal traffic — the rules only flag suspicious patterns. Try connecting to a known-suspicious IP or check the heuristic rules in `stage2_heuristics.py` to see flags fire |
| `uv`-specific error about "trampoline" | Use the launchers or `uv run python -m uvicorn ...` (never `uv run uvicorn`) — fixed path-with-spaces bug |
| Database grows too big | Dashboard → 🧹 cleanup → adjust retention / purge / vacuum |
| Want a completely fresh start | `$env:LILITH_FRESH = "1"` before starting, or dashboard → 🧹 → 🔄 fresh start |

---

## 9. Optional extras

- **Nmap integration** — the dashboard can run nmap scans (recon panel).
  It auto-detects nmap; install it separately from https://nmap.org if wanted.

---

## 10. How the pipeline works (quick reference)

```
 capture.py ──> SQLite ──> geoip.py (country/org/lat/lon)
                │
                ▼
        pipeline.py (stages 1-4, rule-based)
        1 whitelist │ 2 heuristics │ 3 reputation │ 4 behavior
                │
                ▼
        triage.py (loop — marks pass-through connections "clean")
                │
                ▼
        app.py ──> dashboard.html (WebSocket, maps, CSV…)
```

The first stage that returns a verdict wins; later stages are skipped for
that connection. Connections with no verdict after all four stages are
marked **"clean"** — done, no AI needed.
