# Lilith — Feature List

## Core Capture
- [x] **Connection table polling** — Polls Windows `psutil.net_connections()` every 3s
- [x] **Public IP filtering** — Only tracks connections to public internet IPs, ignores LAN traffic
- [x] **Process resolution** — Resolves owning process name, exe path, and cmdline for each connection via PID
- [x] **Connection direction detection** — Heuristic-based ↗ outbound / ↙ inbound / ? unknown detection using port analysis and known client process names
- [x] **Direction badges** — Direction symbols shown in connection log rows
- [x] **Direction updates** — Re-evaluates direction on each poll for existing connections
- [x] **SQLite persistence** — All connections stored in `netmonitor.db` with deduplication
- [x] **Deduplication** — Upserts on `(local_ip, local_port, remote_ip, remote_port, pid)` key

## Geolocation
- [x] **IP geolocation** — Batch resolves country, city, and hosting org via ip-api.com (free tier)
- [x] **Latitude / Longitude** — Stores coordinates for map display
- [x] **Country flags** — Flag emoji rendered next to country names in the connection log and map popups
- [x] **Country code** — ISO 2-letter country code stored for flag rendering
- [x] **Geo DB migration** — Existing rows without lat/lon are automatically re-fetched
- [x] **Graceful error handling** — `json.JSONDecodeError` caught alongside `RequestException` for API response issues

## Pipeline: Multi-Stage Triage System

The triage system is a 4-stage rule-based pipeline. Each connection passes through stages in order; the first stage to return a verdict wins, and later stages are skipped. Connections that pass all stages are marked "clean" — there is no LLM/AI stage.

### Stage 1: Whitelist (`pipeline.py` → existing whitelist table)
- [x] **IP whitelisting** — Manually whitelisted IPs are skipped entirely
- [x] **Process whitelisting** — Manually whitelisted processes are skipped entirely
- [x] **Whitelist API** — Add/remove entries via the dashboard modal or REST API

### Stage 2: Heuristics (`stage2_heuristics.py`)
- [x] **69 rules** across 7 categories, ordered by severity (high → low)
- [x] **Script interpreter abuse** (MITRE T1059) — python.exe, powershell.exe, cmd.exe, wscript, mshta, rundll32, certutil, msiexec, cmstp, installutil, wmic, schtasks, curl/wget, node, perl/ruby/php on suspicious ports → HIGH/MEDIUM
- [x] **System process anomalies** (MITRE T1036) — lsass/services/winlogon/spoolsv/csrss/smss/wininit outbound → HIGH; any system binary running from a non-System32 path → HIGH (masquerade); svchost/conhost/taskhostw/dllhost anomalies → MEDIUM
- [x] **Office product network activity** (MITRE T1204) — winword.exe, excel.exe, powerpnt.exe making connections → HIGH (macro-based C2); msaccess/visio → MEDIUM
- [x] **Port/protocol mismatches** — Browser on SSH/RDP → MEDIUM; admin tools (xcopy, net, whoami) → MEDIUM; Telnet/IRC/Tor/database ports → MEDIUM; FTP/cleartext mail → LOW
- [x] **Injected/masquerading processes** (MITRE T1055) — notepad.exe, calc.exe with network → HIGH; no exe path → MEDIUM; running from TEMP → MEDIUM; short-name from temp/appdata → MEDIUM; explorer.exe on non-standard ports → MEDIUM
- [x] **Known-safe process patterns** — Browsers, cloud clients, messengers, game launchers, AV/security, media players, VPN clients, GPU telemetry, Creative Cloud on standard ports → LOW (skip further analysis)

### Stage 3: IP Reputation (`stage3_reputation.py`)
- [x] **SANS DShield only** — Free community threat intel from the SANS Internet Storm Center
- [x] **No API key needed** — Zero configuration, just works out of the box
- [x] **Attack count scoring** — IPs with ≥100 reported attacks → HIGH, ≥1 → MEDIUM, 0 → clean
- [x] **XML parsing** — Uses stdlib `xml.etree.ElementTree`, no extra dependencies
- [x] **In-memory caching** — Each IP checked once per session (up to 5000 entries)
- [x] **Graceful degradation** — Network failure? Skipped silently, no impact on pipeline

### Stage 4: Behavioral Analysis (`behavior.py`)
- [x] **Rolling window** — Per-process 5-minute sliding window of connection events
- [x] **Connection burst detection** — >10 connections in 60s from same process → MEDIUM
- [x] **Country spread detection** — >3 unique countries in 60s from same process → MEDIUM
- [x] **IP spread detection** — >8 unique IPs in 60s from same process → MEDIUM
- [x] **First-process suppression** — New processes are not flagged until a baseline is established (skips first 3 connections)
- [x] **In-memory state** — Resets on app restart (acceptable for MVP)

### Stage 5: Pass-through (`pipeline.py`)
- [x] **No LLM stage** — This tool is a pure rules + reputation + behavior monitor (like classic pre-AI network analysis tools)
- [x] **Clean marking** — Connections that pass all 4 rule-based stages are marked `clean` with an explanatory note
- [x] **No reprocessing** — Clean-marked connections are never re-analyzed, so the pipeline always drains

### Pipeline Orchestration (`pipeline.py`)
- [x] **Stage ordering** — Whitelist → Heuristics → Reputation → Behavior → clean pass-through
- [x] **Early exit** — First stage with a verdict wins, later stages skipped
- [x] **Pipeline stage tracking** — Each connection records which stage produced its verdict (`pipeline_stage` column)
- [x] **Rule tracking** — Each verdict records which specific rule fired (`pipeline_rule` column)
- [x] **High batch support** — `max_batch` parameter processes up to 60 connections per cycle
- [x] **Whitelist cached** — Loaded once per `run_pipeline()` call for performance

## ASN + Reverse-DNS Enrichment (`asn.py`) — Tier 1
- [x] **Team Cymru ASN lookup** — Free key-less DNS TXT (two-step: `<ip>.origin.asn.cymru.com` → ASN, `AS<asn>.asn.cymru.com` → org)
- [x] **ASN columns** — `remote_asn`, `remote_as_org` stored per connection (idempotent migration)
- [x] **Reverse-DNS (PTR)** — `remote_hostname` column feeds the DNS/DGA stage
- [x] **In-memory caching** — ASN/org/hostname cached per IP/ASN for the session
- [x] **Separate loop** — 20s background enrichment, never blocks capture
- [x] **Dashboard display** — ASN + org shown in connection rows
- [x] **CSV export** — ASN + hostname included
- [x] **Hosting-provider ASN rule** — `unknown_proc_hosting_asn`: unknown process → hosting/cloud ASN on non-443 port → MEDIUM

## Threat-Intel Blocklists (`blocklist.py`) — Tier 3
- [x] **Feodo Tracker (abuse.ch)** — Botnet C2 IP blocklist, hourly HTTP refresh, hit → HIGH
- [x] **Spamhaus ZEN** — DNS-based SBL/CSS/XBL/PBL check, severity mapped from zone code
- [x] **IP validation** — Only valid IP addresses accepted from the feed (junk-proof)
- [x] **Per-IP ZEN cache** — Each IP checked once per session
- [x] **Graceful degradation** — Offline → skipped, no pipeline impact
- [x] **`blocklist` pipeline stage** — Runs between heuristics and reputation

## DNS / DGA Analysis (`dns.py`) — Tier 2
- [x] **Shannon entropy DGA detection** — Label entropy ≥3.5 (len ≥10) → MEDIUM
- [x] **Consonant-heavy DGA detection** — Vowel-ratio <0.15 on labels ≥8 chars → MEDIUM
- [x] **DoT detection** — Remote port 853 → MEDIUM
- [x] **DoH detection** — Port 443 + known resolver SNI (dns.google, cloudflare-dns.com…) → LOW
- [x] **`dns` pipeline stage** — Scores PTR hostnames; future: ETW DNS-Client query capture

## Long-Lived Connection Detection (`pipeline.py`) — Tier 1
- [x] **4h tunnel rule** — ESTABLISHED >4h on unusual ports → MEDIUM (`long_lived_tunnel`)
- [x] **Port exclusions** — 443/80/853/1194/8080… treated as expected
- [x] **Process exclusions** — System services, sync clients, AV engines
- [x] **`longlived` pipeline stage** — Runs after DNS, before clean-marking

## ETW Real-Time Capture (`etw_capture.py`) — Tier 2
- [x] **Kernel-Network provider** — Real-time TCP connect/disconnect (Event 12/13) with PID
- [x] **GUID verified from local system** — `{7DD42A49-5329-4832-8DFD-43D979153A88}`
- [x] **Queue + writer thread** — Hot-path event handling never blocks capture
- [x] **Graceful fallback** — No pywintrace / not admin → clear message, psutil polling continues
- [x] **Optional extra** — `uv sync --extra etw` (pywintrace)
- [x] **Same dedupe key** — ETW rows merge with psutil rows (no duplicates)

## Triage Loop (`triage.py`)
- [x] **Configurable polling interval** — Default 1s between pipeline cycles
- [x] **Configurable BATCH_SIZE** — Default 20 connections per cycle
- [x] **Pipeline-only** — Runs whitelist + heuristics + blocklist + reputation + behavior + dns + longlived; pass-through connections are marked clean (no LLM involved)

## Dashboard — Connection Log
- [x] **Real-time refresh** — Dashboard auto-updates via WebSocket push (2s) with polling fallback (4s)
- [x] **Severity filter** — Filter connections by all / low / medium / high
- [x] **Stage filter** — Filter by pipeline stage: heuristic, reputation, behavior, whitelist
- [x] **Search bar** — Search by IP, process name, country, city, or org (300ms debounce)
- [x] **New-connection flash** — Newly appeared connections highlight with a green glow animation
- [x] **Live indicator** — "⬤ live" badge shows WebSocket status (green = live, yellow = reconnecting)
- [x] **Last-updated timestamp** — Shows when data was last refreshed
- [x] **New-connection counter** — `+N` badge on the connection count stat shows new connections since last filter/search change
- [x] **Stage badges** — Colored badges on each connection showing which pipeline stage processed it
- [x] **Rule tooltips** — Hover over stage badges to see which rule fired

## Dashboard — Process View
- [x] **Top processes** — Ranked by outbound connection count with connection/IP tallies
- [x] **Resource usage** — Memory (🧠) and CPU (⚡) indicators per process, hot-colored when high
- [x] **Flagged count** — Shows how many connections per process were flagged high/medium
- [x] **Kill process** — ✕ button to terminate a process from the dashboard (uses `taskkill /F /PID`)

## Dashboard — Map Views
- [x] **Single-IP map** — Click any IP to see its location on an interactive Leaflet map
- [x] **Global map** — "global map" button shows all geo-located IPs as markers on one world map
- [x] **Dark tiles** — CartoDB dark tile layer matches the dashboard theme
- [x] **Flag emojis** — Country flags in map popups

## Dashboard — Interactions
- [x] **Copy IP** — ⎘ button next to each IP copies to clipboard with toast confirmation
- [x] **IP map lookup** — Underlined IPs open the single-IP location map
- [x] **CSV export** — ⬇ csv button downloads the current filtered/search result as a CSV file
- [x] **Responsive layout** — Adapts to smaller screens (hides less-essential columns)
- [x] **Desktop notifications** — 🔔 toggle for real-time alerts on high-severity connections
- [x] **Whitelist management** — ⊞ buttons on IPs and processes to quickly whitelist from the log
- [x] **Whitelist filter fix** — Filter button now sends `whitelist` (matching DB value) instead of `whitelisted`

## Dashboard — Branding
- [x] **Centered brand** — "Lilith" header is centered and prominent
- [x] **Stylized lettering** — Each letter group has its own color (green, amber, dim)
- [x] **SVG favicon** — Custom favicon with Lilith monogram + network signal bars

## Time Range / History System
- [x] **Time range selector** — ⚡ LIVE | 1h | 24h | 48h | 7d | 30d | all range pills
- [x] **LIVE mode** — Shows only connections from the last 5 minutes (fresh-start feel)
- [x] **History mode** — HTTP polling with time-scoped queries for any range
- [x] **Smart timeline bucketing** — 1m buckets for 1h, 1h for 24h, 6h for 7d, 1d for 30d+
- [x] **URL hash persistence** — View state (`#48h`, `#7d`) survives page refresh
- [x] **Scope-consistent stats** — Stats/processes reflect the selected time range
- [x] **Separate history module** — `history.py` handles all time-range queries independently

## Database Cleanup
- [x] **Auto-purge daemon** — Background thread deletes connections older than N days (default 30)
- [x] **Configurable retention** — Adjustable 1–365 days via API or cleanup modal
- [x] **Manual purge** — "purge now" button with confirmation dialog
- [x] **Purge ALL** — ⚠ clear ALL button deletes every connection and whitelist entry (double confirmation)
- [x] **Fresh start** — 🔄 fresh start button = purge-all + VACUUM in one click (double confirmation)
- [x] **VACUUM** — 🗜️ vacuum button to reclaim disk space after large deletes
- [x] **Cleanup stats** — DB size, oldest record, purge history in the cleanup modal
- [x] **`cleanup.py`** — Standalone module, zero impact on capture/geo/triage

## WebSocket Real-Time
- [x] **Server push** — WebSocket endpoint pushes connections + stats + processes every 2 seconds
- [x] **Scoped to live window** — Only returns connections from the last 5 minutes
- [x] **Auto-reconnect** — Reconnects after 5 seconds on disconnect
- [x] **Fallback polling** — Falls back to 4s HTTP polling if WebSocket can't connect
- [x] **No double-polling** — History and fallback polls properly coordinate to avoid redundant fetches
- [x] **Graceful degradation** — Works with or without WebSocket

## Export
- [x] **CSV download** — Exports connections with all fields, respects current filter & search & time range

## Session Management
- [x] **`LILITH_FRESH=1` env var** — Deletes the database on startup for a completely fresh session
- [x] **Persistent DB** — Data survives restarts by default (no env var needed)
- [x] **Fresh start from dashboard** — 🧹 cleanup → 🔄 fresh start without restarting the app

## Test Scripts
- [ ] **Test scripts removed** — The `tests/` directory was deleted by user
  request. The pipeline was validated end-to-end before removal (heuristics,
  blocklist, DNS/DGA, ASN, long-lived, 7-stage threat verification, and a
  concurrent DB stress test — all green).

## Infrastructure
- [x] **FastAPI server** — Serves dashboard + JSON API
- [x] **uv-based** — Managed with `uv` (Python package manager)
- [x] **dnspython** — Runtime dep for ASN/ZEN/PTR DNS lookups
- [x] **SQLite WAL mode** — Concurrent writer loops (capture/geo/asn/triage/etw) no longer hit "database is locked"
- [x] **Background daemon threads** — Capture, geo, triage pipeline, and cleanup run independently
- [x] **SQLite** — Zero-configuration local database with migration support
- [x] **Leaflet** — Interactive maps with CartoDB dark tiles
- [x] **Chart.js** — Connection timeline chart
- [x] **WebSocket** — True real-time push via `websockets` protocol
- [x] **`__pycache__` prevention** — `PYTHONDONTWRITEBYTECODE` env var stops bytecache clutter
- [x] **`.gitignore` cleanup** — Ignores __pycache__, .venv, test files, NUL artifacts, and OS junk
