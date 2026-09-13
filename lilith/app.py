"""
Lilith -- passive, system-wide network security monitor.

Runs background loops as daemon threads:
  1. capture.capture_loop()  -- polls OS connection table every 3s
  2. geoip.enrich_loop()     -- resolves IP geolocation every 20s
  3. triage.triage_loop()    -- pipeline triage (whitelist + heuristics + reputation + behavior) every 1s
  4. cleanup.purge_loop()    -- auto-purge old data every 24h

Serves a dashboard + JSON API on http://localhost:8000

Run with (Windows, as Administrator for full process visibility):
    .\run.ps1                  # PowerShell launcher (admin check, opens browser)
    run.bat                    # cmd.exe fallback

For a fresh session (delete all previous data on startup), set LILITH_FRESH=1:
    .\run.ps1 -Fresh
    -- or directly --
    $env:LILITH_FRESH=1; uv run python -m uvicorn lilith.app:app --port 8000

The `uv run python -m uvicorn` form is required on Windows because the
uvicorn.exe trampoline fails to canonicalize its script path when the project
path contains spaces (a real hazard on a default `My new projects/...`
layout). The launchers use it for you.
"""
import asyncio
import ctypes
import json
import os
import re
import socket
import subprocess
import threading
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.request import urlopen, Request

from fastapi import FastAPI, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse

from . import asn
from . import blocklist
from . import capture
from . import cleanup
from . import etw_capture
from . import geoip
from . import history
from . import triage

app = FastAPI(title="Lilith — Passive Security Dashboard")

_threads_started = False


@app.on_event("startup")
def start_background_threads():
    global _threads_started
    if _threads_started:
        return

    # If LILITH_FRESH=1, delete the database to start clean
    if os.environ.get("LILITH_FRESH") == "1":
        db_path = capture.DB_PATH
        if os.path.exists(db_path):
            os.remove(db_path)
            print(f"[startup] LILITH_FRESH=1 — deleted {db_path} for fresh start")

    capture.init_db()
    _init_whitelist()

    threading.Thread(target=capture.capture_loop, kwargs={"interval_seconds": 3}, daemon=True).start()
    threading.Thread(target=geoip.enrich_loop, kwargs={"interval_seconds": 20}, daemon=True).start()
    threading.Thread(target=asn.enrich_loop, kwargs={"interval_seconds": 20}, daemon=True).start()
    threading.Thread(target=triage.triage_loop, kwargs={"interval_seconds": 1}, daemon=True).start()
    threading.Thread(target=cleanup.purge_loop, daemon=True).start()
    threading.Thread(target=blocklist.refresh_loop, daemon=True).start()

    # Real-time ETW kernel-network capture (best-effort; falls back to
    # the psutil poller above when pywintrace is missing / not admin).
    etw_capture.start_if_available()

    _threads_started = True


# =====================================================================
# API
# =====================================================================

@app.get("/api/time-ranges")
async def get_time_ranges():
    """Return available time range definitions (label, key)."""
    return [
        {"key": k, "label": v["label"]}
        for k, v in history.RANGES.items()
    ]


@app.get("/api/connections")
async def list_connections(
    time_range: str | None = Query(default=None, description="live|1h|24h|48h|7d|30d|all"),
    severity: str | None = Query(default=None, description="filter: low|medium|high"),
    search: str | None = Query(default=None, description="search by IP, process name, or country"),
    pipeline_stage: str | None = Query(default=None, description="filter: heuristic|blocklist|reputation|behavior|dns|longlived|whitelisted"),
    limit: int = Query(default=200, le=1000),
):
    """
    Return connections. When time_range is None (no param), returns ALL
    for backward compat. When 'live', returns last 5 minutes.
    """
    return history.query_connections(
        time_range=time_range,
        severity=severity,
        search=search,
        pipeline_stage=pipeline_stage,
        limit=limit,
    )


@app.get("/api/stats")
async def stats(
    time_range: str | None = Query(default=None, description="live|1h|24h|48h|7d|30d|all"),
):
    return history.query_stats(time_range=time_range)


@app.get("/api/processes")
async def top_processes(
    time_range: str | None = Query(default=None, description="live|1h|24h|48h|7d|30d|all"),
    limit: int = 20,
):
    """Which local apps are making the most outbound connections."""
    return history.query_processes(time_range=time_range, limit=limit)


# =====================================================================
# Process kill
# =====================================================================

@app.delete("/api/kill-process/{pid}")
async def kill_process(pid: int):
    """Kill a process by PID using taskkill."""
    try:
        result = subprocess.run(
            ["taskkill", "/F", "/PID", str(pid)],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            print(f"[kill] terminated PID {pid}: {result.stdout.strip()}")
            return {"status": "ok", "message": f"Process {pid} terminated"}
        else:
            return {"status": "error", "message": result.stderr.strip()}
    except subprocess.TimeoutExpired:
        return {"status": "error", "message": "Kill timed out"}
    except FileNotFoundError:
        return {"status": "error", "message": "taskkill not found (not Windows?)"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


@app.get("/api/geo-detail/{ip}")
async def geo_detail(ip: str):
    """Return full geo details (including lat/lon) for a specific IP."""
    conn = capture.get_db()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT remote_ip, geo_country, geo_country_code, geo_city, geo_org, geo_lat, geo_lon
        FROM connections
        WHERE remote_ip = ? AND geo_lookup_done = 1
        LIMIT 1
        """,
        (ip,),
    )
    row = cur.fetchone()
    conn.close()
    if row:
        return dict(row)
    return {"error": "no geo data for this IP yet"}


@app.get("/api/geo-all")
async def geo_all(
    time_range: str | None = Query(default=None, description="live|1h|24h|48h|7d|30d|all"),
):
    """Return all geo-located IPs with coordinates."""
    return history.query_geo_all(time_range=time_range)


# =====================================================================
# Export
# =====================================================================

@app.get("/api/export/csv")
async def export_csv(
    time_range: str | None = Query(default=None, description="live|1h|24h|48h|7d|30d|all"),
    severity: str | None = Query(default=None, description="filter: low|medium|high"),
    search: str | None = Query(default=None, description="search filter"),
):
    """Export filtered connections as CSV."""
    rows = history.export_csv_rows(time_range=time_range, severity=severity, search=search)

    import csv, io

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "First Seen", "Last Seen", "Local IP", "Local Port", "Remote IP", "Remote Port",
        "Process", "Executable", "Country", "City", "Org", "ASN", "Hostname",
        "Severity", "Reason",
    ])
    for r in rows:
        writer.writerow([r[c] for c in range(15)])

    from fastapi.responses import Response

    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=roy-export.csv"},
    )


# =====================================================================
# WebSocket — real-time push
# =====================================================================

def _fetch_ws_snapshot():
    """Gather live dashboard data for WebSocket push (last 5 minutes only)."""
    live_cutoff = (datetime.now(timezone.utc) - timedelta(seconds=300)).isoformat()

    conn = capture.get_db()
    cur = conn.cursor()

    # connections — only live window for a true "fresh start" feel
    cur.execute(
        "SELECT * FROM connections WHERE last_seen >= ? ORDER BY last_seen DESC LIMIT 100",
        (live_cutoff,),
    )
    connections = [dict(r) for r in cur.fetchall()]

    # stats — scoped to live window
    cur.execute("SELECT COUNT(*) c FROM connections WHERE last_seen >= ?", (live_cutoff,))
    total = cur.fetchone()["c"]
    cur.execute(
        "SELECT COUNT(*) c FROM connections WHERE last_seen >= ? AND analyzed = 0",
        (live_cutoff,),
    )
    pending_analysis = cur.fetchone()["c"]
    cur.execute(
        "SELECT COUNT(*) c FROM connections WHERE last_seen >= ? AND geo_lookup_done = 0",
        (live_cutoff,),
    )
    pending_geo = cur.fetchone()["c"]
    severity_counts = {}
    for sev in ("low", "medium", "high"):
        cur.execute(
            "SELECT COUNT(*) c FROM connections WHERE last_seen >= ? AND severity = ?",
            (live_cutoff, sev),
        )
        severity_counts[sev] = cur.fetchone()["c"]
    cur.execute(
        "SELECT COUNT(DISTINCT remote_ip) c FROM connections WHERE last_seen >= ?",
        (live_cutoff,),
    )
    unique_ips = cur.fetchone()["c"]
    cur.execute(
        "SELECT COUNT(DISTINCT proc_name) c FROM connections WHERE last_seen >= ? AND proc_name IS NOT NULL",
        (live_cutoff,),
    )
    unique_procs = cur.fetchone()["c"]

    stats_data = {
        "total_connections": total,
        "pending_analysis": pending_analysis,
        "pending_geo": pending_geo,
        "severity_counts": severity_counts,
        "unique_remote_ips": unique_ips,
        "unique_processes": unique_procs,
    }

    # processes — scoped to live window
    cur.execute(
        """
        SELECT proc_name, proc_exe, COUNT(*) as conn_count,
               COUNT(DISTINCT remote_ip) as unique_ips,
               MAX(pid) as sample_pid,
               ROUND(MAX(proc_memory_mb), 1) as peak_mem_mb,
               ROUND(MAX(proc_cpu_pct), 1) as peak_cpu_pct,
               SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) as high_count,
               SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END) as medium_count
        FROM connections
        WHERE pid IS NOT NULL AND last_seen >= ?
        GROUP BY proc_name, proc_exe
        ORDER BY conn_count DESC LIMIT 12
        """,
        (live_cutoff,),
    )
    processes = [dict(r) for r in cur.fetchall()]

    conn.close()
    return {
        "connections": connections,
        "stats": stats_data,
        "processes": processes,
    }


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """
    Real-time push — only connections from the last 5 minutes (live window).

    The client decides whether to render WS data (LIVE mode) or ignore it
    and use HTTP with ?time_range= when viewing history.
    """
    await websocket.accept()
    print(f"[ws] client connected")
    try:
        while True:
            data = await asyncio.to_thread(_fetch_ws_snapshot)
            data["timestamp"] = datetime.now(timezone.utc).isoformat()
            await websocket.send_json(data)
            await asyncio.sleep(2)
    except WebSocketDisconnect:
        print(f"[ws] client disconnected")
    except Exception as e:
        print(f"[ws] error: {e}")
    finally:
        try:
            await websocket.close()
        except Exception:
            pass


# =====================================================================
# Cleanup / Purge
# =====================================================================

@app.get("/api/cleanup")
async def cleanup_status():
    """Return cleanup config + DB stats."""
    return cleanup.get_stats()


@app.post("/api/cleanup/config")
async def update_cleanup_config(
    enabled: bool | None = Query(default=None),
    retention_days: int | None = Query(default=None, ge=1, le=365),
):
    """Update cleanup settings. Only provided fields are changed."""
    kwargs = {}
    if enabled is not None:
        kwargs["enabled"] = enabled
    if retention_days is not None:
        kwargs["retention_days"] = retention_days
    if kwargs:
        cleanup.update_config(**kwargs)
    return cleanup.get_config()


@app.post("/api/cleanup/purge-now")
async def purge_now(
    retention_days: int | None = Query(default=None, ge=1, le=365),
):
    """Trigger an immediate purge. Optionally override retention_days for this run."""
    try:
        count = cleanup.purge_once(retention_days=retention_days)
        return {
            "status": "ok",
            "deleted": count,
            "message": f"Purged {count} connection(s)",
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}


@app.post("/api/cleanup/purge-all")
async def purge_all():
    """
    Delete ALL connections and whitelist entries.
    Hard reset — use with caution.
    """
    try:
        count = cleanup.purge_all()
        return {
            "status": "ok",
            "deleted": count,
            "message": f"Cleared all {count} connection(s) and whitelist",
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}


@app.post("/api/cleanup/vacuum")
async def vacuum():
    """Run VACUUM to reclaim disk space."""
    try:
        result = cleanup.vacuum_db()
        return {"status": "ok", **result}
    except Exception as e:
        return {"status": "error", "message": str(e)}


@app.post("/api/cleanup/reset")
async def reset_database():
    """
    Complete fresh start: purge all data, vacuum, reset counter.
    Same as purge-all + vacuum in one call.
    """
    try:
        count = cleanup.purge_all()
        vacuum_result = cleanup.vacuum_db()
        return {
            "status": "ok",
            "deleted": count,
            "saved_bytes": vacuum_result["saved_bytes"],
            "message": f"Fresh start: cleared {count} records, reclaimed {vacuum_result['saved_bytes'] / 1024:.1f} KB",
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}


# =====================================================================
# Investigation — Reverse DNS + Port Scan + WHOIS
# =====================================================================

# Common ports to scan (fast, top 30)
SCAN_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 389, 443, 445,
    465, 587, 993, 995, 1433, 1521, 2049, 3306, 3389, 5432, 5900,
    5985, 5986, 6379, 8080, 8443, 9090, 27017,
]


def _scan_port(ip: str, port: int, timeout: float = 2.0) -> int | None:
    """Return port if open, None if closed/filtered."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((ip, port))
        s.close()
        return port if result == 0 else None
    except Exception:
        return None


@app.get("/api/investigate/{ip}")
def investigate_ip(ip: str):
    """
    Investigate an IP address using three tools:
      1. Reverse DNS lookup
      2. TCP port scan (common ports, ~15s)
      3. WHOIS via ipip.net
    Returns a dict with all results.

    Note: Sync endpoint — FastAPI runs it in a thread pool so it
    doesn't block the asyncio event loop during port scanning (~15s).
    """
    result = {"ip": ip}

    # 1. Reverse DNS
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        result["reverse_dns"] = hostname
    except (socket.herror, socket.gaierror):
        result["reverse_dns"] = None
    except Exception as e:
        result["reverse_dns"] = f"error: {e}"

    # 2. Port scan (using thread pool for speed)
    open_ports = []
    with ThreadPoolExecutor(max_workers=20) as pool:
        futures = {pool.submit(_scan_port, ip, p): p for p in SCAN_PORTS}
        for future in as_completed(futures, timeout=25):
            port = futures[future]
            try:
                if future.result():
                    open_ports.append(port)
            except Exception:
                pass
    open_ports.sort()
    result["open_ports"] = open_ports

    # Map common ports to service names
    PORT_SERVICES = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        80: "HTTP", 110: "POP3", 111: "RPC", 135: "RPC", 139: "NetBIOS",
        143: "IMAP", 389: "LDAP", 443: "HTTPS", 445: "SMB",
        465: "SMTPS", 587: "SMTP", 993: "IMAPS", 995: "POP3S",
        1433: "MSSQL", 1521: "Oracle", 2049: "NFS", 3306: "MySQL",
        3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
        5985: "WinRM-HTTP", 5986: "WinRM-HTTPS", 6379: "Redis",
        8080: "HTTP-Alt", 8443: "HTTPS-Alt", 9090: "HTTP-Alt2",
        27017: "MongoDB",
    }
    result["open_ports_detail"] = [
        {"port": p, "service": PORT_SERVICES.get(p, "unknown")}
        for p in open_ports
    ]

    # 3. IP WHOIS (ipwho.is — free JSON API, no key needed)
    whois_data = None
    whois_error = None
    try:
        with urlopen(
            Request(f"http://ipwho.is/{ip}", headers={"User-Agent": "Lilith/1.0"}),
            timeout=6,
        ) as resp:
            raw = json.loads(resp.read().decode("utf-8"))
            if raw.get("success"):
                conn = raw.get("connection", {}) or {}
                tz = raw.get("timezone", {}) or {}
                flag = raw.get("flag", {}) or {}
                whois_data = {
                    "ip": raw.get("ip"),
                    "type": raw.get("type"),
                    # Geo
                    "continent": raw.get("continent"),
                    "continent_code": raw.get("continent_code"),
                    "country": raw.get("country"),
                    "country_code": raw.get("country_code"),
                    "region": raw.get("region"),
                    "region_code": raw.get("region_code"),
                    "city": raw.get("city"),
                    "latitude": raw.get("latitude"),
                    "longitude": raw.get("longitude"),
                    "postal": raw.get("postal"),
                    "is_eu": raw.get("is_eu"),
                    "capital": raw.get("capital"),
                    "borders": raw.get("borders"),
                    "calling_code": raw.get("calling_code"),
                    # Flag
                    "flag_emoji": flag.get("emoji"),
                    "flag_img": flag.get("img"),
                    # Timezone
                    "timezone_id": tz.get("id"),
                    "timezone_abbr": tz.get("abbr"),
                    "timezone_is_dst": tz.get("is_dst"),
                    "timezone_offset": tz.get("offset"),
                    "timezone_utc": tz.get("utc"),
                    "timezone_current_time": tz.get("current_time"),
                    # Connection / ASN
                    "asn": conn.get("asn"),
                    "asn_str": f"AS{conn.get('asn')}" if conn.get("asn") else None,
                    "org": conn.get("org"),
                    "isp": conn.get("isp"),
                    "domain": conn.get("domain"),
                }
    except Exception as e:
        whois_error = str(e)

    # Fallback: ipip.net HTML parse (HTTP to avoid SSL handshake issues)
    if whois_data is None:
        try:
            req = Request(
                f"http://whois.ipip.net/{ip}",
                headers={"User-Agent": "Mozilla/5.0 (compatible; Lilith/1.0)"},
            )
            with urlopen(req, timeout=6) as resp:
                html = resp.read().decode("utf-8", errors="replace")
                org_match = re.search(r'org:"?[\s]*([^<,]+)', html, re.IGNORECASE)
                asn_match = re.search(r'AS([\d]+)', html)
                netname_match = re.search(r'netname":?"?[\s]*([^"<,]+)', html, re.IGNORECASE)
                country_match = re.search(re.escape(ip) + r'.*([A-Z]{2})', html[:2000])
                whois_data = {
                    "org": org_match.group(1).strip() if org_match else None,
                    "asn": asn_match.group(1) if asn_match else None,
                    "asn_str": f"AS{asn_match.group(1)}" if asn_match else None,
                    "netname": netname_match.group(1).strip() if netname_match else None,
                    "country_code": country_match.group(1) if country_match else None,
                }
        except Exception as e:
            whois_error = str(e)

    result["whois"] = whois_data if whois_data else {"error": whois_error or "unreachable"}

    # 4. RDAP — authoritative registrar data (net range, abuse contact, org handle)
    rdap_data = None
    rdap_error = None

    # Try ARIN first (most comprehensive for North America), fallback to RIPE/APNIC
    rdap_urls = [
        f"https://rdap.arin.net/registry/ip/{ip}",
        f"https://rdap.db.ripe.net/ip/{ip}",
        f"https://rdap.apnic.net/ip/{ip}",
    ]
    for rdap_url in rdap_urls:
        try:
            with urlopen(
                Request(rdap_url, headers={"User-Agent": "Lilith/1.0", "Accept": "application/json"}),
                timeout=5,
            ) as resp:
                rdap = json.loads(resp.read().decode("utf-8"))
                entities = rdap.get("entities", []) or []
                # Extract abuse contact and org info
                abuse_email = None
                org_name = None
                org_handle = None
                for ent in entities:
                    roles = [r.lower() for r in (ent.get("roles") or [])]
                    vcard = ent.get("vcardArray", []) or []
                    if "abuse" in roles:
                        for item in vcard[1:] if len(vcard) > 1 else []:
                            if isinstance(item, (list, tuple)) and len(item) >= 4:
                                if item[0] == "email":
                                    abuse_email = item[3]
                    if "registrant" in roles or "org" in roles:
                        org_name = ent.get("handle") or ent.get("fn", "")
                        org_handle = ent.get("handle")
                        # Try to get actual org name from vcard
                        for item in vcard[1:] if len(vcard) > 1 else []:
                            if isinstance(item, (list, tuple)) and len(item) >= 4:
                                if item[0] == "fn":
                                    org_name = item[3]
                # Get network range
                start_addr = rdap.get("startAddress")
                end_addr = rdap.get("endAddress")
                net_name = rdap.get("name")
                net_type = rdap.get("type")
                handle = rdap.get("handle")
                parent_handle = rdap.get("parentHandle")

                rdap_data = {
                    "handle": handle,
                    "net_name": net_name,
                    "net_type": net_type,
                    "start_address": start_addr,
                    "end_address": end_addr,
                    "parent_handle": parent_handle,
                    "org_name": org_name,
                    "org_handle": org_handle,
                    "abuse_email": abuse_email,
                    "rir": rdap_url.split("/")[2].split(".")[1].upper(),
                }
                break  # Stop at first successful RDAP
        except Exception:
            continue  # Try next RIR

    if not rdap_data:
        rdap_data = {"error": "no RDAP data"}

    result["rdap"] = rdap_data

    return result


# =====================================================================
# Nmap — full reconnaissance system
# =====================================================================

# Nmap scan profiles for the recon panel
SCAN_PROFILES = {
    "quick": {
        "name": "Quick Scan",
        "desc": "Top 1000 ports, service version detection",
        "args": ["-sV", "--top-ports", "1000", "--open"],
        "timeout": 300,
        "admin": False,
    },
    "full": {
        "name": "Full Port Scan",
        "desc": "All 65535 ports with service detection (may be slow)",
        "args": ["-sV", "-p-", "--open"],
        "timeout": 600,
        "admin": False,
    },
    "aggressive": {
        "name": "Aggressive (-A)",
        "desc": "OS + service + scripts + traceroute — maximum info",
        "args": ["-A", "--top-ports", "1000"],
        "timeout": 600,
        "admin": False,
    },
    "os": {
        "name": "OS Detection",
        "desc": "Operating system fingerprinting",
        "args": ["-O", "-sV", "--top-ports", "500"],
        "timeout": 300,
        "admin": False,
    },
    "stealth": {
        "name": "Stealth SYN Scan",
        "desc": "Half-open SYN scan, faster (requires Administrator)",
        "args": ["-sS", "-sV", "--top-ports", "1000", "--open"],
        "timeout": 300,
        "admin": True,
    },
    "scripts": {
        "name": "Default Scripts",
        "desc": "NSE safe scripts + service version detection",
        "args": ["-sV", "-sC", "--top-ports", "1000"],
        "timeout": 600,
        "admin": False,
    },
    "vuln": {
        "name": "Vulnerability Scan",
        "desc": "Check for known CVEs via NSE vuln scripts (may be slow)",
        "args": ["-sV", "--script", "vuln", "--top-ports", "1000"],
        "timeout": 600,
        "admin": False,
    },
    "udp": {
        "name": "UDP Scan",
        "desc": "Top 100 UDP ports with service detection",
        "args": ["-sU", "-sV", "--top-ports", "100"],
        "timeout": 300,
        "admin": False,
    },
    "discovery": {
        "name": "Host Discovery",
        "desc": "Ping sweep only, no port scan",
        "args": ["-sn"],
        "timeout": 120,
        "admin": False,
    },
}


def _find_nmap() -> str | None:
    """
    Locate the nmap executable.
    Checks PATH first, then common Windows install locations.
    """
    # Check PATH
    try:
        subprocess.run(
            ["nmap", "--version"],
            capture_output=True, timeout=5, check=True,
        )
        return "nmap"
    except (FileNotFoundError, subprocess.TimeoutExpired, subprocess.CalledProcessError):
        pass

    # Check common install paths
    candidates = [
        r"C:\Program Files (x86)\Nmap\nmap.exe",
        r"C:\Program Files\Nmap\nmap.exe",
    ]
    for path in candidates:
        if os.path.exists(path):
            return path

    return None


@app.get("/api/nmap-status")
def nmap_status():
    """Check if nmap is available on this system. Returns available profiles."""
    nmap_path = _find_nmap()
    # Check if running as admin (needed for SYN scan)
    is_admin = False
    try:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        pass

    profiles = {
        k: {
            "name": v["name"],
            "desc": v["desc"],
            "admin_required": v["admin"],
            "available": is_admin if v["admin"] else True,
        }
        for k, v in SCAN_PROFILES.items()
    }

    if nmap_path:
        return {
            "available": True,
            "path": nmap_path,
            "admin": is_admin,
            "profiles": profiles,
            "message": "Nmap detected",
        }
    else:
        return {
            "available": False,
            "profiles": profiles,
            "message": "Nmap not found. Run bin/setup_nmap.bat as Administrator to install.",
        }


def _parse_nmap_xml(xml_text: str) -> dict:
    """Parse nmap XML output into structured data."""
    ports = []
    os_detection = []
    hostnames = []
    host_status = "unknown"
    scripts_result = []
    trace = None

    try:
        root = ET.fromstring(xml_text)
        for host in root.findall(".//host"):
            # Host status
            status_el = host.find("status")
            host_status = status_el.get("state") if status_el is not None else "unknown"

            # Hostnames
            for hn in host.findall(".//hostname"):
                hostnames.append({
                    "name": hn.get("name"),
                    "type": hn.get("type"),
                })

            # Ports with services
            for port_el in host.findall(".//port"):
                port_id = port_el.get("portid")
                protocol = port_el.get("protocol")
                state_el = port_el.find("state")
                state = state_el.get("state") if state_el is not None else "unknown"
                svc_el = port_el.find("service")
                service_name = svc_el.get("name") if svc_el is not None else "unknown"
                service_product = svc_el.get("product") if svc_el is not None else None
                service_version = svc_el.get("version") if svc_el is not None else None
                service_extrainfo = svc_el.get("extrainfo") if svc_el is not None else None

                # NSE script output on this port
                port_scripts = []
                for script_el in port_el.findall(".//script"):
                    port_scripts.append({
                        "id": script_el.get("id"),
                        "output": script_el.get("output"),
                    })

                version_parts = []
                if service_product:
                    version_parts.append(service_product)
                if service_version:
                    version_parts.append(service_version)
                if service_extrainfo:
                    version_parts.append(service_extrainfo)
                version_str = " ".join(version_parts) if version_parts else None

                ports.append({
                    "port": int(port_id),
                    "protocol": protocol,
                    "state": state,
                    "service": service_name,
                    "version": version_str,
                    "scripts": port_scripts,
                })

            # OS detection
            for osmatch in host.findall(".//osmatch"):
                os_detection.append({
                    "name": osmatch.get("name"),
                    "accuracy": osmatch.get("accuracy"),
                    "type": osmatch.get("type"),
                })

            # Host-level NSE scripts
            for script_el in host.findall("hostscript/script"):
                scripts_result.append({
                    "id": script_el.get("id"),
                    "output": script_el.get("output"),
                })

            # Traceroute
            trace_el = host.find("trace")
            if trace_el is not None:
                hops = []
                for hop in trace_el.findall("hop"):
                    hops.append({
                        "ttl": hop.get("ttl"),
                        "ip": hop.get("ipaddr"),
                        "host": hop.get("host"),
                        "rtt": hop.get("rtt"),
                    })
                trace = {
                    "port": trace_el.get("port"),
                    "protocol": trace_el.get("proto"),
                    "hops": hops,
                }

    except ET.ParseError:
        pass

    ports.sort(key=lambda p: p["port"])

    return {
        "host_status": host_status,
        "hostnames": hostnames,
        "ports": ports,
        "open_count": sum(1 for p in ports if p["state"] == "open"),
        "filtered_count": sum(1 for p in ports if p["state"] == "filtered"),
        "os_detection": os_detection,
        "scripts": scripts_result,
        "traceroute": trace,
    }


@app.get("/api/nmap-scan/{ip}")
def nmap_scan_ip(ip: str, profile: str = "quick"):
    """
    Run an nmap scan on the target IP with the specified profile.

    Profiles: quick, full, aggressive, os, stealth, scripts, vuln, udp, discovery
    """
    nmap_path = _find_nmap()
    if not nmap_path:
        return {
            "status": "unavailable",
            "message": "Nmap not found. Install via bin/setup_nmap.bat (run as Administrator).",
            "ports": [], "os_detection": [], "scripts": [],
        }

    profile_config = SCAN_PROFILES.get(profile)
    if not profile_config:
        return {
            "status": "error",
            "message": f"Unknown profile: {profile}. Available: quick, full, aggressive, os, stealth, scripts, vuln, udp, discovery",
            "ports": [], "os_detection": [], "scripts": [],
        }

    try:
        cmd = [nmap_path] + profile_config["args"] + ["-oX", "-", "--max-retries", "2", "--host-timeout", "10m", ip]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=profile_config["timeout"],
        )

        parsed = _parse_nmap_xml(result.stdout) if result.stdout else {}

        # Extract Nmap version
        nmap_version = ""
        for line in result.stderr.split("\n"):
            if "Nmap version" in line or "Nmap" in line:
                nmap_version = line.strip()
                break

        return {
            "status": "complete",
            "ip": ip,
            "profile": profile,
            "profile_name": profile_config["name"],
            "nmap_version": nmap_version,
            "command": " ".join(cmd),
            "raw_xml_size": len(result.stdout),
            **parsed,
        }

    except subprocess.TimeoutExpired:
        return {
            "status": "timeout",
            "message": f"Nmap scan timed out after {profile_config['timeout']}s",
            "ports": [], "os_detection": [], "scripts": [],
        }
    except Exception as e:
        return {
            "status": "error",
            "message": str(e),
            "ports": [], "os_detection": [], "scripts": [],
        }


# =====================================================================
# Whitelist
# =====================================================================

def _init_whitelist():
    conn = capture.get_db()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS whitelist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            entry_type TEXT NOT NULL,
            entry_value TEXT NOT NULL,
            added_at TEXT NOT NULL,
            UNIQUE(entry_type, entry_value)
        )
    """)
    conn.commit()
    conn.close()

@app.get("/api/whitelist")
async def get_whitelist():
    conn = capture.get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM whitelist ORDER BY added_at DESC")
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows

@app.post("/api/whitelist")
async def add_whitelist(entry_type: str = Query(...), entry_value: str = Query(...)):
    now = datetime.now(timezone.utc).isoformat()
    conn = capture.get_db()
    cur = conn.cursor()
    try:
        cur.execute(
            "INSERT INTO whitelist (entry_type, entry_value, added_at) VALUES (?, ?, ?)",
            (entry_type, entry_value, now),
        )
        conn.commit()
        return {"status": "ok", "message": f"Whitelisted {entry_type}: {entry_value}"}
    except Exception as e:
        return {"status": "error", "message": str(e)}
    finally:
        conn.close()

@app.delete("/api/whitelist/{entry_id}")
async def remove_whitelist(entry_id: int):
    conn = capture.get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM whitelist WHERE id = ?", (entry_id,))
    conn.commit()
    conn.close()
    return {"status": "ok"}


# =====================================================================
# Timeline
# =====================================================================

@app.get("/api/timeline")
async def timeline(
    time_range: str = Query(default="24h", description="live|1h|24h|48h|7d|30d|all"),
):
    """
    Connection counts bucketed by time.

    Bucket size automatically adjusts per range (e.g. 1-minute buckets
    for 1h, 6-hour buckets for 7d) so the chart always has ~20-60 points.
    """
    tr = "24h" if time_range == "live" else time_range
    return history.query_timeline(time_range=tr)


# =====================================================================
# Dashboard
# =====================================================================

@app.get("/", response_class=HTMLResponse)
async def dashboard():
    # Resolved from the project root so the dashboard is found no matter
    # which directory the app was launched from.
    dashboard_path = os.path.join(capture.PROJECT_ROOT, "dashboard.html")
    with open(dashboard_path, "r", encoding="utf-8") as f:
        return f.read()
