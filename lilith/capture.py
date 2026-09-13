"""
Connection capture module.

Polls the OS connection table via psutil, resolves the owning process for
each connection, and writes new/changed connections into SQLite. Designed
to be cheap to poll frequently (every 2-5s) without flooding the DB --
we dedupe on (local_ip, local_port, remote_ip, remote_port, pid).
"""
import ipaddress
import os
import sqlite3
import sys
import time
from datetime import datetime, timezone

import psutil

# Project root = the directory that contains the lilith/ package. All paths
# (database, dashboard.html) are resolved from here so the app works no matter
# which folder the user launches it from (important after moving to another PC).
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# The SQLite database lives next to the project. Override with the
# LILITH_DB_PATH environment variable to store it somewhere else.
DB_PATH = os.environ.get("LILITH_DB_PATH") or os.path.join(PROJECT_ROOT, "netmonitor.db")

# Windows consoles/log redirection default to cp1252 with strict errors, so a
# single non-ASCII character (—, →, ✅…) in any print() would crash the app.
# Force UTF-8 with lossy replacement everywhere from the start.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError):
        pass


def get_db():
    # WAL mode (set in init_db) lets the capture/geo/asn/triage loops read
    # and write concurrently without "database is locked" churn. The busy
    # timeout is a fallback for rare write/write contention.
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    cur = conn.cursor()

    # WAL mode: readers never block writers and concurrent writer threads
    # (capture, geoip, asn, triage, etw) rarely contend, so the background
    # loops stop tripping over each other's locks. Must run before any
    # transaction starts. Best-effort: if another instance holds the DB,
    # fall back to the default journal mode rather than failing startup.
    try:
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA busy_timeout=10000")
    except sqlite3.OperationalError:
        pass  # another connection holds a lock — continue without WAL

    cur.execute("""
        CREATE TABLE IF NOT EXISTS connections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            local_ip TEXT,
            local_port INTEGER,
            remote_ip TEXT,
            remote_port INTEGER,
            status TEXT,
            pid INTEGER,
            proc_name TEXT,
            proc_exe TEXT,
            proc_cmdline TEXT,
            proc_memory_mb REAL,
            proc_cpu_pct REAL,
            direction TEXT,
            dedupe_key TEXT UNIQUE,
            geo_country TEXT,
            geo_country_code TEXT,
            geo_city TEXT,
            geo_org TEXT,
            geo_lat REAL,
            geo_lon REAL,
            geo_lookup_done INTEGER DEFAULT 0,
            verdict TEXT,
            severity TEXT,
            reason TEXT,
            analyzed INTEGER DEFAULT 0
        )
    """)

    # Whitelist table. Lives here (not in app.py) so the schema is fully
    # self-contained: triage/pipeline can run standalone without the web app.
    cur.execute("""
        CREATE TABLE IF NOT EXISTS whitelist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            entry_type TEXT NOT NULL,
            entry_value TEXT NOT NULL,
            added_at TEXT NOT NULL,
            UNIQUE(entry_type, entry_value)
        )
    """)

    # Migration: add geo_lat/geo_lon columns if they don't exist yet
    try:
        cur.execute("ALTER TABLE connections ADD COLUMN geo_lat REAL")
    except sqlite3.OperationalError:
        pass  # column already exists
    try:
        cur.execute("ALTER TABLE connections ADD COLUMN geo_lon REAL")
    except sqlite3.OperationalError:
        pass  # column already exists
    try:
        cur.execute("ALTER TABLE connections ADD COLUMN geo_country_code TEXT")
    except sqlite3.OperationalError:
        pass  # column already exists
    try:
        cur.execute("ALTER TABLE connections ADD COLUMN proc_memory_mb REAL")
    except sqlite3.OperationalError:
        pass
    try:
        cur.execute("ALTER TABLE connections ADD COLUMN proc_cpu_pct REAL")
    except sqlite3.OperationalError:
        pass
    # Re-fetch IPs that were resolved before we started storing coordinates
    # Migration: add pipeline tracking columns
    for col in ("pipeline_stage", "pipeline_rule"):
        try:
            cur.execute(f"ALTER TABLE connections ADD COLUMN {col} TEXT")
        except sqlite3.OperationalError:
            pass  # column already exists

    # ------------------------------------------------------------------
    # Migration: ASN / reverse-DNS enrichment columns (Tier 1 + DNS stage).
    # Populated by lilith/asn.py (Team Cymru ASN + PTR hostnames).
    # ------------------------------------------------------------------
    for col in ("remote_asn", "remote_as_org", "remote_hostname"):
        try:
            cur.execute(f"ALTER TABLE connections ADD COLUMN {col} TEXT")
        except sqlite3.OperationalError:
            pass  # column already exists
    for col in ("asn_lookup_done", "rdns_done"):
        try:
            cur.execute(f"ALTER TABLE connections ADD COLUMN {col} INTEGER DEFAULT 0")
        except sqlite3.OperationalError:
            pass  # column already exists

    # ------------------------------------------------------------------
    # Migration: rename the legacy LLM-era columns to neutral names.
    # The LLM stage was removed, so llm_analyzed/llm_verdict/llm_severity/
    # llm_reason become analyzed/verdict/severity/reason. Existing data is
    # copied across; the old columns (and their index) are dropped.
    # ------------------------------------------------------------------
    existing = {row["name"] for row in cur.execute("PRAGMA table_info(connections)")}
    legacy_renames = (
        ("llm_analyzed", "analyzed", "INTEGER DEFAULT 0"),
        ("llm_verdict", "verdict", "TEXT"),
        ("llm_severity", "severity", "TEXT"),
        ("llm_reason", "reason", "TEXT"),
    )
    migrated = False
    for old, new, ddl in legacy_renames:
        if new not in existing:
            cur.execute(f"ALTER TABLE connections ADD COLUMN {new} {ddl}")
        if old in existing:
            # Copy legacy data into the new column, then drop the old one.
            cur.execute(f"UPDATE connections SET {new} = {old}")
            migrated = True

    if migrated:
        # The index on the old column must be removed before dropping it.
        cur.execute("DROP INDEX IF EXISTS idx_conn_analyzed")
        for old, _new, _ddl in legacy_renames:
            try:
                cur.execute(f"ALTER TABLE connections DROP COLUMN {old}")
                print(f"[capture] migrated: dropped legacy column '{old}'")
            except sqlite3.OperationalError as e:
                print(f"[capture] note: could not drop legacy column '{old}': {e}")

    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_conn_analyzed
        ON connections (analyzed)
    """)
    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_conn_geo
        ON connections (geo_lookup_done)
    """)
    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_conn_last_seen
        ON connections (last_seen)
    """)

    cur.execute("UPDATE connections SET geo_lookup_done = 0 WHERE geo_lookup_done = 1 AND geo_lat IS NULL")

    conn.commit()
    conn.close()


_WELL_KNOWN_SERVER_PORTS = {
    20, 21, 22, 23, 25, 53, 80, 110, 123, 143, 161, 194, 389,
    443, 465, 514, 587, 636, 853, 993, 995, 1080, 1194, 1433,
    1521, 2049, 2375, 2376, 3306, 3389, 5432, 5900, 5901, 6379,
    8080, 8443, 9090, 9200, 27017,
}

# Processes that are virtually always making outbound connections
_KNOWN_CLIENTS = {
    "chrome.exe", "firefox.exe", "msedge.exe", "opera.exe", "brave.exe",
    "iexplore.exe", "safari.exe",
    "spotify.exe", "discord.exe", "slack.exe", "teams.exe", "zoom.exe",
    "steam.exe", "epicgameslauncher.exe", "xboxapp.exe", "battle.net.exe",
    "outlook.exe", "thunderbird.exe",
    "python.exe", "python3.exe", "node.exe", "dotnet.exe",
    "svchost.exe", "services.exe", "lsass.exe", "winlogon.exe",
    "searchapp.exe", "searchindexer.exe",
    "onedrive.exe", "googledrivesync.exe", "dropbox.exe",
    "nvdisplay.container.exe", "nvcontainer.exe",
    "windowsupdate.exe", "musnotification.exe",
    "system", "system idle process",
}


def _detect_direction(local_port: int | None, remote_port: int | None, proc_name: str | None) -> str:
    """
    Heuristic direction detection for a connection.

    Returns "outbound", "inbound", or "unknown".

    Logic:
    - If process is a known client app → outbound
    - If remote port is a well-known server port → outbound (we're connecting *to* a server)
    - If local port is >= 49152 (Windows ephemeral range) → outbound (client port)
    - If local port is a well-known server port → likely inbound
    - Otherwise → unknown
    """
    name_lower = (proc_name or "").lower()

    if name_lower in _KNOWN_CLIENTS:
        return "outbound"

    if remote_port is not None and remote_port in _WELL_KNOWN_SERVER_PORTS:
        return "outbound"

    if local_port is not None and local_port >= 49152:
        return "outbound"

    if local_port is not None and local_port in _WELL_KNOWN_SERVER_PORTS:
        return "inbound"

    return "outbound"  # most connections are outbound for a personal PC


def is_public_ip(ip: str) -> bool:
    """Only worth geo-locating / flagging public internet addresses."""
    try:
        addr = ipaddress.ip_address(ip)
        return not (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_multicast
            or addr.is_reserved
        )
    except ValueError:
        return False


def _proc_info(pid):
    """Best-effort process info lookup. Returns (name, exe, cmdline, mem_mb, cpu_pct)."""
    if pid is None:
        return None, None, None, None, None
    try:
        p = psutil.Process(pid)
        name = p.name()
        try:
            exe = p.exe()
        except (psutil.AccessDenied, psutil.ZombieProcess):
            exe = None
        try:
            cmdline = " ".join(p.cmdline())[:500]
        except (psutil.AccessDenied, psutil.ZombieProcess):
            cmdline = None
        try:
            mem = p.memory_info().rss / (1024 * 1024)  # MB
        except Exception:
            mem = None
        try:
            cpu = p.cpu_percent(interval=0)
        except Exception:
            cpu = None
        return name, exe, cmdline, mem, cpu
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return None, None, None, None, None


def poll_once():
    """
    Snapshot current connections, upsert into DB.
    Returns number of NEW connections seen this poll.
    """
    now = datetime.now(timezone.utc).isoformat()
    conn = get_db()
    cur = conn.cursor()

    new_count = 0

    try:
        conns = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, PermissionError):
        # On Windows this usually means "run as Administrator" for full
        # visibility into other users' processes. Partial results still work.
        conns = []

    for c in conns:
        if not c.raddr:
            # No remote address = listening socket, not an active outbound/inbound flow.
            continue

        local_ip, local_port = (c.laddr.ip, c.laddr.port) if c.laddr else (None, None)
        remote_ip, remote_port = c.raddr.ip, c.raddr.port
        status = c.status
        pid = c.pid

        # Only track connections to public IPs -- LAN chatter is noisy and low-signal.
        if not is_public_ip(remote_ip):
            continue

        name, exe, cmdline, mem_mb, cpu_pct = _proc_info(pid)
        direction = _detect_direction(local_port, remote_port, name)

        dedupe_key = f"{local_ip}:{local_port}-{remote_ip}:{remote_port}-{pid}"

        cur.execute(
            "SELECT id FROM connections WHERE dedupe_key = ?", (dedupe_key,)
        )
        row = cur.fetchone()

        if row:
            cur.execute(
                "UPDATE connections SET last_seen = ?, status = ?, direction = ?, proc_memory_mb = ?, proc_cpu_pct = ? WHERE id = ?",
                (now, status, direction, mem_mb, cpu_pct, row["id"]),
            )
        else:
            new_count += 1
            cur.execute(
                """
                INSERT INTO connections
                (first_seen, last_seen, local_ip, local_port, remote_ip, remote_port,
                 status, pid, proc_name, proc_exe, proc_cmdline, proc_memory_mb, proc_cpu_pct,
                 direction, dedupe_key)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    now, now, local_ip, local_port, remote_ip, remote_port,
                    status, pid, name, exe, cmdline, mem_mb, cpu_pct,
                    direction,
                    dedupe_key,
                ),
            )

    conn.commit()
    conn.close()
    return new_count


def capture_loop(interval_seconds=3):
    init_db()
    print(f"[capture] polling every {interval_seconds}s ... Ctrl+C to stop")
    while True:
        try:
            n = poll_once()
            if n:
                print(f"[capture] {n} new connection(s)")
        except Exception as e:
            print(f"[capture] error: {e}")
        time.sleep(interval_seconds)


if __name__ == "__main__":
    capture_loop()
