"""
Automated database cleanup module.

Runs as a background daemon thread that periodically purges connection
records older than a configured retention period. Designed to be safe,
observable, and completely separate from the capture/geo/triage pipeline.

Design decisions:
  - Only deletes based on `last_seen` — never touches connections still
    being actively kept alive by the OS.
  - Uses its own DB connection for each purge (same pattern as capture.py).
  - Never runs VACUUM automatically — the SQLite page reuse makes it
    unnecessary for steady-state operation. An explicit VACUUM endpoint
    is available for manual use.
  - Config is in-memory (survives until the process restarts). For MVP
    this is fine since the default of 30 days is sensible for most users.
"""

import os
import time
from datetime import datetime, timedelta, timezone

from .capture import DB_PATH, get_db

# ---------------------------------------------------------------------------
# Config (in-memory, persists for the lifetime of the process)
# ---------------------------------------------------------------------------

_config: dict = {
    "enabled": True,
    "retention_days": 30,
    "interval_seconds": 86400,  # 24 hours
    "last_purge": None,
    "total_deleted": 0,
    "purge_count": 0,  # how many times purge has run
}


def get_config() -> dict:
    """Return a copy of the current cleanup config."""
    return dict(_config)


def update_config(**kwargs) -> dict:
    """Update config keys. Valid keys: enabled, retention_days, interval_seconds."""
    valid = {"enabled", "retention_days", "interval_seconds"}
    for k, v in kwargs.items():
        if k in valid:
            _config[k] = v
    return dict(_config)


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

def get_stats() -> dict:
    """Return info about the database: size, oldest record, purge history."""
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM connections")
    total = cur.fetchone()[0]
    cur.execute("SELECT MIN(last_seen) FROM connections")
    oldest = cur.fetchone()[0]
    conn.close()

    db_size = os.path.getsize(DB_PATH) if os.path.exists(DB_PATH) else 0

    config = get_config()
    return {
        "total_connections": total,
        "oldest_record": oldest,
        "db_size_bytes": db_size,
        "db_size_mb": round(db_size / (1024 * 1024), 2),
        "retention_days": config["retention_days"],
        "enabled": config["enabled"],
        "last_purge": config["last_purge"],
        "total_deleted": config["total_deleted"],
        "purge_count": config["purge_count"],
    }


# ---------------------------------------------------------------------------
# Purge logic
# ---------------------------------------------------------------------------

def purge_once(retention_days: int | None = None) -> int:
    """
    Delete connections where *last_seen* is older than *retention_days*.

    Returns the number of rows deleted.
    """
    days = retention_days if retention_days is not None else _config["retention_days"]
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()

    conn = get_db()
    cur = conn.cursor()

    # Count first
    cur.execute("SELECT COUNT(*) FROM connections WHERE last_seen < ?", (cutoff,))
    count = cur.fetchone()[0]

    if count > 0:
        cur.execute("DELETE FROM connections WHERE last_seen < ?", (cutoff,))
        conn.commit()
        print(
            f"[cleanup] purged {count} connection(s) older than {days} days "
            f"(cutoff: {cutoff})"
        )

    _config["last_purge"] = datetime.now(timezone.utc).isoformat()
    _config["total_deleted"] += count
    _config["purge_count"] += 1

    conn.close()
    return count


def purge_all() -> int:
    """
    Delete ALL connection records from the database.
    Also resets the whitelist table.

    Returns the number of rows deleted.
    This is a hard reset — use with caution.
    """
    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT COUNT(*) FROM connections")
    count = cur.fetchone()[0]

    cur.execute("DELETE FROM connections")
    cur.execute("DELETE FROM whitelist")
    conn.commit()
    conn.close()

    print(f"[cleanup] purged ALL {count} connection(s) and whitelist (hard reset)")
    _config["total_deleted"] += count
    _config["purge_count"] += 1
    return count


def vacuum_db() -> dict:
    """
    Run VACUUM to reclaim disk space after large deletes.
    Returns dict with size before and after.
    """
    before = os.path.getsize(DB_PATH) if os.path.exists(DB_PATH) else 0
    conn = get_db()
    conn.execute("VACUUM")
    conn.close()
    after = os.path.getsize(DB_PATH) if os.path.exists(DB_PATH) else 0
    saved = before - after
    print(f"[cleanup] VACUUM completed: {before} -> {after} bytes ({saved} freed)")
    return {
        "before_bytes": before,
        "after_bytes": after,
        "saved_bytes": saved,
    }


# ---------------------------------------------------------------------------
# Background loop
# ---------------------------------------------------------------------------

def purge_loop(interval_seconds: int | None = None):
    """
    Background daemon loop.

    Runs the first purge after a 60-second delay (so the app boots fast),
    then repeats every *interval_seconds* (default 24 h).
    """
    interval = interval_seconds or _config["interval_seconds"]
    days = _config["retention_days"]
    print(f"[cleanup] loop started — retention {days}d, interval {interval}s")

    # Short initial delay so the app is responsive immediately
    time.sleep(60)

    while True:
        if _config.get("enabled", True):
            try:
                purge_once()
            except Exception as e:
                print(f"[cleanup] error during purge: {e}")
        time.sleep(interval)
