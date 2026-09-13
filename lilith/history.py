"""
Historical data query module.

Provides time-range-aware query functions that let the dashboard browse
past connections without interfering with the live capture/triage loops.

Time ranges are defined in RANGES and can be extended. Each range has:
  - label:     display name shown in the UI
  - seconds:   lookback window from "now" (None = all time)
  - bucket_sec: timeline chart bucket granularity in seconds

Usage (from app.py):
    from history import query_connections, RANGES
    rows = query_connections(time_range="48h", severity="high")

Design:
  - All functions open/close their own DB connection (no shared state)
  - Uses the existing idx_conn_last_seen index for efficient range queries
  - Zero impact on capture.py, geoip.py, or triage.py
"""

from datetime import datetime, timedelta, timezone

from .capture import get_db

# ---------------------------------------------------------------------------
# Time range definitions
# ---------------------------------------------------------------------------

RANGES = {
    "live": {
        "label": "⚡ LIVE",
        "seconds": 300,  # 5 minutes
        "bucket_sec": 60,  # 1-minute buckets
    },
    "1h": {
        "label": "1h",
        "seconds": 3600,
        "bucket_sec": 60,  # 1-minute buckets → ~60 data points
    },
    "24h": {
        "label": "24h",
        "seconds": 86400,
        "bucket_sec": 3600,  # 1-hour buckets → 24 data points
    },
    "48h": {
        "label": "48h",
        "seconds": 172800,
        "bucket_sec": 3600,  # 1-hour buckets → 48 data points
    },
    "7d": {
        "label": "7d",
        "seconds": 604800,
        "bucket_sec": 21600,  # 6-hour buckets → 28 data points
    },
    "3d": {
        "label": "3d",
        "seconds": 259200,  # 72 hours
        "bucket_sec": 10800,  # 3-hour buckets → 24 data points
    },
    "30d": {
        "label": "30d",
        "seconds": 2592000,
        "bucket_sec": 86400,  # 1-day buckets → 30 data points
    },
    "all": {
        "label": "all",
        "seconds": None,
        "bucket_sec": 86400,  # 1-day buckets
    },
}


def validate(time_range: str | None) -> bool:
    """Return True if time_range is a valid key or None."""
    return time_range is None or time_range in RANGES


def get_cutoff(time_range: str | None) -> str | None:
    """Return an ISO-8601 cutoff string, or None for 'all' / invalid."""
    if not time_range or time_range not in RANGES:
        return None
    seconds = RANGES[time_range]["seconds"]
    if seconds is None:
        return None
    return (datetime.now(timezone.utc) - timedelta(seconds=seconds)).isoformat()


# ---------------------------------------------------------------------------
# SQL WHERE builder
# ---------------------------------------------------------------------------

def _build_where(
    params: list,
    conditions: list,
    time_range: str | None = None,
    severity: str | None = None,
    search: str | None = None,
    pipeline_stage: str | None = None,
) -> str:
    """Mutate *params* and *conditions* in-place, return the WHERE clause string."""
    if time_range and time_range != "all":
        cutoff = get_cutoff(time_range)
        if cutoff:
            conditions.append("last_seen >= ?")
            params.append(cutoff)

    if severity:
        conditions.append("severity = ?")
        params.append(severity)

    if pipeline_stage:
        conditions.append("pipeline_stage = ?")
        params.append(pipeline_stage)

    if search:
        conditions.append(
            "(remote_ip LIKE ? OR proc_name LIKE ? OR geo_country LIKE ? "
            "OR geo_city LIKE ? OR geo_org LIKE ?)"
        )
        like = f"%{search}%"
        params.extend([like, like, like, like, like])

    if conditions:
        return "WHERE " + " AND ".join(conditions)
    return ""


# ---------------------------------------------------------------------------
# Queries
# ---------------------------------------------------------------------------

def query_connections(
    time_range: str | None = None,
    severity: str | None = None,
    search: str | None = None,
    pipeline_stage: str | None = None,
    limit: int = 200,
) -> list[dict]:
    """Return connections filtered by time_range / severity / search / stage."""
    conn = get_db()
    cur = conn.cursor()
    params: list = []
    conditions: list = []
    where = _build_where(params, conditions, time_range, severity, search, pipeline_stage)
    cur.execute(
        f"SELECT * FROM connections {where} ORDER BY last_seen DESC LIMIT ?",
        (*params, limit),
    )
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def _clause(where: str, extra: str) -> str:
    """Safely append an extra condition to an existing WHERE clause."""
    if where:
        return f"{where} AND {extra}"
    return f"WHERE {extra}"


def query_stats(
    time_range: str | None = None,
) -> dict:
    """Return aggregate stats scoped to *time_range*."""
    conn = get_db()
    cur = conn.cursor()
    params: list = []
    conditions: list = []
    where = _build_where(params, conditions, time_range)

    cur.execute(f"SELECT COUNT(*) c FROM connections {where}", tuple(params))
    total = cur.fetchone()["c"]

    cur.execute(
        f"SELECT COUNT(*) c FROM connections {_clause(where, 'analyzed = 0')}",
        tuple(params),
    )
    pending_analysis = cur.fetchone()["c"]

    cur.execute(
        f"SELECT COUNT(*) c FROM connections {_clause(where, 'geo_lookup_done = 0')}",
        tuple(params),
    )
    pending_geo = cur.fetchone()["c"]

    # Severity counts — build fresh conditions per severity, preserving
    # the time-range condition already baked into `conditions`.
    severity_counts = {}
    for sev in ("low", "medium", "high"):
        p = params + [sev]
        w = _build_where([], conditions.copy(), time_range=None, severity=sev)
        cur.execute(
            f"SELECT COUNT(*) c FROM connections {w}",
            tuple(p),
        )
        severity_counts[sev] = cur.fetchone()["c"]

    cur.execute(
        f"SELECT COUNT(DISTINCT remote_ip) c FROM connections {where}",
        tuple(params),
    )
    unique_ips = cur.fetchone()["c"]

    cur.execute(
        f"SELECT COUNT(DISTINCT proc_name) c FROM connections {_clause(where, 'proc_name IS NOT NULL')}",
        tuple(params),
    )
    unique_procs = cur.fetchone()["c"]

    conn.close()
    return {
        "total_connections": total,
        "pending_analysis": pending_analysis,
        "pending_geo": pending_geo,
        "severity_counts": severity_counts,
        "unique_remote_ips": unique_ips,
        "unique_processes": unique_procs,
    }


def query_processes(
    time_range: str | None = None,
    limit: int = 20,
) -> list[dict]:
    """Top processes by outbound volume, scoped to *time_range*."""
    conn = get_db()
    cur = conn.cursor()
    params: list = []
    conditions: list = []
    where = _build_where(params, conditions, time_range)

    pid_where = f"{where} AND pid IS NOT NULL" if where else "WHERE pid IS NOT NULL"

    cur.execute(
        f"""
        SELECT proc_name, proc_exe, COUNT(*) as conn_count,
               COUNT(DISTINCT remote_ip) as unique_ips,
               MAX(pid) as sample_pid,
               ROUND(MAX(proc_memory_mb), 1) as peak_mem_mb,
               ROUND(MAX(proc_cpu_pct), 1) as peak_cpu_pct,
               SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) as high_count,
               SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END) as medium_count
        FROM connections
        {pid_where}
        GROUP BY proc_name, proc_exe
        ORDER BY conn_count DESC
        LIMIT ?
        """,
        (*params, limit),
    )
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def query_timeline(
    time_range: str = "24h",
) -> list[dict]:
    """
    Connection counts bucketed by time.

    Bucket size is chosen per time range so the chart always has a
    reasonable number of data points (between ~20 and ~60).
    """
    if not validate(time_range):
        time_range = "24h"
    bucket_sec = RANGES.get(time_range, RANGES["24h"])["bucket_sec"]
    cutoff = get_cutoff(time_range) or "1970-01-01"

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT
            datetime(
                CAST(STRFTIME('%%s', first_seen) AS INTEGER) / ? * ?,
                'unixepoch'
            ) AS bucket,
            COUNT(*) AS count
        FROM connections
        WHERE first_seen >= ?
        GROUP BY bucket
        ORDER BY bucket ASC
        """,
        (bucket_sec, bucket_sec, cutoff),
    )
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def query_geo_all(
    time_range: str | None = None,
) -> list[dict]:
    """All geo-located IPs with coordinates, scoped to *time_range*."""
    conn = get_db()
    cur = conn.cursor()
    params: list = []
    conditions: list = []
    where = _build_where(params, conditions, time_range)

    geo_where = f"{where} AND geo_lookup_done = 1 AND geo_lat IS NOT NULL" if where \
        else "WHERE geo_lookup_done = 1 AND geo_lat IS NOT NULL"

    cur.execute(
        f"""
        SELECT remote_ip, geo_country, geo_country_code, geo_city, geo_org,
               geo_lat, geo_lon,
               COUNT(*) as conn_count,
               SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) as flag_count
        FROM connections
        {geo_where}
        GROUP BY remote_ip, geo_country, geo_country_code, geo_city, geo_org,
                 geo_lat, geo_lon
        ORDER BY conn_count DESC
        """,
        tuple(params),
    )
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def export_csv_rows(
    time_range: str | None = None,
    severity: str | None = None,
    search: str | None = None,
) -> list:
    """Return raw rows for CSV export, filtered and ordered."""
    conn = get_db()
    cur = conn.cursor()
    params: list = []
    conditions: list = []
    where = _build_where(params, conditions, time_range, severity, search)

    cur.execute(
        f"""
        SELECT first_seen, last_seen, local_ip, local_port, remote_ip, remote_port,
               proc_name, proc_exe, geo_country, geo_city, geo_org,
               remote_asn, remote_hostname,
               severity, reason
        FROM connections
        {where}
        ORDER BY last_seen DESC
        """,
        tuple(params),
    )
    rows = cur.fetchall()
    conn.close()
    return rows
