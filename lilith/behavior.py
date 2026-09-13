"""
Stage 4: Behavioral Anomaly Detection.

Tracks per-process network activity in a rolling 5-minute window and
flags connections that deviate from expected patterns.

Detects:
  - Connection bursts: >10 connections in 60s from the same process
  - Country spread: connections to >3 unique countries in 60s
  - IP spread: connections to >8 unique IPs in 60s
  - First-seen process making connections (not anomalous — these pass through)

Design:
  - In-memory only (resets on app restart — acceptable for MVP).
  - Rolling window evicts entries older than 300 seconds.
  - Each entry is a lightweight (timestamp, remote_ip, country) tuple.
  - Thread-safe for a single-threaded pipeline (pipeline runs in one thread).
"""

import time
from collections import defaultdict, deque
from typing import NamedTuple


# ---------------------------------------------------------------------------
# Verdict type
# ---------------------------------------------------------------------------

class Verdict(NamedTuple):
    severity: str
    reason: str
    rule_name: str


# ---------------------------------------------------------------------------
# Rolling window config
# ---------------------------------------------------------------------------

_WINDOW_SEC = 300       # 5-minute window
_BURST_THRESHOLD = 10   # connections in 60s
_COUNTRY_SPREAD = 3     # unique countries in 60s
_IP_SPREAD = 8          # unique IPs in 60s
_LOOKBACK = 60          # seconds for rate checks


# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------

# _history[proc_name_lower] = deque of (timestamp, remote_ip, country)
_history: dict[str, deque] = defaultdict(
    lambda: deque(maxlen=500)
)
_seen_procs: set[str] = set()  # processes we've seen before


def _prune(proc: str):
    """Remove entries older than the window from a process's history."""
    dq = _history[proc]
    cutoff = time.time() - _WINDOW_SEC
    while dq and dq[0][0] < cutoff:
        dq.popleft()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def evaluate_behavior(connection: dict) -> Verdict | None:
    """
    Check a connection against the process's recent behavior history.

    Must be called with a full connection dict (at minimum proc_name,
    remote_ip, and geo_country must be present).

    Returns a Verdict if an anomaly is detected, or None if the behavior
    appears normal.
    """
    proc = (connection.get("proc_name") or "").strip().lower()
    if not proc or proc in ("system", "system idle process", ""):
        return None

    now = time.time()
    ip = connection.get("remote_ip", "")
    country = connection.get("geo_country") or ""

    # Track this process
    is_new_proc = proc not in _seen_procs
    _seen_procs.add(proc)

    # Prune old entries
    _prune(proc)

    # Record this connection
    _history[proc].append((now, ip, country))

    # Don't flag first-time processes (they need a baseline)
    if is_new_proc:
        return None

    # Count events within the lookback window
    cutoff = now - _LOOKBACK
    recent = [e for e in _history[proc] if e[0] >= cutoff]

    if len(recent) < 3:
        return None  # not enough data to judge

    # --- Check 1: Connection burst ---
    if len(recent) > _BURST_THRESHOLD:
        return Verdict(
            severity="medium",
            reason=f"Burst: {proc} made {len(recent)} connections in 60s",
            rule_name="behavior_burst",
        )

    # --- Check 2: Country spread ---
    countries = {e[2] for e in recent if e[2]}
    if len(countries) > _COUNTRY_SPREAD:
        return Verdict(
            severity="medium",
            reason=f"Geographic spread: {proc} connected to {len(countries)} countries in 60s",
            rule_name="behavior_country_spread",
        )

    # --- Check 3: IP spread ---
    unique_ips = {e[1] for e in recent if e[1]}
    if len(unique_ips) > _IP_SPREAD:
        return Verdict(
            severity="medium",
            reason=f"IP spread: {proc} connected to {len(unique_ips)} unique IPs in 60s",
            rule_name="behavior_ip_spread",
        )

    return None


def reset():
    """Clear all behavioral state (useful for testing)."""
    _history.clear()
    _seen_procs.clear()
