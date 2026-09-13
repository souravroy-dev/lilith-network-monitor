"""
Stage 3: IP Reputation Checker.

Checks each remote IP against SANS DShield (isc.sans.edu) — free community
threat intelligence. No API key, no signup, no configuration needed.

Design:
  - In-memory LRU cache: each IP checked once per session (up to 5000 entries).
  - Uses stdlib xml.etree.ElementTree for XML parsing (no extra deps).
  - DShield returns attack counts per IP; we map those to severity.
  - Network failures are silently handled — stage degrades gracefully.
"""

import time
import xml.etree.ElementTree as ET
from typing import NamedTuple


# ---------------------------------------------------------------------------
# Verdict type (same shape as stage2_heuristics.Verdict)
# ---------------------------------------------------------------------------

class Verdict(NamedTuple):
    severity: str
    reason: str
    rule_name: str


# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------

# _cache[ip] = (attack_count, timestamp)
_cache: dict[str, tuple[int, float]] = {}
_MAX_CACHE = 5000


# ---------------------------------------------------------------------------
# DShield lookup
# ---------------------------------------------------------------------------

def _dshield_lookup(ip: str) -> int | None:
    """
    Query SANS DShield for attack history on an IP.

    Returns total attack count or None on failure.
    No API key required — just a descriptive User-Agent header (SANS asks
    you to include contact info so they can reach out if there's a problem).
    """
    import requests as req

    try:
        resp = req.get(
            f"https://isc.sans.edu/api/ip/{ip}",
            headers={
                "User-Agent": "Lilith Security Monitor (passive traffic review)"
            },
            timeout=10,
        )
        if resp.status_code != 200:
            return None

        root = ET.fromstring(resp.text)
        ip_elem = root.find("ip")
        if ip_elem is None:
            return None

        attacks_str = ip_elem.findtext("numberofattacks", "0")
        return int(attacks_str) if attacks_str and attacks_str.isdigit() else 0

    except Exception as e:
        print(f"[reputation] DShield lookup failed for {ip}: {e}")
        return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_ip(ip: str) -> Verdict | None:
    """
    Check a single IP against SANS DShield reputation data.

    Returns a Verdict if the IP has reported attacks, or None if clean
    or the lookup failed.

    Severity mapping:
      - ≥100 attacks → HIGH
      - 1–99 attacks → MEDIUM
      - 0 attacks   → clean (None)
    """
    ip = ip.strip().lower()

    # Check cache
    cached = _cache.get(ip)
    if cached:
        attacks, _ts = cached
    else:
        if len(_cache) >= _MAX_CACHE:
            for k in list(_cache.keys())[:1000]:
                del _cache[k]
        attacks = _dshield_lookup(ip)
        if attacks is None:
            return None
        _cache[ip] = (attacks, time.time())

    if attacks == 0:
        return None  # clean

    if attacks >= 100:
        return Verdict(
            severity="high",
            reason=f"IP {ip} has {attacks} reported attacks on SANS DShield",
            rule_name="dshield_high",
        )
    return Verdict(
        severity="medium",
        reason=f"IP {ip} has {attacks} reported attacks on SANS DShield",
        rule_name="dshield_medium",
    )
