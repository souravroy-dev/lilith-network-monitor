"""
Threat-intel blocklist stage (Tier 3).

Two zero-key threat-intel sources:
  1. **Feodo Tracker** (abuse.ch) — botnet C2 IP blocklist (Dridex/Emotet/
     QakBot…), a static text file refreshed hourly. A hit = HIGH.
  2. **Spamhaus ZEN** — DNS-based reputation (SBL/CSS/XBL/PBL combined zone).
     A hit = MEDIUM/LOW depending on the zone code.

Design:
  - The Feodo list is fetched over HTTP (requests) with an hourly TTL and
    held in memory as a set of IPs.
  - ZEN is queried per-IP via a DNS A lookup on <reversed>.zen.spamhaus.org
    using the system resolver. (Spamhaus discourages public recursive
    resolvers like 8.8.8.8 — the default Windows DNS config is fine.)
  - Every failure degrades gracefully (offline → skipped), exactly like
    stage 3 (DShield). ZEN results are cached per IP for the session.
"""

import ipaddress
import time
from typing import NamedTuple

import dns.resolver
import requests

# ---------------------------------------------------------------------------
# Verdict type (same shape as the other stages)
# ---------------------------------------------------------------------------

class Verdict(NamedTuple):
    severity: str
    reason: str
    rule_name: str


# ---------------------------------------------------------------------------
# Sources
# ---------------------------------------------------------------------------

FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
FEODO_TTL_SEC = 3600
ZEN_SUFFIX = ".zen.spamhaus.org"
REQUEST_TIMEOUT = 15

# 127.0.0.x ZEN zone codes → (severity, human label)
_ZEN_CODES = {
    "127.0.0.2": ("medium", "Spamhaus SBL — listed spam source"),
    "127.0.0.3": ("medium", "Spamhaus CSS — listed phishing-domain host"),
    "127.0.0.4": ("medium", "Spamhaus XBL — listed exploit / malware source"),
    "127.0.0.9": ("high", "Spamhaus DROP — policy-blocked netblock"),
    "127.0.0.10": ("low", "Spamhaus PBL — dynamic / residential IP range"),
    "127.0.0.11": ("low", "Spamhaus PBL — dynamic / residential IP range"),
}

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------

_feodo_ips: set[str] = set()
_feodo_ts: float = 0.0
_zen_cache: dict[str, tuple[str, str] | None] = {}   # ip -> (code, label) or None
_zen_failed: set[str] = set()                        # transient failures — skip quietly
_ZEN_MAX_CACHE = 20000


# ---------------------------------------------------------------------------
# Feodo Tracker
# ---------------------------------------------------------------------------

def _parse_feodo(text: str) -> set[str]:
    """
    Parse the Feodo Tracker plain-text IP list (lines, '#' comments).

    Only valid IP addresses are kept — this guards against a proxy error
    page or other junk being mistaken for blocklist entries.
    """
    result: set[str] = set()
    for line in text.splitlines():
        candidate = line.strip().lower()
        if not candidate or candidate.startswith("#"):
            continue
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            continue
        result.add(candidate)
    return result


def refresh_feodo() -> bool:
    """Fetch the Feodo blocklist into memory. Returns True on success."""
    global _feodo_ips, _feodo_ts
    try:
        resp = requests.get(
            FEODO_URL,
            timeout=REQUEST_TIMEOUT,
            headers={"User-Agent": "Lilith Security Monitor (passive traffic review)"},
        )
        resp.raise_for_status()
        ips = _parse_feodo(resp.text)
        if not ips:
            return False
        _feodo_ips = ips
        _feodo_ts = time.time()
        print(f"[blocklist] loaded {len(ips)} Feodo Tracker C2 IPs")
        return True
    except Exception as e:
        print(f"[blocklist] Feodo refresh failed: {e}")
        return False


def feodo_hit(ip: str) -> Verdict | None:
    """Check an IP against the loaded Feodo list (HIGH if present)."""
    if not _feodo_ips or not ip:
        return None
    if ip.strip().lower() in _feodo_ips:
        return Verdict(
            severity="high",
            reason=f"IP {ip} is in the Feodo Tracker botnet C2 blocklist",
            rule_name="feodo_c2",
        )
    return None


# ---------------------------------------------------------------------------
# Spamhaus ZEN
# ---------------------------------------------------------------------------

def _zen_lookup(ip: str):
    """
    DNS lookup of <reversed>.zen.spamhaus.org. Returns (code, label) or None.
    Cached per IP for the session.
    """
    if ip in _zen_cache:
        return _zen_cache[ip]
    try:
        name = ".".join(reversed(ip.split("."))) + ZEN_SUFFIX
        answers = dns.resolver.resolve(name, "A", lifetime=3)
        code = answers[0].to_text()
        result = _ZEN_CODES.get(code) or ("medium", f"Spamhaus ZEN listing {code}")
        if len(_zen_cache) >= _ZEN_MAX_CACHE:
            _zen_cache.clear()
        _zen_cache[ip] = result
        return result
    except dns.resolver.NXDOMAIN:
        _zen_cache[ip] = None
        return None
    except Exception:
        # Transient network failure — don't cache, but don't hammer either.
        _zen_failed.add(ip)
        if len(_zen_failed) > 5000:
            _zen_failed.clear()
        return None


def zen_hit(ip: str) -> Verdict | None:
    """Check an IP against Spamhaus ZEN (severity mapped from the zone code)."""
    ip = ip.strip().lower()
    if not ip or ip in _zen_failed:
        return None
    result = _zen_lookup(ip)
    if not result:
        return None
    severity, label = result
    return Verdict(
        severity=severity,
        reason=f"IP {ip} is listed in {label}",
        rule_name="spamhaus_zen",
    )


# ---------------------------------------------------------------------------
# Combined entry point
# ---------------------------------------------------------------------------

def check_blocklist(ip: str) -> Verdict | None:
    """Run the IP through both blocklist sources. Returns the first hit."""
    ip = (ip or "").strip().lower()
    if not ip:
        return None
    hit = feodo_hit(ip)
    if hit:
        return hit
    return zen_hit(ip)


def get_status() -> dict:
    """Expose blocklist state for diagnostics / the dashboard."""
    return {
        "feodo_ips": len(_feodo_ips),
        "feodo_age_sec": int(time.time() - _feodo_ts) if _feodo_ts else None,
        "zen_cache": len(_zen_cache),
    }


def refresh_loop(interval_seconds=FEODO_TTL_SEC):
    """Background thread: refresh Feodo immediately, then hourly."""
    refresh_feodo()
    while True:
        time.sleep(interval_seconds)
        refresh_feodo()


if __name__ == "__main__":
    refresh_loop()
