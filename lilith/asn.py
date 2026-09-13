"""
IP → ASN + reverse-DNS enrichment.

ASN lookup uses Team Cymru's public IP-to-ASN mapping service
(https://www.team-cymru.com/ip-asn-mapping) — a free, key-less DNS TXT
lookup in two steps:

  1. IP → ASN:   <reversed-ip>.origin.asn.cymru.com
                 TXT "15169 | 8.8.8.0/24 | US | arin | 2023-12-28"
                 (ASN without the "AS" prefix, country, registry)
  2. ASN → org:  AS<asn>.asn.cymru.com
                 TXT "15169 | US | arin | 2000-03-30 | GOOGLE - Google LLC, US"
                 (org name is the last field)

The same loop also performs a best-effort reverse-DNS (PTR) lookup per IP
and stores the hostname in remote_hostname — this feeds the DNS/DGA
analysis stage (lilith/dns.py).

Design mirrors geoip.py: a separate background loop so a slow/failing
lookup never blocks connection capture. Results are cached in memory
(ASNs and hostnames are very stable), and every attempted IP is marked
asn_lookup_done / rdns_done so the loop never re-queries in a tight cycle.
"""

import time

import dns.reversename
import dns.resolver

from .capture import get_db

BATCH = 100
TIMEOUT = 3.0
INTERVAL = 20

_asn_cache: dict[str, tuple[str, str, str, str] | None] = {}   # ip -> (asn, org, country, registry)
_org_cache: dict[str, str | None] = {}                          # asn -> org
_rdns_cache: dict[str, str | None] = {}                         # ip -> hostname
_MAX_CACHE = 10000


# ---------------------------------------------------------------------------
# Lookups (cached, never raise)
# ---------------------------------------------------------------------------

def _lookup_asn(ip: str):
    """
    Resolve ASN info for an IP. Returns (asn, org, country, registry)
    or None when the IP has no ASN data / the lookup fails.
    """
    if ip in _asn_cache:
        return _asn_cache[ip]

    result = None
    try:
        name = ".".join(reversed(ip.split("."))) + ".origin.asn.cymru.com"
        answers = dns.resolver.resolve(name, "TXT", lifetime=TIMEOUT)
        for ans in answers:
            # TXT records can be split into 255-byte chunks; join them back.
            txt = "".join(s.decode(errors="replace") for s in ans.strings)
            parts = [p.strip() for p in txt.split("|")]
            # "15169 | 8.8.8.0/24 | US | arin | 2023-12-28"
            if len(parts) >= 5 and parts[0].lstrip("AS").isdigit():
                asn = parts[0].lstrip("AS")   # normalize to bare number
                country = parts[2]
                registry = parts[3]
                org = _lookup_asn_org(asn)
                result = (asn, org, country, registry)
                break
    except Exception:
        pass

    if len(_asn_cache) >= _MAX_CACHE:
        _asn_cache.clear()
    _asn_cache[ip] = result
    return result


def _lookup_asn_org(asn: str) -> str | None:
    """Resolve an ASN's organization name. Cached per ASN."""
    asn = asn.lstrip("AS")
    if asn in _org_cache:
        return _org_cache[asn]
    org = None
    try:
        answers = dns.resolver.resolve(f"AS{asn}.asn.cymru.com", "TXT", lifetime=TIMEOUT)
        for ans in answers:
            txt = "".join(s.decode(errors="replace") for s in ans.strings)
            parts = [p.strip() for p in txt.split("|")]
            # "15169 | US | arin | 2000-03-30 | GOOGLE - Google LLC, US"
            if len(parts) >= 5:
                org = parts[4]
                break
    except Exception:
        pass
    if len(_org_cache) >= _MAX_CACHE:
        _org_cache.clear()
    _org_cache[asn] = org
    return org


def _lookup_rdns(ip: str) -> str | None:
    """Best-effort reverse-DNS (PTR) lookup. Returns hostname or None."""
    if ip in _rdns_cache:
        return _rdns_cache[ip]
    host = None
    try:
        rev = dns.reversename.from_address(ip)
        answers = dns.resolver.resolve(rev, "PTR", lifetime=TIMEOUT)
        host = answers[0].to_text().rstrip(".")
    except Exception:
        pass
    if len(_rdns_cache) >= _MAX_CACHE:
        _rdns_cache.clear()
    _rdns_cache[ip] = host
    return host


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def enrich_once() -> int:
    """Resolve ASN (+ reverse-DNS) for a batch of unresolved IPs."""
    conn = get_db()
    cur = conn.cursor()

    cur.execute(
        "SELECT DISTINCT remote_ip FROM connections WHERE asn_lookup_done = 0 LIMIT ?",
        (BATCH,),
    )
    ips = [r["remote_ip"] for r in cur.fetchall()]

    if not ips:
        conn.close()
        return 0

    for ip in ips:
        asn = org = country = registry = None
        info = _lookup_asn(ip)
        if info:
            asn, org, country, registry = info
        hostname = _lookup_rdns(ip)

        cur.execute(
            """
            UPDATE connections
            SET remote_asn = ?, remote_as_org = ?, asn_lookup_done = 1,
                remote_hostname = ?, rdns_done = ?
            WHERE remote_ip = ? AND asn_lookup_done = 0
            """,
            (asn, org, hostname, 1 if hostname else 0, ip),
        )

    conn.commit()
    conn.close()
    return len(ips)


def enrich_loop(interval_seconds=INTERVAL):
    print(f"[asn] ASN + reverse-DNS enrichment every {interval_seconds}s ... Ctrl+C to stop")
    while True:
        try:
            n = enrich_once()
            if n:
                print(f"[asn] enriched {n} IP(s)")
        except Exception as e:
            print(f"[asn] error: {e}")
        time.sleep(interval_seconds)


if __name__ == "__main__":
    enrich_loop()
