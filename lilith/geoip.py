"""
IP geolocation enrichment.

Uses ip-api.com's free batch endpoint (no API key, 45 req/min limit,
up to 100 IPs per batch call) to resolve country/city/org for remote IPs
that don't have geo data yet. Run periodically (e.g. every 20-30s) as a
separate loop from the connection poller so a slow/rate-limited lookup
never blocks connection capture.
"""
import json
import time

import requests

from .capture import get_db

BATCH_ENDPOINT = "http://ip-api.com/batch"
BATCH_SIZE = 100
FIELDS = "status,message,country,countryCode,city,org,lat,lon,query"


def enrich_once():
    conn = get_db()
    cur = conn.cursor()

    cur.execute(
        """
        SELECT DISTINCT remote_ip FROM connections
        WHERE geo_lookup_done = 0
        LIMIT ?
        """,
        (BATCH_SIZE,),
    )
    ips = [r["remote_ip"] for r in cur.fetchall()]

    if not ips:
        conn.close()
        return 0

    payload = [{"query": ip, "fields": FIELDS} for ip in ips]

    try:
        resp = requests.post(BATCH_ENDPOINT, json=payload, timeout=10)
        resp.raise_for_status()
        results = resp.json()
    except (requests.RequestException, json.JSONDecodeError) as e:
        print(f"[geoip] lookup failed: {e}")
        conn.close()
        return 0

    for r in results:
        ip = r.get("query")
        if not ip:
            continue
        if r.get("status") == "success":
            country = r.get("country")
            country_code = r.get("countryCode")
            city = r.get("city")
            org = r.get("org")
            lat = r.get("lat")
            lon = r.get("lon")
        else:
            # Lookup failed for this IP (private range slipped through, rate limited, etc)
            country = country_code = city = org = lat = lon = None

        cur.execute(
            """
            UPDATE connections
            SET geo_country = ?, geo_country_code = ?, geo_city = ?, geo_org = ?, geo_lat = ?, geo_lon = ?, geo_lookup_done = 1
            WHERE remote_ip = ? AND geo_lookup_done = 0
            """,
            (country, country_code, city, org, lat, lon, ip),
        )

    conn.commit()
    conn.close()
    return len(ips)


def enrich_loop(interval_seconds=20):
    print(f"[geoip] polling every {interval_seconds}s ... Ctrl+C to stop")
    while True:
        try:
            n = enrich_once()
            if n:
                print(f"[geoip] resolved {n} IP(s)")
        except Exception as e:
            print(f"[geoip] error: {e}")
        time.sleep(interval_seconds)


if __name__ == "__main__":
    enrich_loop()
