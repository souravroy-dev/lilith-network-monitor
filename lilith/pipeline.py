"""
Pipeline orchestrator.

Runs connections through a rule-based analysis pipeline:
  1. Whitelist check
  2. Heuristic rules (stage2_heuristics.py)
  3. Threat-intel blocklists (blocklist.py — Feodo C2 IPs, Spamhaus ZEN)
  4. IP reputation (stage3_reputation.py)
  5. Behavioral analysis (behavior.py)
  6. DNS / DGA analysis (dns.py)
  7. Long-lived connection check (tunnels / reverse shells)

Each stage can return a verdict. The first stage with a verdict wins,
and later stages are skipped for that connection. Connections that pass
all stages are marked "clean" — there is no AI/LLM stage; this is a pure
rule + reputation + behavior monitor.

Designed to be called from triage.triage_loop().
"""

from __future__ import annotations

from datetime import datetime
from typing import NamedTuple

from .capture import get_db
from .stage2_heuristics import evaluate_one as h_evaluate
from .stage3_reputation import check_ip as r_check
from .behavior import evaluate_behavior as b_evaluate
from .blocklist import check_blocklist as bl_check
from .dns import evaluate_dns as dns_check


# ---------------------------------------------------------------------------
# Whitelist check
# ---------------------------------------------------------------------------

def _load_whitelist() -> tuple[set[str], set[str]]:
    """Return (whitelisted_ips, whitelisted_processes)."""
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT entry_type, entry_value FROM whitelist")
    ips: set[str] = set()
    procs: set[str] = set()
    for r in cur.fetchall():
        if r["entry_type"] == "ip":
            ips.add(r["entry_value"].strip().lower())
        elif r["entry_type"] == "proc":
            procs.add(r["entry_value"].strip().lower())
    conn.close()
    return ips, procs


def _is_whitelisted(c: dict, whitelisted_ips: set[str], whitelisted_procs: set[str]) -> bool:
    """Check if a connection's IP or process is whitelisted."""
    ip = (c.get("remote_ip") or "").strip().lower()
    if ip in whitelisted_ips:
        return True
    proc = (c.get("proc_name") or "").strip().lower()
    if proc in whitelisted_procs:
        return True
    return False


# ---------------------------------------------------------------------------
# Shared DB update helper
# ---------------------------------------------------------------------------

CLEAN_REASON = (
    "No suspicious signals detected — passed whitelist, heuristics, "
    "blocklist, reputation, behavior, DNS, and long-lived checks"
)


def _mark_clean(cur, cid: int):
    """Mark a connection that passed all rule-based stages as clean."""
    cur.execute(
        """
        UPDATE connections
        SET analyzed = 1, severity = NULL, reason = ?,
            verdict = 'clean', pipeline_stage = 'clean', pipeline_rule = NULL
        WHERE id = ?
        """,
        (CLEAN_REASON, cid),
    )


def _mark_verdict(cur, cid: int, severity: str | None, reason: str | None,
                  stage: str, rule: str | None):
    """Update a connection with a pipeline verdict."""
    if severity:
        cur.execute(
            """
            UPDATE connections
            SET analyzed = 1, severity = ?, reason = ?,
                verdict = 'reviewed', pipeline_stage = ?, pipeline_rule = ?
            WHERE id = ?
            """,
            (severity, reason, stage, rule, cid),
        )
    else:
        # Whitelist / no severity
        cur.execute(
            """
            UPDATE connections
            SET analyzed = 1, severity = NULL, reason = NULL,
                verdict = ?, pipeline_stage = ?, pipeline_rule = NULL
            WHERE id = ?
            """,
            (stage, stage, cid),
        )


# ---------------------------------------------------------------------------
# Long-lived connection check (tunnels / reverse shells)
# ---------------------------------------------------------------------------

class _Verdict(NamedTuple):
    severity: str
    reason: str
    rule_name: str


LONG_LIVED_MIN_HOURS = 4.0

# Ports where long-lived sessions are expected and boring.
_LONG_LIVED_EXCLUDED_PORTS = {
    21, 22, 25, 53, 80, 123, 443, 465, 587, 993, 995, 1194, 853, 8443, 8080,
}

# Processes known to hold long-lived connections (system services, sync
# clients, AV engines) — excluded so the rule stays precise.
_LONG_LIVED_EXCLUDED_PROCS = {
    "svchost.exe", "services.exe", "windowsupdate.exe", "musnotification.exe",
    "wuauclt.exe", "wuaucltcore.exe",
    "onedrive.exe", "googledrivesync.exe", "dropbox.exe", "bzbui.exe",
    "msmpeng.exe", "msmpengctl.exe", "mfemms.exe", "ekrn.exe", "csfalconservice.exe",
    "system", "system idle process", "searchapp.exe", "searchindexer.exe",
    "explorer.exe", "dwm.exe",
}


def _parse_iso(ts):
    """Best-effort ISO-8601 parse. Returns a datetime or None."""
    if not ts:
        return None
    try:
        return datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def _check_long_lived(c: dict) -> _Verdict | None:
    """
    Flag connections that have stayed ESTABLISHED for LONG_LIVED_MIN_HOURS
    or more on an unusual port — classic tunnel / reverse-shell / long-lived
    C2 behaviour (detection technique #5 from the roadmap).
    """
    if (c.get("status") or "").upper() != "ESTABLISHED":
        return None
    port = c.get("remote_port") or 0
    proc = (c.get("proc_name") or "").strip().lower()
    if port in _LONG_LIVED_EXCLUDED_PORTS or not proc or proc in _LONG_LIVED_EXCLUDED_PROCS:
        return None

    first = _parse_iso(c.get("first_seen"))
    last = _parse_iso(c.get("last_seen"))
    if not first or not last:
        return None

    # Defensive: mixed aware/naive timestamps would raise on subtraction.
    # One bad row must never stall the whole triage batch.
    try:
        hours = (last - first).total_seconds() / 3600.0
    except (TypeError, ValueError):
        return None

    if hours >= LONG_LIVED_MIN_HOURS:
        return _Verdict(
            severity="medium",
            reason=(
                f"{proc} kept a connection to {c.get('remote_ip')}:{port} "
                f"open for {hours:.1f}h — possible tunnel / reverse shell"
            ),
            rule_name="long_lived_tunnel",
        )
    return None


# ---------------------------------------------------------------------------
# Main pipeline entry point
# ---------------------------------------------------------------------------

def run_pipeline(max_batch: int = 15) -> int:
    """
    Fetch unanalyzed connections and run them through all pipeline stages.

    Returns the number of connections that received a verdict (from any stage).
    """
    whitelisted_ips, whitelisted_procs = _load_whitelist()

    conn = get_db()
    cur = conn.cursor()

    # Fetch connections that are geo-resolved but not yet analyzed
    cur.execute(
        """
        SELECT * FROM connections
        WHERE analyzed = 0 AND geo_lookup_done = 1
        ORDER BY first_seen ASC
        LIMIT ?
        """,
        (max_batch,),
    )
    rows = [dict(r) for r in cur.fetchall()]

    if not rows:
        conn.close()
        return 0

    processed = 0

    for c in rows:
        cid = c["id"]

        # --- Stage 1: Whitelist ---
        if _is_whitelisted(c, whitelisted_ips, whitelisted_procs):
            _mark_verdict(cur, cid, None, None, "whitelist", None)
            processed += 1
            continue

        # --- Stage 2: Heuristics ---
        verdict = h_evaluate(c)
        if verdict:
            _mark_verdict(cur, cid, verdict.severity, verdict.reason,
                          "heuristic", verdict.rule_name)
            processed += 1
            continue

        # --- Stage 3: Threat-intel blocklists (Feodo / Spamhaus ZEN) ---
        verdict = bl_check(c.get("remote_ip", ""))
        if verdict:
            _mark_verdict(cur, cid, verdict.severity, verdict.reason,
                          "blocklist", verdict.rule_name)
            processed += 1
            continue

        # --- Stage 4: IP Reputation ---
        verdict = r_check(c.get("remote_ip", ""))
        if verdict:
            _mark_verdict(cur, cid, verdict.severity, verdict.reason,
                          "reputation", verdict.rule_name)
            processed += 1
            continue

        # --- Stage 5: Behavioral Analysis ---
        verdict = b_evaluate(c)
        if verdict:
            _mark_verdict(cur, cid, verdict.severity, verdict.reason,
                          "behavior", verdict.rule_name)
            processed += 1
            continue

        # --- Stage 6: DNS / DGA analysis ---
        verdict = dns_check(c)
        if verdict:
            _mark_verdict(cur, cid, verdict.severity, verdict.reason,
                          "dns", verdict.rule_name)
            processed += 1
            continue

        # --- Stage 7: Long-lived connection (tunnel / reverse shell) ---
        verdict = _check_long_lived(c)
        if verdict:
            _mark_verdict(cur, cid, verdict.severity, verdict.reason,
                          "longlived", verdict.rule_name)
            processed += 1
            continue

        # --- No rule-based signals detected: mark clean ---
        # There is no LLM stage; connections that pass all checks are
        # recorded as "clean" so they are not reprocessed every cycle.
        _mark_clean(cur, cid)
        processed += 1

    conn.commit()
    conn.close()
    return processed
