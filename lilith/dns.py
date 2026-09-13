"""
DNS / DGA analysis stage (Tier 2).

Classic IDS heuristics, no ML:
  1. **DoH / DoT detection** — remote port 853 = DNS-over-TLS; port 443 with
     a known DoH resolver hostname (cloudflare-dns.com, dns.google, …).
  2. **DGA-style domains** — high Shannon entropy labels (≥3.5) typical of
     domain-generation-algorithm C2 domains, plus consonant-heavy labels
     (unnatural vowel absence, e.g. `xqjvplm`).

Where hostnames come from: reverse-DNS (PTR) hostnames captured during ASN
enrichment (lilith/asn.py) and stored in connections.remote_hostname. Full
DNS-query monitoring (ETW DNS-Client) is a future upgrade — the scoring
works on any hostname that lands in the connection row.

Shannon entropy per label: H = -Σ p(i)·log₂ p(i)
  legit labels ≈ 2.0–3.0 ; DGA labels ≈ ≥3.5–4.0
"""

import math
from typing import NamedTuple


# ---------------------------------------------------------------------------
# Verdict type (same shape as the other stages)
# ---------------------------------------------------------------------------

class Verdict(NamedTuple):
    severity: str
    reason: str
    rule_name: str


# ---------------------------------------------------------------------------
# Tuning
# ---------------------------------------------------------------------------

DGA_ENTROPY_THRESHOLD = 3.5   # per-label Shannon entropy
DGA_MIN_ENTROPY_LEN = 10      # only judge labels at least this long
DGA_MIN_CONSONANT_LEN = 8     # consonant-heavy labels at least this long
DGA_MAX_VOWEL_RATIO = 0.15    # below this → suspiciously vowel-free

DOH_SNIS = {
    "cloudflare-dns.com", "dns.google", "dns.quad9.net",
    "doh.opendns.com", "dns.nextdns.io", "nextdns.io",
}


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

def shannon_entropy(s: str) -> float:
    """Shannon entropy H = -Σ p(i)·log₂ p(i) over the string's characters."""
    if not s:
        return 0.0
    s = s.lower()
    n = len(s)
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def vowel_ratio(s: str) -> float:
    """Fraction of characters that are vowels (a/e/i/o/u)."""
    if not s:
        return 0.0
    return sum(1 for ch in s.lower() if ch in "aeiou") / len(s)


def _labels(hostname: str) -> list[str]:
    """Hostname labels that start with a letter (skips pure-numeric parts)."""
    return [
        part for part in hostname.lower().split(".")
        if part and part[0].isalpha()
    ]


def score_hostname(hostname: str) -> dict:
    """
    Score a hostname for DGA-style randomness.

    Returns {"max_entropy": float, "best_label": str|None,
             "consonant_label": str|None, "suspicious": bool}
    """
    labels = _labels(hostname)
    if not labels:
        return {
            "max_entropy": 0.0,
            "best_label": None,
            "consonant_label": None,
            "suspicious": False,
        }

    best_label = max(labels, key=shannon_entropy)
    max_entropy = shannon_entropy(best_label)

    consonant_label = None
    for label in labels:
        if len(label) >= DGA_MIN_CONSONANT_LEN and vowel_ratio(label) < DGA_MAX_VOWEL_RATIO:
            consonant_label = label
            break

    entropy_flag = (
        len(best_label) >= DGA_MIN_ENTROPY_LEN and max_entropy >= DGA_ENTROPY_THRESHOLD
    )
    suspicious = entropy_flag or consonant_label is not None

    return {
        "max_entropy": round(max_entropy, 2),
        "best_label": best_label,
        "consonant_label": consonant_label,
        "suspicious": suspicious,
    }


# ---------------------------------------------------------------------------
# Stage entry point
# ---------------------------------------------------------------------------

def evaluate_dns(c: dict) -> Verdict | None:
    """
    Run DNS-related heuristics against one connection dict.

    Needs at minimum proc_name and remote_port; uses remote_hostname
    (reverse-DNS) when present.
    """
    proc = (c.get("proc_name") or "?").strip()
    port = c.get("remote_port") or 0

    # --- DoT: DNS-over-TLS on 853 ---
    if port == 853:
        return Verdict(
            severity="medium",
            reason=f"{proc} connecting to DNS-over-TLS port 853 — encrypted DNS tunnelling / C2",
            rule_name="dot_853",
        )

    hostname = (c.get("remote_hostname") or "").strip().lower()
    if not hostname:
        return None

    # --- DoH: known DoH resolver SNI on 443 ---
    if port == 443:
        base = ".".join(hostname.split(".")[-2:])
        if base in DOH_SNIS or hostname in DOH_SNIS:
            return Verdict(
                severity="low",
                reason=f"{proc} using DoH resolver {hostname} — encrypted DNS",
                rule_name="doh_sni",
            )

    # --- DGA-style randomness on the hostname labels ---
    score = score_hostname(hostname)
    if score["consonant_label"]:
        return Verdict(
            severity="medium",
            reason=(
                f"{proc} connected to consonant-heavy hostname {hostname} "
                f"(label '{score['consonant_label']}') — possible DGA C2"
            ),
            rule_name="dga_consonants",
        )
    if score["suspicious"]:
        return Verdict(
            severity="medium",
            reason=(
                f"{proc} connected to high-entropy hostname {hostname} "
                f"(label '{score['best_label']}' entropy {score['max_entropy']:.2f}) — possible DGA C2"
            ),
            rule_name="dga_entropy",
        )

    return None
