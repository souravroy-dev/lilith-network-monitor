# 🗺️ Lilith — Improvement Roadmap & Session Handoff

> **Purpose of this file:** Persists the web research and the prioritized
> improvement plan so a future session can pick up exactly where we left off
> without re-reading the conversation or re-searching the web.

---

## 0. Current project state (as of last session)

- **Lilith** = passive, Windows-only outbound-connection security monitor.
  FastAPI + SQLite + single `dashboard.html`; background loops in
  `capture.py` (3s psutil poll), `geoip.py` (20s), `triage.py` (1s), `cleanup.py` (24h).
- **LLM stage completely removed.** Pure rules + reputation + behavior.
- **69 heuristic rules** in `stage2_heuristics.py` across 7 categories
  (was 34). Includes known-safe lists to suppress noise.
- **Pipeline = 4 stages + clean pass-through:** whitelist → heuristics →
  reputation (SANS DShield) → behavior (burst / country spread / IP spread).
  Pass-through connections are marked `clean` (verdict='clean').
- **DB columns renamed** via auto-migration in `capture.init_db()`:
  `llm_analyzed→analyzed`, `llm_verdict→verdict`, `llm_severity→severity`,
  `llm_reason→reason`. Stats key `pending_triage→pending_analysis`.
  Migration is idempotent and preserves data (verified on 18.6k rows).
- **Portability done:** `INSTRUCTIONS.md` (transfer/setup guide), launchers
  fall back to pip when uv missing, paths resolve from project root.
- **Tests:** the `tests/` directory was **removed by user request** (session
  cleanup) after a full validation pass. All suites passed before removal
  (direct stages, 28 new-stage checks, 20 7-stage threat checks, DB stress
  with zero "database is locked").
- **Not yet committed to git** (repo has no commits yet — `git status` shows
  all files untracked). Consider `git init` + first commit.

### ✅ Implemented since this roadmap was written (Tier 1 core + Tier 3 + Tier 2 partial)

- **ASN enrichment** (`lilith/asn.py`) — Team Cymru two-step DNS TXT lookup
  (`<ip>.origin.asn.cymru.com` → ASN, then `AS<asn>.asn.cymru.com` → org),
  plus reverse-DNS (PTR) per IP. New columns: `remote_asn`, `remote_as_org`,
  `remote_hostname`, `asn_lookup_done`, `rdns_done` (idempotent migration in
  `capture.init_db()`). Loop runs every 20s like geoip. Dashboard shows the
  ASN + org; CSV export includes ASN + hostname.
- **Hosting-provider ASN rule** (`stage2_heuristics.py`) —
  `unknown_proc_hosting_asn`: unknown process → hosting/cloud ASN on a
  non-443 port → MEDIUM (the roadmap's telemetry-vs-C2 disambiguator).
- **Long-lived connection rule** (`pipeline.py` `_check_long_lived`) —
  ESTABLISHED > 4h on an unusual port → MEDIUM (`long_lived_tunnel`),
  excludes 443/80/853/… and known system/sync/AV processes.
- **Threat-intel blocklists** (`lilith/blocklist.py`) — Feodo Tracker C2 IP
  list (hourly HTTP refresh, hit = HIGH) + Spamhaus ZEN DNS check (hit =
  MEDIUM/LOW by zone code). New `blocklist` pipeline stage.
- **DNS / DGA stage** (`lilith/dns.py`) — Shannon entropy (≥3.5) + consonant-
  heavy (vowel-ratio < 0.15) DGA detection on `remote_hostname`, plus DoH
  (known SNI on 443) and DoT (port 853). New `dns` pipeline stage. Works on
  PTR hostnames; full DNS-query capture (ETW DNS-Client) still future.
- **ETW kernel-network capture** (`lilith/etw_capture.py`) — real-time TCP
  connect/disconnect (Event 12/13) via `pywintrace` (imports as `etw`,
  optional extra: `uv sync --extra etw`). Verified GUID
  `{7DD42A49-5329-4832-8DFD-43D979153A88}` from the local system.
  Graceful fallback to psutil polling when not admin / package missing.
- **Pipeline is now 7 stages**: whitelist → heuristics → blocklist →
  reputation → behavior → dns → longlived → clean. DB switched to
  **WAL mode** + busy timeout to stop "database is locked" churn between the
  (now 5) writer loops.
- **New dep:** `dnspython` (runtime). **New optional extra:** `etw`
  (`pywintrace`). Test suites (incl. `test_new_stages.py`) were removed by
  user request during the cleanup pass.
- **Robustness fixes found during the full test pass:**
  - `whitelist` table creation moved into `capture.init_db()` — the schema is
    now self-contained, so triage/pipeline work standalone (previously only
    `app._init_whitelist()` created it).
  - Stdout/stderr forced to UTF-8 with lossy replacement at import — fixed a
    crash on Windows when a print() contained non-ASCII (e.g. the `→` in
    `cleanup.vacuum_db()`, which broke `POST /api/cleanup/vacuum` under
    redirected output).
  - Rule count is now **69** (was 68) across **7 categories** after the
    hosting-ASN rule; docs updated.
  - **Validation:** `test_malicious.py` (7-stage threat verification, 20
    checks) and `test_db_stress.py` (concurrent DB stress — zero "database
    is locked") were run green, then removed with the rest of `tests/` by
    user request.

---

## 1. The single biggest blind spot: the data source

`capture.py` polls `psutil.net_connections()` every 3s → it only sees sockets
**open at that instant**. A beacon that connects, sends, closes between polls
is invisible to *every* rule (heuristic, reputation, or behavior).

| Option | Sees short-lived conns? | Setup | Admin? |
|---|---|---|---|
| **ETW `Microsoft-Windows-Kernel-Network`** via Python `pywintrace` / `ETW` | ✅ real-time, every TCP connect + PID | **None** (built into Windows) | ✅ |
| Sysmon Event ID 3 (NetworkConnection) | ✅ | Install Sysmon + XML config | ✅ |
| Npcap packet capture (scapy / pyshark) | ✅ + full payloads (TLS etc.) | Install Npcap | ✅ |
| psutil polling (current) | ❌ misses them | — | — |

**Recommended:** ETW kernel-network tracing = highest leverage. Zero install,
real-time, PID included, admin already recommended for this tool. Enables
failed-attempt detection (SYN no complete) and churn detection.

---

## 2. Detection techniques worth adding (classic IDS, no ML)

From Snort / Suricata / Zeek / OSSEC / Wazuh research. All implementable in
`behavior.py` / `stage2_heuristics.py` / new modules:

| # | Technique | Signal | Where |
|---|---|---|---|
| 1 | **Beacon regularity score** (RITA) | Low-and-slow C2: periodic timestamps | `behavior.py` |
| 2 | **New-destination / first-contact** | First-ever external IP for a process | `behavior.py` (needs persistent history) |
| 3 | **Failed-attempt tracking** | Many SYN_SENT with no completion = recon/scan | `capture.py` (needs ETW status) |
| 4 | **Connection churn** | Rapid connect/disconnect cycles per process | `behavior.py` |
| 5 | **Long-lived connection age** | Same connection open >4h on odd port = tunnel/reverse shell | `capture.py` |
| 6 | **Host port-scan behavior** | One process hitting many distinct remote ports fast | `behavior.py` |
| 7 | **DNS query monitoring + DGA entropy** | Random-looking domains = DGA C2 | new `dns.py` stage |
| 8 | **DoH/DoT detection** | Port 853, or TLS SNI = `cloudflare-dns.com` / `dns.google` / `dns.quad9.net` | heuristic rule |

### 2.1 RITA beacon detection formula (crown jewel for C2)

Group connections by **(source IP → destination IP, port)**. Then:
1. Collect each connection's start timestamp.
2. Compute delta (inter-arrival) times between consecutive connections.
3. Bucket each delta (round to nearest second).
4. **Regularity score = (count of the most common interval) ÷ (N − 1)**
   where N = number of connections (N − 1 = number of deltas).
5. **Flag when score ≥ 0.7 AND mean connections/day ≥ 2.**
6. Optional extra signals: jitter (std dev of deltas), avg connection
   duration, avg bytes. Source: activecm/rita `pkg/beacon`.

This catches *exactly* what the current burst/country/IP-spread rules cannot:
a process phoning one IP every 5 minutes. **Telemetry disambiguation:** a
process beaconing to a known vendor ASN on 443 = probably telemetry; to a
hosting-provider or residential ASN on a non-443 port = high-confidence C2.

---

## 3. Threat-intel feeds (free / no-key-first)

| Feed | What it adds | Query method | Key? |
|---|---|---|---|
| **Team Cymru** `origin.asn.cymru.com` | IP → ASN + hosting org (**DNS TXT**) | `<reversed-ip>.origin.asn.cymru.com` TXT | ❌ none |
| **Spamhaus ZEN** | `2.0.0.127.zen.spamhaus.org`-style reversed-octet DNS | DNS, low-volume free (don't use public resolvers like 8.8.8.8) | ❌ none |
| **SANS DShield** | Already integrated (API); also has static `block.txt` feed (≤1 req/hour polite) | HTTP | ❌ none |
| **Feodo Tracker** (abuse.ch) | Botnet C2 IP blocklists (Dridex/Emotet/QakBot…) | HTTP static text files | ❌ none |
| **ThreatFox / URLhaus** (abuse.ch) | IOCs: IPs, domains, URLs, JA3 | HTTP API | 🔑 free key required |
| **AbuseIPDB** | Abuse confidence score + categories | HTTP v2 API | 🔑 free (1,000/day) |
| **AlienVault OTX** | Crowdsourced pulses/IOCs | HTTP REST | 🔑 free key (10k/hr) |

**Sleeper hit = Team Cymru ASN attribution** (zero-key DNS):
- Tells you *residential ISP vs. hosting provider vs. Microsoft/Google/
  Cloudflare* — enables rules like *"unknown process → hosting provider on a
  weird port"*.
- Best **telemetry-vs-C2 disambiguator**: allowlist known vendor ASNs on 443
  → expected (auto-low); anything else periodic → flag.
- Works **today** with the existing connection table (no new data source).

---

## 4. TLS/DNS fingerprinting (research summary)

- **JA3:** MD5 of ClientHello fields (TLS version, cipher suites, extensions,
  elliptic curves, point formats). **JA4** is the successor — sorts ciphers/
  extensions before hashing (resists reordering), includes SNI/ALPN flags.
- **Malicious JA3 database:** abuse.ch SSL Blacklist (SSLBL) — free.
- **Limitation:** CANNOT compute JA3 from a connection table — needs full
  packet capture (Npcap + admin) to see the ClientHello. Heavy; session
  resumption + browser JA3 randomization reduce value.
- **DGA detection formulas:**
  - Shannon entropy `H = −Σ p(i)·log₂ p(i)` per domain label; legit domains
    ≈ 2.0–3.0, DGA ≈ **≥3.5–4.0**.
  - Consonant-vowel ratio: DGA domains often have unnatural vowel absence
    (e.g. `xqjvplm.com`).
- **DoH/DoT:** DoT = port 853; DoH = 443 + known SNI (`cloudflare-dns.com`,
  `dns.google`, `dns.quad9.net`, NextDNS).

---

## 5. Prioritized implementation tiers

### 🔥 Tier 1 — "Now" (no new deps, works today)
1. ~~**Team Cymru ASN lookup**~~ ✅ **DONE** (`lilith/asn.py`, two-step DNS TXT;
   columns + dashboard + CSV; hosting-provider ASN rule added).
2. **Beacon regularity score** in `behavior.py` — RITA formula (§2.1).
   Needs connection timestamps per (proc, remote_ip) — already available
   in the in-memory rolling deque; raise window from 5 min to e.g. 1h and
   persist? (see §6 tradeoffs).
3. ~~**Long-lived connection rule**~~ ✅ **DONE** (`pipeline._check_long_lived`, 4h
   threshold, port + process exclusions).
4. **Connection churn rule** — count connect/disconnect cycles per proc.
   Now stronger thanks to ETW disconnect events (Event 13) — a natural
   next step.

### 💪 Tier 2 — "Strong" (fixes the data blind spot)
5. ~~**ETW kernel-network capture**~~ ✅ **DONE** (`lilith/etw_capture.py`,
   `uv sync --extra etw`, GUID verified from local system; graceful fallback
   to psutil). Note: on this dev machine ETW stays inactive (not admin) —
   test on an elevated session to exercise real-time capture.
6. **New-destination tracking** — persist "seen IPs per process" in SQLite
   (new table + cleanup), flag first-contact with new external IPs.
7. ~~**DNS stage + DGA detection**~~ ✅ **PARTIAL** (`lilith/dns.py`: Shannon
   entropy ≥3.5 + consonant-heavy + DoH/DoT on port 853 / known SNI).
   Works on PTR hostnames. **Still future:** real DNS-query capture via ETW
   `Microsoft-Windows-DNS-Client` (Event 3006/3008) for query-level DGA.

### ✨ Tier 3 — "Ambitious" (heaviest)
8. **JA3/JA4 + abuse.ch SSLBL** via Npcap (scapy/pyshark) — optional add-on,
   needs Npcap install + admin; correlate ClientHello fingerprints.
9. ~~**Spamhaus ZEN + Feodo static blocklist**~~ ✅ **DONE** (`lilith/blocklist.py`,
   Feodo hourly HTTP + ZEN DNS; `blocklist` pipeline stage). Note the Feodo
   list can be tiny at times (5 IPs seen) — it fluctuates.
10. **AbuseIPDB / ThreatFox** (free keys) — only if user registers keys.

---

## 6. Design notes / tradeoffs (decide before implementing)

- **Behavior state is in-memory and resets on restart** (5-min rolling
  window). Beacon detection needs longer history → either (a) persist
  per-(proc,ip) timestamp lists to SQLite, or (b) accept only
  session-long detection. Persistence is the "right" fix; adds a table +
  pruning.
- **Known-safe rules are LOW severity and run AFTER medium rules** — a
  medium rule (e.g. `no_exe_path`) will beat a known-safe low rule. This is
  by design; keep in mind when adding "expected = low" logic. Prefer
  **ASN-level allowlist** (Tier 1) over more process-name lists.
- **ETW requires admin**; the tool already recommends admin. Add graceful
  fallback to psutil polling when ETW can't start (like stage3 DShield
  degrades offline).
- **No LLM**: every flag is a human-review item. Favor precision over recall;
  use layered signals (beacon score + ASN + port) rather than single rules.
- **Threat-feed rate limits:** DShield ≤1/hr, Spamhaus low-volume DNS only,
  AbuseIPDB 1k/day. Cache aggressively (in-memory like `stage3`).

---## 7. Open decision (resolved)

> "Which improvements should I implement?" — user picked: **Tier 1 core
> (ASN + long-lived) + Tier 3 blocklists + Tier 2 DNS/DGA + Tier 2 ETW**.
> All implemented (see §0.1).

**Remaining candidates for the next session (in suggested order):**
1. **Beacon regularity score** (RITA) — the roadmap's crown-jewel C2
   detection; needs persistent per-(proc, IP) timestamps (new table).
2. **Connection churn rule** — now feasible with ETW disconnect events.
3. **New-destination / first-contact tracking** (Tier 2 #6).
4. **ETW DNS-Client query capture** — completes the DNS/DGA story.
5. **git init + first commit** — still no commits in the repo.

---

## 8. Reference links (from research)

- RITA beacon analyzer: https://github.com/activecm/rita (`pkg/beacon`)
- Team Cymru IP-to-ASN: https://www.team-cymru.com/ip-asn-mapping
- Spamhaus ZEN: https://www.spamhaus.org/zen/
- abuse.ch (ThreatFox / URLhaus / SSLBL / Feodo): https://abuse.ch
- DShield: https://isc.sans.edu
- AbuseIPDB: https://www.abuseipdb.com
- JA4: https://github.com/FoxIO-LLC/ja4
- Sysmon event IDs: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- ETW from Python: `pywintrace` / `ETW` packages (PyPI)
