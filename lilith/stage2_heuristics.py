"""
Stage 2: Heuristic rule engine.

Hard-coded rules that map process + port + country + exe_path combinations
to severity verdicts. No external dependencies, no API calls, no DB access.

Each rule is a dict with:
  - name:       short identifier (for pipeline_rule tracking)
  - category:   human-readable group
  - severity:   "low" | "medium" | "high"
  - reason:     template string explaining the finding
  - match:      callable(connection_dict) -> bool

Design:
  - Pure functions — zero side effects. Takes a connection dict, returns a
    Verdict namedtuple or None.
  - Easy to add/remove rules without touching anything else.
  - Rules are ordered by severity (high first) so the most critical signal
    wins when multiple rules match.
"""

from typing import NamedTuple


# ---------------------------------------------------------------------------
# Verdict type
# ---------------------------------------------------------------------------

class Verdict(NamedTuple):
    """Returned by the heuristics engine when a rule fires."""
    severity: str        # "low" | "medium" | "high"
    reason: str          # human-readable explanation
    rule_name: str       # which rule fired (stored in pipeline_rule)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _proc(c: dict) -> str:
    return (c.get("proc_name") or "").lower()


def _exe(c: dict) -> str:
    return (c.get("proc_exe") or "").lower()


def _port(c: dict, default: int = 0) -> int:
    return c.get("remote_port") or default


def _country(c: dict) -> str:
    return (c.get("geo_country") or "").lower()


def _org(c: dict) -> str:
    return (c.get("geo_org") or "").lower()


def _asn_org(c: dict) -> str:
    return (c.get("remote_as_org") or "").lower()


# ---------------------------------------------------------------------------
# Suspicious port sets
# ---------------------------------------------------------------------------

_METASPLOIT_PORTS = {4444, 5555, 1337, 6666, 6667, 6668, 6669, 7777, 8888, 9999}
_REVERSE_SHELL_PORTS = {4444, 5555, 6666, 7777, 8888, 9001, 31337, 443, 80}
_UNUSUAL_HIGH_PORTS = set(range(1024, 49152)) - {
    3306, 5432, 6379, 8080, 8443, 9090, 9200, 27017,
    1433, 1521, 2049, 2375, 2376,
}
_ATTACK_PORTS = {445, 139, 3389, 22, 23, 21, 5900, 5901}

# ---------------------------------------------------------------------------
# Hosting / cloud / VPS org keywords (from Team Cymru ASN enrichment)
# ---------------------------------------------------------------------------

# Matched as a substring of the AS organization name. Used to disambiguate
# "unknown process phoning a hosting provider on a weird port" — the
# classic C2 hosting pattern (vs. vendor telemetry on 443, which the
# known-safe rules already downgrade).
HOSTING_ASN_KEYWORDS = (
    "amazon", "aws", "azure", "microsoft", "google", "alphabet",
    "ovh", "hetzner", "digitalocean", "vultr", "linode", "scaleway",
    "contabo", "hostinger", "namecheap", "godaddy", "alibaba", "aliyun",
    "tencent", "huawei", "gcore", "leaseweb", "cloudflare", "akamai",
    "fastly", "datacamp", "choopa", "quadranet", "psychz", "colocrossing",
    "interserver", "hostwinds", "ionos", "strato", "hosting",
    "datacenter", "data center", "colo", "vps", "server hosting",
)


# Ports node.exe legitimately talks to on a developer machine (web servers,
# dev servers, local databases, package registries). Anything else is
# unusual enough to warrant a flag.
_NODE_COMMON_PORTS = {
    80, 443, 3000, 4200, 5000, 5173, 5432, 6379, 8000, 8080, 8443,
    8888, 9000, 9090, 9443, 3306, 27017,
}

# Processes that are almost certainly legitimate even when their exe path is
# unreadable (protected processes return AccessDenied). Excluded from the
# no_exe_path rule so known-good apps aren't flagged when permissions hide
# their path.
_KNOWN_SAFE_PROCS = frozenset({
    # browsers
    "chrome.exe", "firefox.exe", "msedge.exe", "opera.exe", "brave.exe", "safari.exe",
    "vivaldi.exe", "arc.exe", "librewolf.exe", "chromium.exe", "waterfox.exe", "iridium.exe",
    # cloud clients
    "onedrive.exe", "googledrivesync.exe", "dropbox.exe", "icloud.exe",
    "bzbui.exe", "megasync.exe", "boxsync.exe", "nextcloud.exe", "pcloud.exe", "syncthing.exe",
    # communication apps
    "discord.exe", "slack.exe", "teams.exe", "zoom.exe", "spotify.exe",
    "telegram.exe", "whatsapp.exe", "signal.exe", "skype.exe", "wechat.exe", "wechatapp.exe",
    "line.exe", "viber.exe", "kakaotalk.exe",
    # game launchers
    "steam.exe", "epicgameslauncher.exe", "battle.net.exe", "xboxapp.exe",
    "riotclient.exe", "valorant.exe", "eadesktop.exe", "eaapp.exe", "galaxyclient.exe",
    "ubisoftconnect.exe", "epicwebhelper.exe",
    # windows system services
    "svchost.exe", "windowsupdate.exe", "musnotification.exe", "wuauclt.exe", "wuaucltcore.exe",
    # antivirus / security
    "msmpeng.exe", "msmpengctl.exe", "mpcmdrun.exe", "mfemms.exe", "avp.exe",
    "avastsvc.exe", "avgnt.exe", "mbam.exe", "mbamtray.exe", "ekrn.exe", "csfalconservice.exe",
    # media / streaming
    "vlc.exe", "plex.exe", "plex media server.exe", "kodi.exe", "tidal.exe",
    "foobar2000.exe", "netflix.exe",
    # creative cloud
    "adobeccxprocess.exe", "adobeupdateservice.exe", "core sync.exe", "photoshop.exe",
    "illustrator.exe", "indesign.exe", "adobe premiere pro.exe",
    # vpn clients
    "openvpn.exe", "openvpntray.exe", "wireguard.exe", "nordvpn.exe", "expressvpn.exe",
    "protonvpn.exe", "surfshark.exe", "mullvad.exe",
    # gpu / peripheral software
    "nvcontainer.exe", "nvdisplay.container.exe", "nvidia web helper.exe",
    "razercentral.exe", "lghub.exe", "icue.exe", "armservice.exe",
})


# ---------------------------------------------------------------------------
# Rule definitions
# ---------------------------------------------------------------------------

RULES: list[dict] = [
    # =========================================================================
    # Category 1: Script Interpreter Abuse  (MITRE T1059)
    # =========================================================================
    {
        "name": "python_smb",
        "category": "Script interpreter abuse",
        "severity": "high",
        "reason": "{proc} connecting to SMB port {port} — possible lateral movement / ransomware",
        "match": lambda c: _proc(c) in ("python.exe", "python3.exe") and _port(c) == 445,
    },
    {
        "name": "script_metasploit_port",
        "category": "Script interpreter abuse",
        "severity": "high",
        "reason": "{proc} on known C2 port {port} — possible reverse shell",
        "match": lambda c: _proc(c) in ("python.exe", "python3.exe", "powershell.exe", "pwsh.exe", "cmd.exe")
        and _port(c) in _METASPLOIT_PORTS,
    },
    {
        "name": "powershell_nonstandard",
        "category": "Script interpreter abuse",
        "severity": "high",
        "reason": "PowerShell making outbound connection on port {port} — possible C2 beacon",
        "match": lambda c: _proc(c) in ("powershell.exe", "pwsh.exe") and _port(c) not in (80, 443),
    },
    {
        "name": "cmd_exe_outbound",
        "category": "Script interpreter abuse",
        "severity": "high",
        "reason": "cmd.exe making outbound connection — possible reverse shell",
        "match": lambda c: _proc(c) == "cmd.exe" and _port(c) > 0,
    },
    {
        "name": "wscript_cscript",
        "category": "Script interpreter abuse",
        "severity": "high",
        "reason": "{proc} making outbound connection — LOLBin abuse",
        "match": lambda c: _proc(c) in ("wscript.exe", "cscript.exe") and _port(c) > 0,
    },
    {
        "name": "mshta_outbound",
        "category": "Script interpreter abuse",
        "severity": "high",
        "reason": "MSHTA making outbound connection — HTA-based C2",
        "match": lambda c: _proc(c) == "mshta.exe" and _port(c) > 0,
    },
    {
        "name": "rundll32_outbound",
        "category": "Script interpreter abuse",
        "severity": "high",
        "reason": "rundll32.exe making outbound connection — C2 beaconing",
        "match": lambda c: _proc(c) == "rundll32.exe" and _port(c) > 0,
    },
    {
        "name": "regsvr32_outbound",
        "category": "Script interpreter abuse",
        "severity": "medium",
        "reason": "regsvr32.exe making outbound connection — Squiblydoo technique",
        "match": lambda c: _proc(c) == "regsvr32.exe" and _port(c) > 0,
    },
    {
        "name": "certutil_outbound",
        "category": "Script interpreter abuse",
        "severity": "medium",
        "reason": "certutil.exe making outbound connection — download cradle",
        "match": lambda c: _proc(c) == "certutil.exe" and _port(c) > 0,
    },
    {
        "name": "bitsadmin_outbound",
        "category": "Script interpreter abuse",
        "severity": "medium",
        "reason": "bitsadmin.exe making outbound connection — BITS job C2",
        "match": lambda c: _proc(c) == "bitsadmin.exe" and _port(c) > 0,
    },
    {
        "name": "msiexec_outbound",
        "category": "Script interpreter abuse",
        "severity": "medium",
        "reason": "msiexec.exe making outbound connection — possible MSI payload fetch (T1218.007)",
        "match": lambda c: _proc(c) == "msiexec.exe" and _port(c) > 0,
    },
    {
        "name": "cmstp_outbound",
        "category": "Script interpreter abuse",
        "severity": "high",
        "reason": "cmstp.exe making outbound connection — rare COM scriptlet execution (T1218.003)",
        "match": lambda c: _proc(c) == "cmstp.exe" and _port(c) > 0,
    },
    {
        "name": "installutil_outbound",
        "category": "Script interpreter abuse",
        "severity": "medium",
        "reason": "{proc} making outbound connection — .NET installer abuse (T1218.004/.009)",
        "match": lambda c: _proc(c) in ("installutil.exe", "regasm.exe", "regsvcs.exe") and _port(c) > 0,
    },
    {
        "name": "wmic_outbound",
        "category": "Script interpreter abuse",
        "severity": "medium",
        "reason": "wmic.exe making outbound connection — WMI remote execution (T1047)",
        "match": lambda c: _proc(c) == "wmic.exe" and _port(c) > 0,
    },
    {
        "name": "schtasks_outbound",
        "category": "Script interpreter abuse",
        "severity": "medium",
        "reason": "{proc} making outbound connection — possible scheduled-task / service C2",
        "match": lambda c: _proc(c) in ("schtasks.exe", "sc.exe") and _port(c) > 0,
    },
    {
        "name": "curl_download_cradle",
        "category": "Script interpreter abuse",
        "severity": "medium",
        "reason": "{proc} connecting on non-standard port {port} — possible download cradle / data transfer (T1105)",
        "match": lambda c: _proc(c) in ("curl.exe", "wget.exe", "aria2c.exe", "ncat.exe")
        and _port(c) not in (80, 443),
    },
    {
        "name": "node_runtime_outbound",
        "category": "Script interpreter abuse",
        "severity": "medium",
        "reason": "{proc} connecting on unusual port {port} — possible scripted beacon",
        "match": lambda c: _proc(c) in ("node.exe", "nodejs.exe", "deno.exe", "bun.exe")
        and _port(c) not in _NODE_COMMON_PORTS,
    },
    {
        "name": "other_script_runtime",
        "category": "Script interpreter abuse",
        "severity": "medium",
        "reason": "{proc} making outbound connection — unusual script runtime on Windows",
        "match": lambda c: _proc(c) in ("perl.exe", "ruby.exe", "php.exe", "lua.exe", "tclsh.exe", "groovy.exe")
        and _port(c) > 0,
    },

    # =========================================================================
    # Category 2: System Process Anomalies  (MITRE T1036 — Masquerading)
    # =========================================================================
    {
        "name": "system_binary_wrong_path",
        "category": "System process anomaly",
        "severity": "high",
        "reason": "{proc} running from {exe} instead of System32 — masquerading malware",
        "match": lambda c: _proc(c) in (
            "lsass.exe", "services.exe", "winlogon.exe", "wininit.exe",
            "csrss.exe", "smss.exe", "spoolsv.exe", "taskhostw.exe",
            "dllhost.exe", "conhost.exe", "svchost.exe",
        )
        and _exe(c) and "system32" not in _exe(c) and "syswow64" not in _exe(c),
    },
    {
        "name": "lsass_outbound",
        "category": "System process anomaly",
        "severity": "high",
        "reason": "lsass.exe making outbound connection — possible credential theft / exfil",
        "match": lambda c: _proc(c) == "lsass.exe" and _port(c) > 0,
    },
    {
        "name": "services_outbound",
        "category": "System process anomaly",
        "severity": "high",
        "reason": "services.exe making outbound connection — possible service tampering",
        "match": lambda c: _proc(c) == "services.exe" and _port(c) > 0,
    },
    {
        "name": "winlogon_outbound",
        "category": "System process anomaly",
        "severity": "high",
        "reason": "winlogon.exe making outbound connection — possible credential theft",
        "match": lambda c: _proc(c) == "winlogon.exe" and _port(c) > 0,
    },
    {
        "name": "spoolsv_outbound",
        "category": "System process anomaly",
        "severity": "high",
        "reason": "spoolsv.exe making outbound connection — possible PrintNightmare / RCE",
        "match": lambda c: _proc(c) == "spoolsv.exe" and _port(c) > 0,
    },
    {
        "name": "svchost_suspicious_port",
        "category": "System process anomaly",
        "severity": "medium",
        "reason": "svchost.exe on unexpected port {port} — possible host process anomaly",
        "match": lambda c: _proc(c) == "svchost.exe" and _port(c) not in (53, 80, 123, 443),
    },
    {
        "name": "csrss_outbound",
        "category": "System process anomaly",
        "severity": "high",
        "reason": "csrss.exe making outbound connection — highly unusual, possible injection",
        "match": lambda c: _proc(c) == "csrss.exe" and _port(c) > 0,
    },
    {
        "name": "smss_outbound",
        "category": "System process anomaly",
        "severity": "high",
        "reason": "smss.exe making outbound connection — highly unusual, possible injection",
        "match": lambda c: _proc(c) == "smss.exe" and _port(c) > 0,
    },
    {
        "name": "wininit_outbound",
        "category": "System process anomaly",
        "severity": "high",
        "reason": "wininit.exe making outbound connection — possible privilege escalation / tampering",
        "match": lambda c: _proc(c) == "wininit.exe" and _port(c) > 0,
    },
    {
        "name": "conhost_outbound",
        "category": "System process anomaly",
        "severity": "medium",
        "reason": "conhost.exe making outbound connection — possible hollowed console host",
        "match": lambda c: _proc(c) == "conhost.exe" and _port(c) > 0,
    },
    {
        "name": "taskhostw_outbound",
        "category": "System process anomaly",
        "severity": "medium",
        "reason": "{proc} making outbound connection — possible task host abuse",
        "match": lambda c: _proc(c) in ("taskhostw.exe", "taskhost.exe", "taskhostex.exe") and _port(c) > 0,
    },
    {
        "name": "dllhost_outbound",
        "category": "System process anomaly",
        "severity": "medium",
        "reason": "dllhost.exe making outbound connection — COM surrogate abuse",
        "match": lambda c: _proc(c) == "dllhost.exe" and _port(c) > 0,
    },

    # =========================================================================
    # Category 3: Office Product Network Activity  (MITRE T1204)
    # =========================================================================
    {
        "name": "winword_outbound",
        "category": "Office product network activity",
        "severity": "high",
        "reason": "WinWord making outbound connection — possible macro-based C2",
        "match": lambda c: _proc(c) in ("winword.exe", "word.exe") and _port(c) > 0,
    },
    {
        "name": "excel_outbound",
        "category": "Office product network activity",
        "severity": "high",
        "reason": "Excel making outbound connection — possible macro-based C2",
        "match": lambda c: _proc(c) in ("excel.exe", "excel") and _port(c) > 0,
    },
    {
        "name": "powerpnt_outbound",
        "category": "Office product network activity",
        "severity": "high",
        "reason": "PowerPoint making outbound connection — possible macro-based C2",
        "match": lambda c: _proc(c) in ("powerpnt.exe", "powerpoint.exe") and _port(c) > 0,
    },
    {
        "name": "msaccess_outbound",
        "category": "Office product network activity",
        "severity": "medium",
        "reason": "Microsoft Access making outbound connection — possible macro / linked-data exfil",
        "match": lambda c: _proc(c) in ("msaccess.exe", "access.exe") and _port(c) > 0,
    },
    {
        "name": "visio_outbound",
        "category": "Office product network activity",
        "severity": "medium",
        "reason": "Visio making outbound connection — possible embedded-object C2",
        "match": lambda c: _proc(c) in ("visio.exe", "visio32.exe") and _port(c) > 0,
    },

    # =========================================================================
    # Category 4: Port / Protocol Mismatches
    # =========================================================================
    {
        "name": "browser_on_service_port",
        "category": "Port/protocol mismatch",
        "severity": "medium",
        "reason": "{proc} connecting on service port {port} — possible tunneling",
        "match": lambda c: _proc(c) in (
            "chrome.exe", "firefox.exe", "msedge.exe", "opera.exe", "brave.exe"
        ) and _port(c) in {22, 23, 3389, 5900, 5901},
    },
    {
        "name": "rdp_outbound",
        "category": "Port/protocol mismatch",
        "severity": "medium",
        "reason": "{proc} connecting to RDP port 3389 — possible lateral movement",
        "match": lambda c: _port(c) == 3389,
    },
    {
        "name": "ssh_outbound",
        "category": "Port/protocol mismatch",
        "severity": "medium",
        "reason": "{proc} connecting to SSH port 22 — possible tunneling / C2",
        "match": lambda c: _port(c) == 22,
    },
    {
        "name": "admin_tool_exfil",
        "category": "Port/protocol mismatch",
        "severity": "medium",
        "reason": "{proc} making network connection — possible data staging for exfil",
        "match": lambda c: _proc(c) in ("xcopy.exe", "robocopy.exe", "whoami.exe",
        "net.exe", "net1.exe", "ipconfig.exe", "nslookup.exe") and _port(c) > 0,
    },
    {
        "name": "telnet_outbound",
        "category": "Port/protocol mismatch",
        "severity": "medium",
        "reason": "{proc} connecting to Telnet port 23 — cleartext remote admin / legacy C2",
        "match": lambda c: _port(c) == 23,
    },
    {
        "name": "ftp_outbound",
        "category": "Port/protocol mismatch",
        "severity": "low",
        "reason": "{proc} connecting to FTP port 21 — cleartext file transfer",
        "match": lambda c: _port(c) == 21,
    },
    {
        "name": "smb_internet_outbound",
        "category": "Port/protocol mismatch",
        "severity": "medium",
        "reason": "{proc} connecting to SMB port 445 — internet SMB is almost always malicious",
        "match": lambda c: _port(c) == 445 and _proc(c) not in ("svchost.exe",),
    },
    {
        "name": "database_outbound",
        "category": "Port/protocol mismatch",
        "severity": "medium",
        "reason": "{proc} connecting to database port {port} — unusual for a home PC",
        "match": lambda c: _port(c) in (1433, 1521, 3306, 5432, 6379, 9200, 27017),
    },
    {
        "name": "mail_cleartext_outbound",
        "category": "Port/protocol mismatch",
        "severity": "low",
        "reason": "{proc} connecting to cleartext mail port {port} — credentials sent unencrypted",
        "match": lambda c: _port(c) in (110, 143),
    },
    {
        "name": "tor_outbound",
        "category": "Port/protocol mismatch",
        "severity": "medium",
        "reason": "{proc} connecting to Tor proxy port {port} — possible anonymized C2",
        "match": lambda c: _port(c) in (9050, 9051, 9150),
    },
    {
        "name": "irc_c2_port",
        "category": "Port/protocol mismatch",
        "severity": "medium",
        "reason": "{proc} connecting to IRC port {port} — possible IRC C2 channel",
        "match": lambda c: _port(c) in (6666, 6667, 6668, 6669),
    },

    # =========================================================================
    # Category 5: Injected / Unsigned / Masquerading  (MITRE T1055)
    # =========================================================================
    {
        "name": "notepad_outbound",
        "category": "Injected / masquerading process",
        "severity": "high",
        "reason": "notepad.exe making outbound connection — possible process hollowing",
        "match": lambda c: _proc(c) == "notepad.exe" and _port(c) > 0,
    },
    {
        "name": "calc_outbound",
        "category": "Injected / masquerading process",
        "severity": "high",
        "reason": "calc.exe making outbound connection — possible process injection",
        "match": lambda c: _proc(c) == "calc.exe" and _port(c) > 0,
    },
    {
        "name": "explorer_outbound_suspicious",
        "category": "Injected / masquerading process",
        "severity": "medium",
        "reason": "explorer.exe making outbound connection — possible parent process abuse",
        "match": lambda c: _proc(c) == "explorer.exe" and _port(c) in _ATTACK_PORTS,
    },
    {
        "name": "no_exe_path",
        "category": "Injected / masquerading process",
        "severity": "medium",
        "reason": "{proc} has no executable path — possible injected / reflective DLL",
        "match": lambda c: not _exe(c) and _port(c) > 0
        and _proc(c) not in ("system", "system idle process", "")
        and _proc(c) not in _KNOWN_SAFE_PROCS,
    },
    {
        "name": "runs_from_temp",
        "category": "Injected / masquerading process",
        "severity": "medium",
        "reason": "{proc} running from temp directory — possible dropped malware",
        "match": lambda c: _exe(c) and (
            "\\temp\\" in _exe(c) or "\\tmp\\" in _exe(c)
            or "\\appdata\\local\\temp" in _exe(c)
        ) and _port(c) > 0,
    },
    {
        "name": "short_name_from_temp",
        "category": "Injected / masquerading process",
        "severity": "medium",
        "reason": "{proc} with a short name running from temp/appdata — possible dropped payload",
        "match": lambda c: _exe(c) and len(_proc(c).rsplit(".", 1)[0]) <= 3
        and ("\\temp\\" in _exe(c) or "\\tmp\\" in _exe(c) or "\\appdata\\" in _exe(c))
        and _port(c) > 0,
    },
    {
        "name": "explorer_nonstandard_port",
        "category": "Injected / masquerading process",
        "severity": "medium",
        "reason": "explorer.exe on non-standard port {port} — possible parent-process abuse",
        "match": lambda c: _proc(c) == "explorer.exe" and _port(c) not in (80, 443),
    },

    # =========================================================================
    # Category 6: Known-safe process patterns → LOW (skip further analysis)
    # =========================================================================
    {
        "name": "known_browser_safe",
        "category": "Known safe",
        "severity": "low",
        "reason": "{proc} on standard port {port} — normal browser traffic",
        "match": lambda c: _proc(c) in (
            "chrome.exe", "firefox.exe", "msedge.exe", "opera.exe", "brave.exe", "safari.exe"
        ) and _port(c) in (80, 443),
    },
    {
        "name": "known_cloud_client",
        "category": "Known safe",
        "severity": "low",
        "reason": "Cloud sync client {proc} on standard port — expected behavior",
        "match": lambda c: _proc(c) in (
            "onedrive.exe", "googledrivesync.exe", "dropbox.exe", "icloud.exe"
        ) and _port(c) in (80, 443),
    },
    {
        "name": "known_comm_app",
        "category": "Known safe",
        "severity": "low",
        "reason": "{proc} on standard port {port} — expected communication app",
        "match": lambda c: _proc(c) in (
            "discord.exe", "slack.exe", "teams.exe", "zoom.exe", "spotify.exe"
        ) and _port(c) in (80, 443),
    },
    {
        "name": "known_game_launcher",
        "category": "Known safe",
        "severity": "low",
        "reason": "{proc} on standard port — expected game launcher traffic",
        "match": lambda c: _proc(c) in (
            "steam.exe", "epicgameslauncher.exe", "battle.net.exe", "xboxapp.exe"
        ) and _port(c) in (80, 443),
    },
    {
        "name": "windows_update",
        "category": "Known safe",
        "severity": "low",
        "reason": "Windows update service on standard port — expected",
        "match": lambda c: _proc(c) in (
            "windowsupdate.exe", "musnotification.exe", "wuauclt.exe", "wuaucltcore.exe"
        ) and _port(c) in (80, 443),
    },
    {
        "name": "svchost_dns_ntp",
        "category": "Known safe",
        "severity": "low",
        "reason": "svchost.exe on DNS/NTP — expected system traffic",
        "match": lambda c: _proc(c) == "svchost.exe" and _port(c) in (53, 123),
    },
    {
        "name": "known_antivirus",
        "category": "Known safe",
        "severity": "low",
        "reason": "{proc} on standard port — expected antivirus / security product traffic",
        "match": lambda c: _proc(c) in (
            "msmpeng.exe", "msmpengctl.exe", "mpcmdrun.exe", "mfemms.exe",
            "avp.exe", "avastsvc.exe", "avgnt.exe", "mbam.exe", "mbamtray.exe",
            "ekrn.exe", "csfalconservice.exe",
        ) and _port(c) in (80, 443),
    },
    {
        "name": "known_messenger",
        "category": "Known safe",
        "severity": "low",
        "reason": "{proc} on standard port — expected messaging app traffic",
        "match": lambda c: _proc(c) in (
            "telegram.exe", "whatsapp.exe", "signal.exe", "skype.exe",
            "wechat.exe", "wechatapp.exe", "line.exe", "viber.exe", "kakaotalk.exe",
        ) and _port(c) in (80, 443),
    },
    {
        "name": "known_cloud_more",
        "category": "Known safe",
        "severity": "low",
        "reason": "Cloud sync client {proc} on standard port — expected behavior",
        "match": lambda c: _proc(c) in (
            "bzbui.exe", "megasync.exe", "boxsync.exe", "nextcloud.exe",
            "pcloud.exe", "syncthing.exe",
        ) and _port(c) in (80, 443),
    },
    {
        "name": "known_game_launcher_more",
        "category": "Known safe",
        "severity": "low",
        "reason": "{proc} on standard port — expected game launcher traffic",
        "match": lambda c: _proc(c) in (
            "riotclient.exe", "valorant.exe", "eadesktop.exe", "eaapp.exe",
            "galaxyclient.exe", "ubisoftconnect.exe", "epicwebhelper.exe",
        ) and _port(c) in (80, 443),
    },
    {
        "name": "known_browser_more",
        "category": "Known safe",
        "severity": "low",
        "reason": "{proc} on standard port {port} — expected browser traffic",
        "match": lambda c: _proc(c) in (
            "vivaldi.exe", "arc.exe", "librewolf.exe", "chromium.exe",
            "waterfox.exe", "iridium.exe",
        ) and _port(c) in (80, 443),
    },
    {
        "name": "known_media",
        "category": "Known safe",
        "severity": "low",
        "reason": "{proc} on standard port — expected media/streaming traffic",
        "match": lambda c: _proc(c) in (
            "vlc.exe", "plex.exe", "plex media server.exe", "kodi.exe",
            "tidal.exe", "foobar2000.exe", "netflix.exe",
        ) and _port(c) in (80, 443),
    },
    {
        "name": "known_creative_cloud",
        "category": "Known safe",
        "severity": "low",
        "reason": "Adobe {proc} on standard port — expected Creative Cloud traffic",
        "match": lambda c: _proc(c) in (
            "adobeccxprocess.exe", "adobeupdateservice.exe", "core sync.exe",
            "photoshop.exe", "illustrator.exe", "indesign.exe", "adobe premiere pro.exe",
        ) and _port(c) in (80, 443),
    },
    {
        "name": "known_vpn_client",
        "category": "Known safe",
        "severity": "low",
        "reason": "{proc} on standard port — expected VPN client traffic",
        "match": lambda c: _proc(c) in (
            "openvpn.exe", "openvpntray.exe", "wireguard.exe", "nordvpn.exe",
            "expressvpn.exe", "protonvpn.exe", "surfshark.exe", "mullvad.exe",
        ) and _port(c) in (80, 443, 1194),
    },
    # =========================================================================
    # Category 7: Hosting / VPS abuse  (needs ASN enrichment from lilith/asn.py)
    # =========================================================================
    {
        "name": "unknown_proc_hosting_asn",
        "category": "Hosting / VPS abuse",
        "severity": "medium",
        "reason": "{proc} connecting to hosting provider {asn_org} on port {port} — possible C2 hosting",
        "match": lambda c: (
            bool(_asn_org(c))
            and any(k in _asn_org(c) for k in HOSTING_ASN_KEYWORDS)
            and _port(c) not in (80, 443)
            and _proc(c) not in _KNOWN_SAFE_PROCS
        ),
    },

    {
        "name": "known_gpu_telemetry",
        "category": "Known safe",
        "severity": "low",
        "reason": "{proc} on standard port — expected GPU / peripheral telemetry",
        "match": lambda c: _proc(c) in (
            "nvcontainer.exe", "nvdisplay.container.exe", "nvidia web helper.exe",
            "razercentral.exe", "lghub.exe", "icue.exe", "armservice.exe",
        ) and _port(c) in (80, 443),
    },
]


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

# Precompute severity priority for sorting (high → medium → low)
_SEVERITY_RANK = {"high": 0, "medium": 1, "low": 2}
_HIGHEST_FIRST = sorted(RULES, key=lambda r: _SEVERITY_RANK.get(r["severity"], 99))


def evaluate_one(connection: dict) -> Verdict | None:
    """
    Run all rules against a single connection dict.

    Returns the *highest severity* Verdict that matches, or None if no
    rule fires. When multiple rules match at the same severity, the
    first one encountered (earliest in the sorted list) wins — which
    means the most specific high-severity rule fires first.
    """
    best = None
    best_rank = 99

    for rule in _HIGHEST_FIRST:
        try:
            if rule["match"](connection):
                rank = _SEVERITY_RANK.get(rule["severity"], 99)
                if rank < best_rank:
                    reason = rule["reason"].format(
                        proc=connection.get("proc_name", "?"),
                        exe=connection.get("proc_exe", "?"),
                        port=connection.get("remote_port", "?"),
                        ip=connection.get("remote_ip", "?"),
                        country=connection.get("geo_country", "?"),
                        org=connection.get("geo_org", "?"),
                        asn_org=connection.get("remote_as_org", "?"),
                    )
                    best = Verdict(
                        severity=rule["severity"],
                        reason=reason,
                        rule_name=rule["name"],
                    )
                    best_rank = rank
        except Exception as e:
            print(f"[heuristics] rule '{rule['name']}' errored: {e}")
            continue

    return best
