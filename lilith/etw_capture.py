"""
Real-time ETW kernel-network capture (Tier 2 — fixes the data blind spot).

Why: psutil polling only sees sockets open *at the instant of the poll*.
A beacon that connects, sends and closes between polls is invisible to
every rule (heuristic, reputation, or behavior). Subscribing to the
Microsoft-Windows-Kernel-Network ETW provider delivers every TCP connect
and disconnect (with the owning PID) in real time, so short-lived
connections are no longer missed.

Requirements:
  - `pywintrace` (imports as the `etw` module) — install with:
        uv sync --extra etw
  - Administrator privileges (enabling an ETW provider requires admin).

Design:
  - `start_if_available()` tries to start the trace; if the package is
    missing or the process isn't elevated, it logs a clear message and
    returns False — the normal psutil capture loop keeps running untouched
    (graceful fallback, mirroring how stage 3 degrades offline).
  - Events arrive on the `etw` library's own thread; we push connect /
    disconnect records into a bounded queue and a writer thread upserts
    them into SQLite (same dedupe key as capture.py) so the hot path stays
    fast.
  - The Kernel-Network connect events carry IPv4 addresses only (classic
    manifest); IPv6 continues to be covered by the psutil poller.

Event reference (verified against the manifest on Windows 10/11):
  - Event 12  TcpConnect      → saddr/sport/daddr/dport/pid/size (UInt32)
  - Event 13  TcpDisconnect   → same template
"""

import ctypes
import os
import queue
import socket
import struct
import threading
import time
from datetime import datetime, timezone

try:
    from etw import ETW, ProviderInfo
    ETW_AVAILABLE = True
except Exception:  # pragma: no cover - depends on optional dependency
    ETW_AVAILABLE = False

from .capture import get_db, _proc_info, _detect_direction, is_public_ip

# Confirmed via `wevtutil gp Microsoft-Windows-Kernel-Network` (local system).
KERNEL_NETWORK_GUID = "{7DD42A49-5329-4832-8DFD-43D979153A88}"
EVENT_TCP_CONNECT = 12
EVENT_TCP_DISCONNECT = 13

_events: "queue.Queue[dict]" = queue.Queue(maxsize=20000)
_writer_started = False


def _ipv4(value):
    """Convert a TDH UInt32 (host-order dword) to a dotted-quad string."""
    try:
        if isinstance(value, str):
            value = int(value, 0)
        return socket.inet_ntoa(struct.pack("<I", value & 0xFFFFFFFF))
    except Exception:
        return None


def _on_event(payload):
    """Called by the etw library for every event. payload = (event_id, event_dict)."""
    try:
        event_id, out = payload
        if event_id not in (EVENT_TCP_CONNECT, EVENT_TCP_DISCONNECT):
            return
        remote_ip = _ipv4(out.get("daddr"))
        remote_port = out.get("dport")
        if not remote_ip or not remote_port or not is_public_ip(remote_ip):
            return
        record = {
            "event": event_id,
            "local_ip": _ipv4(out.get("saddr")),
            "local_port": out.get("sport"),
            "remote_ip": remote_ip,
            "remote_port": remote_port,
            "pid": out.get("pid"),
            "ts": datetime.now(timezone.utc).isoformat(),
        }
        try:
            _events.put_nowait(record)
        except queue.Full:
            pass  # drop under extreme load rather than block the ETW thread
    except Exception:
        pass  # never let a parse error kill the ETW thread


def _upsert(item: dict):
    """Upsert one ETW connection record into SQLite (same key as capture.py)."""
    now = item["ts"]
    local_ip, local_port = item.get("local_ip"), item.get("local_port")
    remote_ip, remote_port = item["remote_ip"], item["remote_port"]
    pid = item.get("pid")

    name, exe, cmdline, mem, cpu = _proc_info(pid)
    direction = _detect_direction(local_port, remote_port, name)
    dedupe = f"{local_ip}:{local_port}-{remote_ip}:{remote_port}-{pid}"

    conn = get_db()
    cur = conn.cursor()

    if item["event"] == EVENT_TCP_CONNECT:
        cur.execute("SELECT id FROM connections WHERE dedupe_key = ?", (dedupe,))
        row = cur.fetchone()
        if row:
            cur.execute(
                "UPDATE connections SET last_seen = ?, status = 'ESTABLISHED', "
                "direction = ?, proc_memory_mb = ?, proc_cpu_pct = ? WHERE id = ?",
                (now, direction, mem, cpu, row["id"]),
            )
        else:
            cur.execute(
                """
                INSERT INTO connections
                (first_seen, last_seen, local_ip, local_port, remote_ip, remote_port,
                 status, pid, proc_name, proc_exe, proc_cmdline, proc_memory_mb, proc_cpu_pct,
                 direction, dedupe_key)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    now, now, local_ip, local_port, remote_ip, remote_port,
                    "ESTABLISHED", pid, name, exe, cmdline, mem, cpu,
                    direction, dedupe,
                ),
            )
    else:  # TCP disconnect — reflect it in the row's status
        cur.execute(
            "UPDATE connections SET status = 'CLOSED', last_seen = ? WHERE dedupe_key = ?",
            (now, dedupe),
        )

    conn.commit()
    conn.close()


def _writer_loop():
    """Drain the event queue into SQLite in a background thread."""
    while True:
        try:
            item = _events.get(timeout=1.0)
        except queue.Empty:
            continue
        try:
            _upsert(item)
        except Exception as e:
            print(f"[etw] write error: {e}")


def _is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def start_if_available() -> bool:
    """
    Start the ETW consumer in a background thread.

    Returns True when the trace is live (psutil polling continues in
    parallel either way). Logs a clear reason and returns False when the
    package is missing, the process isn't elevated, or ETW fails to start.
    """
    if not ETW_AVAILABLE:
        print(
            "[etw] pywintrace not installed — real-time capture disabled "
            "(install with: uv sync --extra etw). Falling back to psutil polling."
        )
        return False

    if not _is_admin():
        print(
            "[etw] not running as Administrator — real-time capture disabled. "
            "Falling back to psutil polling."
        )
        return False

    try:
        # PID-suffixed session name so a stale/second instance can't collide
        # and silently receive no events.
        trace = ETW(
            session_name=f"LilithKernelNetwork-{os.getpid()}",
            event_callback=_on_event,
            providers=[
                ProviderInfo("Microsoft-Windows-Kernel-Network", KERNEL_NETWORK_GUID)
            ],
        )
    except Exception as e:
        print(f"[etw] failed to initialise trace: {e} — falling back to psutil polling.")
        return False

    try:
        trace.start()
    except Exception as e:
        print(f"[etw] could not start trace: {e} — falling back to psutil polling.")
        return False

    global _writer_started
    if not _writer_started:
        _writer_started = True
        threading.Thread(target=_writer_loop, daemon=True).start()

    print("[etw] real-time Kernel-Network capture active (IPv4 TCP connect/disconnect)")
    return True


if __name__ == "__main__":
    ok = start_if_available()
    print(f"ETW started: {ok}")
    if ok:
        while True:
            time.sleep(5)
