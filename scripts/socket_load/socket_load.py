#!/usr/bin/env python3
"""Live load test of get_socket_summary and get_tcp_connections: one disposable VM makes TCP
load against another, then get_socket_summary runs on both and must show each generated
state on one counted line, and get_tcp_connections must list the sockets behind them.

    socket_load.py run   --server root@1.2.3.4 --client alpine@5.6.7.8   # start, settle, check, stop
    socket_load.py start --server root@1.2.3.4 --client alpine@5.6.7.8 [--held N --closed N --seconds N]
    socket_load.py check --server root@1.2.3.4 --client alpine@5.6.7.8 [--held N --closed N]
    socket_load.py stop  --server root@1.2.3.4 --client alpine@5.6.7.8

The server is USER@HOST[:PORT] of a Debian/Ubuntu VM as root; the client any user on any VM
with nc, timeout, wget and setsid (BusyBox is fine). start and stop write over plain ssh
(the server cannot); check calls the tools of ../../mcp_ssh.py as Python functions.
check fails (exit 1) when a generated state is missing, the summary is not small, or
get_tcp_connections does not list or cap the sockets.
"""
from __future__ import annotations

import argparse
import os
import re
import shlex
import socket
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(os.path.dirname(HERE)))
import mcp_ssh  # noqa: E402

# what server_start.sh sets up
LEAKY_PORT = 9000
BLACKHOLE = "10.255.255.1:5432"
# the summary must stay this small however many sockets there are
MAX_SUMMARY_BYTES = 4096
# a count passes at this share of what was generated (some connections may still be opening)
SHARE = 0.9
ROW = re.compile(r"^\s*(\d+)\s+(\S+)\s+(in|out)\s+(\S+)\s+(\S+)\s*$")


def parse_dest(text):
    if "@" not in text:
        raise argparse.ArgumentTypeError(f"expected USER@HOST[:PORT], got {text!r}")
    user, _, hostport = text.partition("@")
    host, _, port = hostport.partition(":")
    return {"user": user, "host": host, "port": int(port or 22)}


def ssh_script(dest, key, script, *args):
    """Runs a local script on dest over plain ssh, with args."""
    remote = "sh -s -- " + " ".join(shlex.quote(str(a)) for a in args)
    with open(os.path.join(HERE, script), "rb") as f:
        r = subprocess.run(["ssh", "-i", key, "-p", str(dest["port"]), "-o", "BatchMode=yes",
                            f"{dest['user']}@{dest['host']}", remote], stdin=f, capture_output=True)
    print(f"[{dest['host']}] {script}: exit {r.returncode}")
    sys.stdout.write(r.stdout.decode(errors="replace")[-2000:])
    sys.stdout.write(r.stderr.decode(errors="replace")[-2000:])
    return r.returncode


def summary(dest, key):
    t = time.time()
    r = mcp_ssh.get_socket_summary(host=dest["host"], user=dest["user"], port=dest["port"], key_path=key)
    data = r.get("data", {})
    out = data.get("stdout") or ""
    print(f"== {dest['user']}@{dest['host']}: exit {data.get('exit_code')}, {len(out)} bytes, "
          f"{time.time() - t:.1f}s")
    print(out)
    if data.get("stderr"):
        print("stderr:", data["stderr"])
    rows = [m.groups() for m in map(ROW.match, out.splitlines()) if m]
    return r, out, [(int(c), state, d, where, proc) for c, state, d, where, proc in rows]


def count(rows, state, direction, where, proc=None):
    return sum(c for c, s, d, w, p in rows
               if s == state and d == direction and w == where and (proc is None or p == proc))


def check(server, client, key, held, closed):
    failures = []

    def expect(what, got, want):
        ok = got >= want
        print(f"  {'ok  ' if ok else 'FAIL'} {what}: {got} (want >= {want})")
        if not ok:
            failures.append(f"{what}: {got}, want >= {want}")

    raw = mcp_ssh.run_ssh_command(server["host"], server["user"], "ss -tanp | wc -lc",
                                  server["port"], None, key, 20, False)
    print("raw ss -tanp on the server (lines, bytes):", (raw.get("data") or {}).get("stdout", "").strip())
    r, out, rows = summary(server, key)
    if not r.get("ok"):
        failures.append(f"server: {r.get('error') or 'tool failed'}")
    if len(out) > MAX_SUMMARY_BYTES:
        failures.append(f"server summary is {len(out)} bytes, want <= {MAX_SUMMARY_BYTES}")
    print(f"  {'ok  ' if len(out) <= MAX_SUMMARY_BYTES else 'FAIL'} server summary size: "
          f"{len(out)} bytes (want <= {MAX_SUMMARY_BYTES})")
    expect("server TIME-WAIT in :80 (wget churn)", count(rows, "TIME-WAIT", "in", ":80"), 100)
    expect(f"server ESTAB in :{LEAKY_PORT} python3 (held)",
           count(rows, "ESTAB", "in", f":{LEAKY_PORT}", "python3"), int(held * SHARE))
    expect(f"server CLOSE-WAIT in :{LEAKY_PORT} python3 (leak)",
           count(rows, "CLOSE-WAIT", "in", f":{LEAKY_PORT}", "python3"), int(closed * SHARE))
    expect("server SYN-SENT out to the blackhole", count(rows, "SYN-SENT", "out", BLACKHOLE, "python3"), 1)

    r, out, rows = summary(client, key)
    if not r.get("ok"):
        failures.append(f"client: {r.get('error') or 'tool failed'}")
    server_ip = socket.gethostbyname(server["host"])
    expect(f"client ESTAB out {server_ip}:{LEAKY_PORT} nc (held)",
           count(rows, "ESTAB", "out", f"{server_ip}:{LEAKY_PORT}", "nc"), int(held * SHARE))

    # drilling in: the sockets behind the CLOSE-WAIT line, and the cap on the TIME-WAIT pile
    out = connections(server, key, state="close-wait", tcp_port=LEAKY_PORT)
    expect(f"server get_tcp_connections close-wait :{LEAKY_PORT}: CLOSE-WAIT python3 lines",
           sum(1 for x in out.splitlines() if x.startswith("CLOSE-WAIT") and '"python3"' in x), int(closed * SHARE))
    out = connections(server, key, state="time-wait", tcp_port=80, lines=10)
    rows_shown = [x for x in out.splitlines() if x.startswith("TIME-WAIT")]
    capped = re.search(r"^# showing the first 10 of (\d+) matching sockets", out, re.M)
    expect("server get_tcp_connections time-wait :80 lines=10: rows shown", len(rows_shown), 10)
    expect("server get_tcp_connections time-wait :80 lines=10: matching count in the cap note",
           int(capped.group(1)) if capped else 0, 100)
    if len(rows_shown) > 10:
        failures.append(f"get_tcp_connections lines=10 showed {len(rows_shown)} rows")
    out = connections(client, key, state="established", tcp_port=LEAKY_PORT, lines=1000)
    expect(f"client get_tcp_connections established :{LEAKY_PORT} (netstat on BusyBox)",
           sum(1 for x in out.splitlines() if x.startswith("tcp") or x.startswith("ESTAB")), int(held * SHARE))
    return failures


def connections(dest, key, **args):
    r = mcp_ssh.get_tcp_connections(host=dest["host"], user=dest["user"], port=dest["port"], key_path=key, **args)
    out = (r.get("data") or {}).get("stdout") or ""
    lines = out.splitlines()
    print(f"== get_tcp_connections {args} on {dest['host']}: exit {(r.get('data') or {}).get('exit_code')}, "
          f"{len(lines)} lines, {len(out)} bytes")
    print("\n".join(lines[:4] + (["..."] + lines[-2:] if len(lines) > 6 else lines[4:])))
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("mode", choices=["run", "start", "check", "stop"])
    ap.add_argument("--server", type=parse_dest, required=True)
    ap.add_argument("--client", type=parse_dest, required=True)
    ap.add_argument("--key", default=os.path.expanduser("~/.ssh/id_rsa"))
    ap.add_argument("--held", type=int, default=200)
    ap.add_argument("--closed", type=int, default=50)
    ap.add_argument("--seconds", type=int, default=240, help="how long the load runs")
    ap.add_argument("--settle", type=int, default=30, help="run: seconds between start and check")
    a = ap.parse_args()

    def start():
        return (ssh_script(a.server, a.key, "server_start.sh")
                or ssh_script(a.client, a.key, "client_start.sh", a.server["host"], a.held, a.closed, a.seconds))

    def stop():
        return ssh_script(a.client, a.key, "client_stop.sh") | ssh_script(a.server, a.key, "server_stop.sh")

    if a.mode == "start":
        sys.exit(1 if start() else 0)
    if a.mode == "stop":
        sys.exit(1 if stop() else 0)
    if a.mode == "run":
        if start():
            stop()
            sys.exit(1)
        print(f"settling for {a.settle}s")
        time.sleep(a.settle)
    try:
        failures = check(a.server, a.client, a.key, a.held, a.closed)
    finally:
        if a.mode == "run":
            stop()
    print(f"\n{len(failures)} failure(s)")
    for x in failures:
        print("  " + x)
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
