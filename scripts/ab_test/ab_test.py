#!/usr/bin/env python3
"""A/B test of mcp_ssh.py: a git ref (A, default HEAD) against the working tree (B).

Modes:
    commands   Offline. Records the command every tool sends (run_ssh_command patched
               out) and the wrapper _run_cmd puts around it, for A and B, and prints
               every difference. A pure refactor must show none.
    fleet      Runs every registered tool on every host, with A and with B, and compares
               ok / exit code / timed_out / error / stderr, and which stdouts differ.
    timeouts   Runs timeout scenarios (pipelines, background jobs, a command ignoring
               TERM, ...) on every host with B and checks that nothing is left running.

Usage:
    python scripts/ab_test/ab_test.py commands [--ref REF]
    python scripts/ab_test/ab_test.py fleet    [--ref REF] [--hosts FILE] [--key PATH]
    python scripts/ab_test/ab_test.py timeouts [--hosts FILE] [--key PATH]

Each version runs in its own process (its own import of mcp_ssh), so A and B never mix.
See README.md next to this file.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
DEFAULT_HOSTS = os.path.join(HERE, "hosts.txt")
DEFAULT_KEY = "~/.ssh/id_rsa"

# Valid values for the required parameters of the tools
REQUIRED = {
    "abs_path": "/var", "abs_paths": ["/srv"], "binary": "sshd", "daemon": "sshd", "container": "web",
    "pod": "web-1", "resource_type": "pod", "name": "web-1", "container_id": "abcdef123456",
    "image": "nginx:1", "target_host": "example.com", "target_port": 443, "service": "sshd",
}
# Extra calls (commands mode) for tools whose parameters change the command
VARIANTS = {
    "get_dmesg": [{"since": "1 hour ago"}, {"since": "today"}, {"since": "bad value"}],
    "get_journal_errors": [{"lines": 20}, {"current_boot_only": True}, {"since": "1 hour ago"},
                           {"lines": 5, "current_boot_only": True, "since": "2026-11-22 10:00"},
                           {"lines": 0}, {"current_boot_only": "yes"}, {"since": "bad value"}],
    "get_iostat": [{"samples": 1, "interval": 2}],
    "get_mpstat": [{"samples": 1, "interval": 2}],
    "get_cpu_info": [{"include_flags": True}],
}
# (name, command, timeout_s, expect_timeout); {n} is a sleep length unique to the run.
# expect_timeout "rejected": the timeout is out of bounds, so nothing may run on the host
# (with timeout 0, GNU timeout would not stop the command at all).
SCENARIOS = [
    ("simple", "sleep {n}", 3, True),
    ("pipeline", "sleep {n} | cat", 3, True),
    ("output then pipeline", "echo start; sleep {n} | cat", 3, True),
    ("background job", "sleep {n} & wait", 3, True),
    ("ignores TERM", "trap '' TERM; sleep {n} | cat", 3, True),
    ("stderr and exit code", "echo out; echo err >&2; exit 3", 10, False),
    ("pipefail (bash) or not", "set -o pipefail 2>/dev/null; false | true; echo rc=$?", 10, False),
    ("8 MB stdout", "head -c 8000000 /dev/zero | tr '\\0' x", 20, False),
    ("finishes just in time", "sleep 1; echo done", 3, False),
    ("timeout 0 rejected", "sleep {n}", 0, "rejected"),
    ("timeout 361 rejected", "sleep {n}", 361, "rejected"),
]


# ============================================================
# Workers: run inside a process that imported one version of mcp_ssh
# ============================================================

def _import(module_dir):
    os.environ["SAFE_SSH_MCP_LOG_FILE"] = os.path.join(tempfile.mkdtemp(), "ab_test.log")
    sys.path.insert(0, module_dir)
    import mcp_ssh
    return mcp_ssh


def _tools(mcp_ssh):
    import asyncio
    names = sorted(t.name for t in asyncio.run(mcp_ssh.mcp.list_tools()))
    return {n: getattr(mcp_ssh, n) for n in names}


def _base_kwargs(fn, host, user):
    import inspect
    params = inspect.signature(fn).parameters
    return {"host": host, "user": user, **{k: v for k, v in REQUIRED.items() if k in params}}


def worker_commands(module_dir):
    mcp_ssh = _import(module_dir)
    calls = []

    def fake_run(host, user, cmd, *args, **kwargs):
        calls.append({"cmd": cmd, "args": [repr(a) for a in args],
                      "kwargs": {k: repr(v) for k, v in kwargs.items()}})
        return {"ok": True, "host": host, "data": {"command": cmd, "exit_code": 0, "stdout": "", "stderr": ""}}
    mcp_ssh.run_ssh_command = fake_run

    out = {}
    tools = _tools(mcp_ssh)
    out["_tool_names"] = sorted(tools)
    for name, fn in tools.items():
        for extra in [{}] + VARIANTS.get(name, []):
            calls.clear()
            result = fn(**_base_kwargs(fn, "h", "u"), **extra)
            key = name + (json.dumps(extra, sort_keys=True) if extra else "")
            out[key] = {"calls": list(calls), "result_error": result.get("error")}
    out["_wrapper"] = mcp_ssh.timeout_wrapped("echo 'a b'; ls", 17) if hasattr(mcp_ssh, "timeout_wrapped") else None
    return out


def worker_fleet(module_dir, host, user, port, key):
    import hashlib
    import time
    mcp_ssh = _import(module_dir)
    out = {}
    for name, fn in _tools(mcp_ssh).items():
        kw = _base_kwargs(fn, host, user)
        kw.update(port=port, key_path=key)
        started = time.monotonic()
        try:
            r = fn(**kw)
        except Exception as e:  # a crash is a result too
            r = {"ok": None, "error": f"CRASH: {type(e).__name__}: {e}"}
        d = r.get("data") if isinstance(r.get("data"), dict) else {}
        stdout = d.get("stdout", "") if d else json.dumps(r.get("data"))
        out[name] = {
            "ok": r.get("ok"), "exit": d.get("exit_code"), "timed_out": d.get("timed_out", False),
            "error": (r.get("error") or "")[:200], "stderr": (d.get("stderr") or "")[:300],
            "seconds": round(time.monotonic() - started, 1), "stdout_len": len(stdout),
            "stdout_md5": hashlib.md5(stdout.encode()).hexdigest(), "stdout_head": stdout[:300],
        }
    return out


def worker_timeouts(module_dir, host, user, port, key):
    import random
    import time
    mcp_ssh = _import(module_dir)
    base = 7000 + random.randrange(300) * 10
    rows = []
    for i, (scenario, cmd, timeout_s, expect) in enumerate(SCENARIOS):
        n = base + i
        started = time.monotonic()
        r = mcp_ssh.run_ssh_command(host, user, cmd.format(n=n), port=port, key_path=key, timeout_s=timeout_s)
        seconds = time.monotonic() - started
        d = r.get("data", {})
        time.sleep(0.5)
        # the pattern is split so that grep does not find itself
        probe = f"ps -eo pid,ppid,args 2>/dev/null || ps -o pid,ppid,args; true"
        ps = mcp_ssh.run_ssh_command(host, user, probe, port=port, key_path=key).get("data", {}).get("stdout", "")
        leftovers = [l.strip() for l in ps.splitlines() if f"sleep {n}" in l and "ps -eo" not in l]
        error = r.get("error") or ""
        rows.append({
            "scenario": scenario, "seconds": round(seconds, 1), "exit": d.get("exit_code"),
            "timed_out": d.get("timed_out", False), "stdout": d.get("stdout", "")[:30],
            "stdout_len": len(d.get("stdout", "")), "stderr": d.get("stderr", "")[:30],
            "error": error[:80], "leftovers": leftovers,
            "pass": (error.startswith("Invalid timeout") and seconds < 1 and not leftovers
                     if expect == "rejected" else
                     d.get("timed_out", False) == expect and not leftovers
                     and "Network error" not in error and seconds < timeout_s + 4),
        })
    return rows


# ============================================================
# Orchestration
# ============================================================

def read_hosts(path):
    """hosts file: one `name user@host[:port]` per line; # comments allowed."""
    if not os.path.isfile(path):
        sys.exit(f"No hosts file at {path}. Copy hosts.example.txt to hosts.txt and fill it in.")
    hosts = []
    for line in open(path):
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        name, target = line.split()
        user, _, hostport = target.partition("@")
        host, _, port = hostport.partition(":")
        hosts.append({"name": name, "user": user, "host": host, "port": int(port or 22)})
    return hosts


def version_dir(ref):
    """A directory holding mcp_ssh.py as of `ref`, or the working tree for ref=None."""
    if ref is None:
        return REPO
    d = tempfile.mkdtemp(prefix=f"ab_test_{ref.replace('/', '_')}_")
    src = subprocess.run(["git", "-C", REPO, "show", f"{ref}:mcp_ssh.py"],
                         capture_output=True, text=True, check=True).stdout
    with open(os.path.join(d, "mcp_ssh.py"), "w") as f:
        f.write(src)
    return d


def run_worker(*args):
    """Runs a worker in a fresh interpreter (so each version is imported alone)."""
    p = subprocess.run([sys.executable, os.path.abspath(__file__), "_worker", *map(str, args)],
                       capture_output=True, text=True, cwd=tempfile.gettempdir())
    if p.returncode != 0:
        raise RuntimeError(f"worker {args[:2]} failed:\n{p.stderr[-2000:]}")
    return json.loads(p.stdout)


def cmd_commands(args):
    a, b = (run_worker("commands", version_dir(v)) for v in (args.ref, None))
    diffs = [k for k in sorted(set(a) | set(b)) if a.get(k) != b.get(k)]
    print(f"A={args.ref}  B=working tree: {len(a)} / {len(b)} entries, {len(diffs)} differ")
    for k in diffs:
        print(f"\n== {k}\n  A: {json.dumps(a.get(k))[:600]}\n  B: {json.dumps(b.get(k))[:600]}")
    return 1 if diffs else 0


def cmd_fleet(args):
    hosts = read_hosts(args.hosts)
    dirs = {"A": version_dir(args.ref), "B": REPO}
    jobs = [(v, h) for v in dirs for h in hosts]
    with ThreadPoolExecutor(len(jobs)) as pool:
        results = dict(zip(
            [(v, h["name"]) for v, h in jobs],
            pool.map(lambda j: run_worker("fleet", dirs[j[0]], j[1]["host"], j[1]["user"], j[1]["port"], args.key), jobs),
        ))
    print(f"A={args.ref}  B=working tree")
    failed = False
    for h in hosts:
        a, b = results[("A", h["name"])], results[("B", h["name"])]
        same = sum(a[t]["stdout_md5"] == b.get(t, {}).get("stdout_md5") for t in a)
        print(f"\n== {h['name']} ({h['user']}@{h['host']}): ok A {sum(bool(a[t]['ok']) for t in a)}/{len(a)}, "
              f"B {sum(bool(b[t]['ok']) for t in b)}/{len(b)}; identical stdout {same}/{len(a)}; "
              f"time A {sum(a[t]['seconds'] for t in a):.0f}s, B {sum(b[t]['seconds'] for t in b):.0f}s")
        for t in sorted(set(a) | set(b)):
            if t not in a or t not in b:
                print(f"  {t}: only in {'B' if t not in a else 'A'}")
                continue
            fields = [k for k in ("ok", "exit", "timed_out", "error", "stderr") if a[t][k] != b[t][k]]
            if fields:
                failed = True
                print(f"  {t}: " + "; ".join(f"{k}: {a[t][k]!r} -> {b[t][k]!r}" for k in fields))
        changed = [f"{t} ({a[t]['stdout_len']}->{b[t]['stdout_len']})" for t in sorted(a)
                   if t in b and a[t]["stdout_md5"] != b[t]["stdout_md5"]]
        if changed:
            print("  stdout differs (expected for live data: times, counters, process lists): " + ", ".join(changed))
    if args.save:
        json.dump({f"{v}:{n}": r for (v, n), r in results.items()}, open(args.save, "w"), indent=1)
        print(f"\nraw results: {args.save}")
    return 1 if failed else 0


def cmd_timeouts(args):
    hosts = read_hosts(args.hosts)
    with ThreadPoolExecutor(len(hosts)) as pool:
        results = list(pool.map(
            lambda h: run_worker("timeouts", REPO, h["host"], h["user"], h["port"], args.key), hosts))
    failures = 0
    for h, rows in zip(hosts, results):
        for r in rows:
            failures += not r["pass"]
            print(f"{h['name']:8} {r['scenario']:24} {r['seconds']:5}s exit={r['exit']!s:4} "
                  f"timed_out={r['timed_out']!s:5} stdout={r['stdout'] if r['stdout_len'] < 30 else str(r['stdout_len']) + 'B'!r:14} "
                  f"stderr={r['stderr']!r:10} leftovers={len(r['leftovers'])} {'PASS' if r['pass'] else 'FAIL ' + r['error']}")
            for l in r["leftovers"]:
                print(f"{'':10}left running: {l[:150]}")
    print(f"\n{failures} failed of {sum(len(r) for r in results)}")
    if failures:
        print("Leftovers that ignore TERM need `pkill -KILL -f 'sleep <n>'` on the host.")
    return 1 if failures else 0


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "_worker":
        mode, module_dir, *rest = sys.argv[2:]
        if mode == "commands":
            out = worker_commands(module_dir)
        else:
            host, user, port, key = rest
            out = {"fleet": worker_fleet, "timeouts": worker_timeouts}[mode](
                module_dir, host, user, int(port), os.path.expanduser(key))
        json.dump(out, sys.stdout)
        return 0

    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="mode", required=True)
    for name in ("commands", "fleet", "timeouts"):
        s = sub.add_parser(name)
        if name != "timeouts":
            s.add_argument("--ref", default="HEAD", help="git ref for version A (default HEAD)")
        if name != "commands":
            s.add_argument("--hosts", default=DEFAULT_HOSTS, help="hosts file (default: hosts.txt here)")
            s.add_argument("--key", default=DEFAULT_KEY, help=f"SSH private key (default {DEFAULT_KEY})")
        if name == "fleet":
            s.add_argument("--save", help="write the raw per-tool results to this JSON file")
    args = p.parse_args()
    return {"commands": cmd_commands, "fleet": cmd_fleet, "timeouts": cmd_timeouts}[args.mode](args)


if __name__ == "__main__":
    sys.exit(main())
