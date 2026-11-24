"""Live test of secret redaction: plants fake secrets on disposable VMs, runs every tool
against them and reports which secrets each tool shows.

    redaction_test.py plant --target debian=root@1.2.3.4 --target alpine=alpine@5.6.7.8
    redaction_test.py check --target debian=root@1.2.3.4 --target alpine=alpine@5.6.7.8 [--save out.json]
    redaction_test.py clean --target debian=root@1.2.3.4 --target alpine=alpine@5.6.7.8

A target is PROFILE=USER@HOST[:PORT]; PROFILE is debian (Debian/Ubuntu, as root) or alpine
(a non-root user with doas -n). plant and clean write over plain ssh (the server cannot);
check calls the tools of ../../mcp_ssh.py as Python functions (not over MCP).

Every secret is a marker ZQ<letter><2 digits>, listed in MARKERS. check fails (exit 1) when
- a tool that redacts (its result has a "redaction" field; for get_host_overview, a section
  with "redaction_replaced") shows a "secret" marker,
- a "control" marker (a value that is NOT a secret) is missing from a tool that should show it,
- a call in MUST_REDACT replaced nothing (the planting did not land).
Markers shown by tools without redaction are listed, not failed: see the README.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(os.path.dirname(HERE)))
import mcp_ssh  # noqa: E402

MARKER = re.compile(r"ZQ[A-Z]\d\d")
# marker -> (kind, where it is planted). kind: secret (must be hidden by a redacting tool),
# gap (a known form redaction cannot catch), control (not a secret: must stay visible)
MARKERS = {
    # debian: systemd unit leaktest.service, its drop-ins, its environment file
    "ZQU01": ("secret", "unit Environment=DB_PASSWORD=x"),
    "ZQU02": ("secret", 'unit Environment="API_TOKEN=x y" (first word)'),
    "ZQU03": ("secret", 'unit Environment="API_TOKEN=x y" (after the space)'),
    "ZQU04": ("secret", "unit Environment='SECRET_KEY=x'"),
    "ZQU05": ("secret", "unit Environment=MODE=prod DB_PASS=x LOG=1"),
    "ZQU06": ("secret", "unit amqp://user:x@host"),
    "ZQU07": ("secret", "unit AWS_SECRET_ACCESS_KEY=x"),
    "ZQU08": ("secret", "unit GITHUB_PAT=x"),
    "ZQU09": ("secret", "unit STRIPE_KEY=sk_live_x"),
    "ZQU10": ("secret", "unit MYSQL_PWD=x"),
    "ZQU11": ("secret", "unit SetCredential=name:x"),
    "ZQU12": ("secret", "unit ExecStart --password=x (also in ps, systemctl status)"),
    "ZQU13": ("secret", "unit ExecStart --api-key x"),
    "ZQU14": ("secret", "unit ExecStart --token=x"),
    "ZQU15": ("secret", "unit ExecStartPre curl -u user:x"),
    "ZQU16": ("secret", "unit ExecStartPre Authorization: Bearer x"),
    "ZQU18": ("secret", "drop-in redis://:x@host (no user)"),
    "ZQU19": ("secret", 'drop-in Environment="PGPASSWORD=x"'),
    "ZQU20": ("secret", "drop-in postgres://u:x@db"),
    "ZQU21": ("secret", "drop-in comment password=x"),
    "ZQT01": ("secret", 'drop-in "STRIPE_KEY=sk_live_x y"'),
    "ZQT02": ("secret", "drop-in xoxb- token"),
    "ZQT03": ("secret", "drop-in ghp_ token"),
    "ZQT04": ("secret", "drop-in AKIA key id"),
    "ZQX01": ("control", 'drop-in "PRIMARY_KEY=x"'),
    "ZQX02": ("control", 'drop-in "PUBLIC_KEY=x"'),
    "ZQF01": ("secret", "EnvironmentFile contents (no tool reads it)"),
    # debian: unit leakfail.service, writes to the journal and fails
    "ZQJ01": ("secret", "journal: password=x on stderr (also in the unit's ExecStart)"),
    "ZQJ02": ("gap", "journal: 'token x' with no = (also in the unit's ExecStart)"),
    "ZQJ03": ("secret", "journal: logger -p err password=x"),
    "ZQJ04": ("secret", "journal: mysql -px on stdout"),
    # debian: root crontab
    "ZQC01": ("secret", "crontab DB_PASSWORD=x"),
    "ZQC02": ("secret", "crontab mysqldump -px"),
    "ZQC03": ("secret", "crontab curl -u user:x"),
    "ZQC04": ("secret", "crontab PGPASSWORD=x"),
    "ZQC05": ("secret", "crontab --password x"),
    "ZQC06": ("secret", "crontab --api-key=x"),
    "ZQC07": ("secret", "crontab Authorization: Bearer x"),
    "ZQC08": ("secret", "crontab sshpass -p x"),
    "ZQC09": ("secret", "crontab rsync://user:x@host"),
    "ZQC10": ("secret", "crontab sh -c 'DB_PASS=x ./run'"),
    "ZQC11": ("secret", "crontab TOKEN=x"),
    "ZQC12": ("secret", 'crontab --password="x with space"'),
    "ZQC13": ("secret", "crontab mysql -p'x q'"),
    "ZQC14": ("secret", "crontab --db-password x"),
    "ZQC15": ("gap", "crontab echo x | docker login --password-stdin"),
    "ZQC16": ("secret", "crontab export API_KEY=x; /usr/bin/..."),
    "ZQX11": ("control", "crontab command after 'API_KEY=x;', must stay"),
    # debian: /etc/cron.d, /etc/crontab, another user's crontab
    "ZQD01": ("secret", "cron.d SECRET=x"),
    "ZQD02": ("secret", "cron.d --secret=x"),
    "ZQD03": ("secret", "cron.d REDIS_PASSWORD=x"),
    "ZQT05": ("secret", "cron.d bare ghp_ token"),
    "ZQT06": ("secret", "cron.d bare sk_live_ token"),
    "ZQT07": ("secret", "cron.d bare AKIA key id"),
    "ZQT08": ("secret", "cron.d MYSQL_PWD=x"),
    "ZQT09": ("secret", "cron.d GITHUB_PAT=x"),
    "ZQX03": ("control", "cron.d SORT_KEY=x"),
    "ZQX04": ("control", "cron.d OLDPWD=x"),
    "ZQE01": ("secret", "/etc/crontab --token x"),
    "ZQV01": ("secret", "appuser crontab export API_KEY=x"),
    "ZQV02": ("secret", "appuser crontab MY_PRIVATE_KEY=x"),
    # debian: /etc/fstab
    "ZQM01": ("secret", "fstab cifs password=x,vers=3.0"),
    "ZQM02": ("secret", "fstab cifs user=bob%x"),
    "ZQM03": ("secret", "fstab cifs pass=x"),
    "ZQM04": ("secret", "fstab cifs password2=x"),
    "ZQX07": ("control", "fstab cifs domain=x after password=, must stay"),
    "ZQX08": ("control", "fstab cifs uid=x after pass=/password2=, must stay"),
    "ZQM05": ("secret", "fstab cifs password=x,,y (before the doubled comma)"),
    "ZQM06": ("secret", "fstab cifs password=x,,y (after the doubled comma)"),
    "ZQX10": ("control", "fstab cifs file_mode=x after a ,, password, must stay"),
    # debian: process arguments
    "ZQP01": ("secret", "busy loop --password=x (top CPU, get_process_info by its pid)"),
    "ZQP02": ("secret", "150 MB python --token=x (top memory; may be OOM-killed on 512 MB)"),
    "ZQP03": ("secret", "listening python --password=x"),
    # debian: docker container leakdocker
    "ZQK01": ("secret", "docker -e DB_PASSWORD=x"),
    "ZQK02": ("secret", "docker -e API_TOKEN=x"),
    "ZQK03": ("secret", "docker -e DATABASE_URL=postgres://u:x@db"),
    "ZQK04": ("secret", "docker label secret=x"),
    "ZQK05": ("secret", "docker command and log: password=x"),
    "ZQK06": ("gap", "docker command and log: 'token x' with no ="),
    "ZQK07": ("secret", "docker command: sleep --password=x"),
    # alpine: login user's crontab, root's crontab, periodic script, syslog, process
    "ZQA01": ("secret", "crontab DB_PASSWORD=x"),
    "ZQA02": ("secret", "crontab mysqldump -px"),
    "ZQA03": ("secret", "crontab wget --http-password=x"),
    "ZQA04": ("secret", "crontab curl -u user:x"),
    "ZQA05": ("secret", "crontab --api-key x"),
    "ZQT10": ("secret", "crontab SSH_KEY=x"),
    "ZQT11": ("secret", "crontab bare xoxb- token"),
    "ZQT12": ("secret", "crontab GITHUB_PAT=x"),
    "ZQX05": ("control", "crontab PRIMARY_KEY=x"),
    "ZQX06": ("control", "crontab FOREIGN_KEY=x"),
    "ZQB01": ("secret", "root crontab PGPASSWORD=x"),
    "ZQB02": ("secret", "root crontab --token=x"),
    "ZQB03": ("secret", "root crontab ftp://user:x@host"),
    "ZQB04": ("secret", "periodic script contents (only its name is listed)"),
    "ZQB05": ("secret", "syslog password=x (no tool reads /var/log/messages)"),
    "ZQP11": ("secret", "busy loop --password=x (top CPU, get_process_info by its pid)"),
    "ZQM11": ("secret", "fstab cifs password=x"),
    "ZQM12": ("secret", "fstab cifs user=bob%x,,y (before the doubled comma)"),
    "ZQM13": ("secret", "fstab cifs user=bob%x,,y (after the doubled comma)"),
    "ZQX09": ("control", "fstab cifs domain=x after password=, must stay"),
    # k8s: a deployment in namespace zqleak, pinned to the control plane node
    "ZQN01": ("secret", "pod env DB_PASSWORD=x (describe), echoed as password=x (logs)"),
    "ZQN02": ("secret", "pod env MODE=x: describe hides every literal env value"),
    "ZQN03": ("secret", "pod env DATABASE_URL=postgres://u:x@db (describe, logs)"),
    "ZQN04": ("secret", "secret value via secretKeyRef, echoed as api_key=x (logs)"),
    "ZQN05": ("secret", "pod args --password=x (describe)"),
    "ZQN06": ("gap", "pod log 'token x' with no ="),
    "ZQN07": ("secret", "pod env multi-line value, first line (describe)"),
    "ZQN08": ("secret", "pod env multi-line value, continuation line (describe)"),
    "ZQN09": ("secret", "pod env with a harmless name (describe)"),
    "ZQX18": ("control", "pod env variable name, must stay (describe)"),
    "ZQX19": ("control", "secretKeyRef key name in <set to the key ...>, must stay (describe)"),
    "ZQL11": ("secret", "lockfile requirements.txt --index-url https://user:x@host"),
    "ZQL12": ("secret", "lockfile requirements.txt git+https://x@host (token as user name)"),
    "ZQX16": ("control", "lockfile requirements.txt secretstorage==x, must stay"),
    # both profiles: lockfiles under /srv/zqleak, read by get_lockfiles(include_contents=True)
    "ZQL01": ("secret", "lockfile requirements.txt --index-url https://user:x@host"),
    "ZQL02": ("secret", "lockfile requirements.txt --extra-index-url https://__token__:x@host"),
    "ZQL03": ("secret", "lockfile requirements.txt git+https://x@host (token as user name)"),
    "ZQL04": ("secret", "lockfile requirements.txt name @ https://x@host/pkg.whl"),
    "ZQL05": ("secret", "lockfile requirements.txt git+https://ghp_x@github.com"),
    "ZQL06": ("secret", "lockfile package-lock.json resolved https://user:x@registry"),
    "ZQL07": ("secret", "lockfile package-lock.json resolved ...tgz?private_token=x"),
    "ZQL08": ("secret", "lockfile requirements.txt name @ https://host/pkg.whl?token=x"),
    "ZQX12": ("control", "lockfile requirements.txt secretstorage==x, must stay"),
    "ZQX13": ("control", "lockfile requirements.txt ${x} placeholder in an index URL, must stay"),
    "ZQX14": ("control", "lockfile requirements.txt git+ssh://x@host user name, must stay"),
    "ZQX15": ("control", 'lockfile package-lock.json "js-tokens": "x" version, must stay'),
    "ZQX17": ("control", "lockfile requirements.txt git+https://host/repo?branch=x, must stay"),
}
# profile -> (tool, args) -> controls that tool must show
CONTROLS = {
    "debian": {("get_systemd_unit_definition", "leaktest"): ["ZQX01", "ZQX02"],
               ("get_crontab_tasks", None): ["ZQX11"],
               ("get_cron_jobs", None): ["ZQX03", "ZQX04", "ZQX11"],
               ("get_fstab", None): ["ZQX07", "ZQX08", "ZQX10"],
               ("get_lockfiles", "include_contents"): ["ZQX12", "ZQX13", "ZQX14", "ZQX15", "ZQX17"]},
    "alpine": {("get_crontab_tasks", None): ["ZQX05", "ZQX06"],
               ("get_cron_jobs", None): ["ZQX05", "ZQX06"],
               ("get_fstab", None): ["ZQX09"],
               ("get_lockfiles", "include_contents"): ["ZQX16"]},
    "k8s": {("get_kubectl_describe", None): ["ZQX18", "ZQX19"]},
}
# profile -> the calls (tool, daemon or service arg) whose output always holds a planted
# secret: when one of them replaced nothing, the planting did not land
MUST_REDACT = {
    "debian": {("get_systemd_unit_definition", "leaktest"), ("get_systemd_unit_definition", "leakfail"),
               ("get_systemd_status", "leaktest"), ("get_systemd_status", "leakfail"),
               ("get_crontab_tasks", None), ("get_cron_jobs", None), ("get_ps_aux_top_cpu_consumers", None),
               ("get_top", None), ("get_service_logs_from_journalctl", "leakfail"), ("get_journal_errors", None),
               ("get_docker_logs", None), ("get_docker_inspect", None), ("get_host_overview", None),
               ("get_fstab", None), ("get_mount_problems", None), ("get_lockfiles", "include_contents"),
               ("get_process_info", None)},
    "alpine": {("get_crontab_tasks", None), ("get_cron_jobs", None), ("get_ps_aux_top_cpu_consumers", None),
               ("get_top", None), ("get_host_overview", None), ("get_fstab", None),
               ("get_mount_problems", None), ("get_lockfiles", "include_contents"), ("get_process_info", None)},
    "k8s": {("get_kubectl_logs", None), ("get_crictl_logs", None), ("get_kubectl_describe", None)},
}
# values for required parameters; the leak units and container are the interesting ones
REQUIRED = {
    "abs_paths": ["/srv"], "daemon": "leaktest", "container": "leakdocker", "pod": "web-1",
    "resource_type": "pod", "name": "example.com", "container_id": "abcdef123456", "image": "busybox",
    "target_host": "127.0.0.1", "target_port": 22, "service": "leakfail",
}
# extra calls on top of one call per tool with REQUIRED
EXTRA_CALLS = [
    ("get_systemd_status", {"daemon": "leakfail"}),
    ("get_systemd_unit_definition", {"daemon": "leakfail"}),
    ("get_service_logs_from_journalctl", {"service": "leaktest"}),
    ("get_lockfiles", {"abs_paths": ["/srv/zqleak"], "include_contents": True}),
]


# profile -> tool -> the arguments of its one call, in place of REQUIRED. {pod} and {cid} are
# looked up on the node when check starts (the pod name has a random suffix).
PROFILE_ARGS = {
    "debian": {"get_process_info": {"pid": "{busy}"}},
    "alpine": {"get_process_info": {"pid": "{busy}"}},
    "k8s": {
        "get_kubectl_logs": {"pod": "{pod}", "namespace": "zqleak"},
        "get_kubectl_describe": {"resource_type": "pod", "name": "{pod}", "namespace": "zqleak"},
        "get_kubectl_events": {"namespace": "zqleak"},
        "get_crictl_logs": {"container_id": "{cid}"},
        "get_crictl_inspect": {"container_id": "{cid}"},
    },
}
PROFILE_EXTRA_CALLS = {
    "k8s": [("get_kubectl_describe", {"resource_type": "deployment", "name": "leakpod", "namespace": "zqleak"})],
}
# what {pod} and {cid} are: read-only lookups, run through the server's own run_ssh_command
LOOKUPS = {
    # [b]usy: the pattern does not match the command line of the shell running pgrep
    "debian": {"busy": "pgrep -f '[b]usy --password=ZQP01' | head -n 1"},
    "alpine": {"busy": "pgrep -f '[b]usy --password=ZQP11' | head -n 1"},
    "k8s": {"pod": "kubectl -n zqleak get pod -l app=leakpod -o name | cut -d/ -f2",
            "cid": "crictl ps --name leak -q | head -n 1"},
}


def call_key(tool, args):
    """(tool, what tells its calls apart) as in CONTROLS and MUST_REDACT: the unit or
    service, or "include_contents" for get_lockfiles printing the files."""
    return (tool, args.get("daemon") or args.get("service")
            or ("include_contents" if args.get("include_contents") else None))


def parse_target(text):
    profile, _, dest = text.partition("=")
    if profile not in CONTROLS or "@" not in dest:
        raise argparse.ArgumentTypeError(f"expected debian=, alpine= or k8s=USER@HOST[:PORT], got {text!r}")
    user, _, hostport = dest.partition("@")
    host, _, port = hostport.partition(":")
    return {"profile": profile, "user": user, "host": host, "port": int(port or 22)}


def ssh_script(target, key, script):
    """Runs a local script on the target over plain ssh (plant/clean write; the server cannot)."""
    with open(os.path.join(HERE, script), "rb") as f:
        r = subprocess.run(["ssh", "-i", key, "-p", str(target["port"]), "-o", "BatchMode=yes",
                            f"{target['user']}@{target['host']}", "sh -s"], stdin=f, capture_output=True)
    print(f"[{target['profile']} {target['host']}] {script}: exit {r.returncode}")
    sys.stdout.write(r.stdout.decode(errors="replace")[-2000:])
    sys.stdout.write(r.stderr.decode(errors="replace")[-2000:])
    return r.returncode


def tool_calls(profile, found):
    overrides = PROFILE_ARGS.get(profile, {})
    def fill(args):
        filled = {k: v.format(**found) if isinstance(v, str) else v for k, v in args.items()}
        return {k: int(v) if k == "pid" else v for k, v in filled.items()}
    calls = []
    for tool in asyncio.run(mcp_ssh.mcp.list_tools()):
        fn = getattr(mcp_ssh, tool.name)
        params = mcp_ssh.inspect.signature(fn).parameters
        if tool.name in overrides:
            calls.append((tool.name, fill(overrides[tool.name])))
        else:
            calls.append((tool.name, {p: REQUIRED[p] for p in params if p in REQUIRED and params[p].default is params[p].empty}))
    return calls + EXTRA_CALLS + [(t, fill(a)) for t, a in PROFILE_EXTRA_CALLS.get(profile, [])]


def lookup(target, key):
    found = {}
    for name, cmd in LOOKUPS.get(target["profile"], {}).items():
        r = mcp_ssh.run_ssh_command(target["host"], target["user"], cmd, port=target["port"], key_path=key)
        found[name] = (r.get("data") or {}).get("stdout", "").strip()
        if not found[name]:
            sys.exit(f"[{target['profile']}] could not find {name} ({cmd}): did plant run?")
    return found


def check(target, key):
    failures, rows = [], []
    for tool, args in tool_calls(target["profile"], lookup(target, key)):
        r = getattr(mcp_ssh, tool)(host=target["host"], user=target["user"], port=target["port"], key_path=key, **args)
        shown = sorted(set(MARKER.findall(json.dumps(r))))
        redacts, replaced, checked = "redaction" in r, (r.get("redaction") or {}).get("replaced"), r
        sections = ((r.get("data") or {}).get("sections") or {}) if tool == "get_host_overview" else {}
        if sections:
            # the overview redacts the sections whose tool redacts: check those, list the rest
            redacted = {n: x for n, x in sections.items() if "redaction_replaced" in x}
            redacts, replaced, checked = True, sum(x["redaction_replaced"] for x in redacted.values()), redacted
        in_checked = set(MARKER.findall(json.dumps(checked)))
        row = {"tool": tool, "args": args, "ok": r.get("ok"), "redacts": redacts,
               "replaced": replaced, "shown": shown, "result": r}
        rows.append(row)
        problems = []
        if redacts:
            leaked = [m for m in shown if m in in_checked and MARKERS.get(m, ("secret",))[0] == "secret"]
            if leaked:
                problems.append("LEAKED " + ", ".join(f"{m} ({MARKERS.get(m, ('', '?'))[1]})" for m in leaked))
            call = call_key(tool, args)
            if call in MUST_REDACT[target["profile"]] and not replaced:
                problems.append("replaced nothing: did plant run?")
        key_args = call_key(tool, args)
        if r.get("ok") and key_args in CONTROLS[target["profile"]]:
            missing = [m for m in CONTROLS[target["profile"]][key_args] if m not in shown]
            if missing:
                problems.append("over-redacted controls " + ", ".join(missing))
        status = "FAIL" if problems else ("ok  " if redacts else "info")
        gaps = [m for m in shown if MARKERS.get(m, ("",))[0] == "gap"]
        unredacted = [m for m in shown if m not in in_checked]  # overview sections that do not redact
        note = "; ".join(problems) if problems else (
            "; ".join(x for x in (f"known gaps {', '.join(gaps)}" if gaps else "",
                                  f"in sections without redaction: {' '.join(unredacted)}" if unredacted else "") if x)
            if redacts and (gaps or unredacted) else
            "" if redacts else (f"no redaction, shows {' '.join(shown)}" if shown else ""))
        red = f"redacted {row['replaced']:>3}" if redacts else "            "
        print(f"  {status} {tool:34} {str(args or '')[:28]:28} ok={str(r.get('ok')):5} {red}  {note}")
        failures += [f"{tool} {args}: {p}" for p in problems]
    return failures, rows


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("mode", choices=["plant", "check", "clean"])
    ap.add_argument("--target", type=parse_target, action="append", required=True)
    ap.add_argument("--key", default=os.path.expanduser("~/.ssh/id_rsa"))
    ap.add_argument("--save", help="check: write every result to this JSON file")
    a = ap.parse_args()
    if a.mode in ("plant", "clean"):
        rcs = [ssh_script(t, a.key, f"{a.mode}_{t['profile']}.sh") for t in a.target]
        sys.exit(0 if not any(rcs) else 1)
    failures, saved = [], {}
    for t in a.target:
        print(f"== {t['profile']} {t['user']}@{t['host']}")
        f, rows = check(t, a.key)
        failures += [f"{t['profile']}: {x}" for x in f]
        saved[f"{t['profile']}@{t['host']}"] = rows
    if a.save:
        with open(a.save, "w") as fh:
            json.dump(saved, fh, indent=1)
    print(f"\n{len(failures)} failure(s)")
    for x in failures:
        print("  " + x)
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
