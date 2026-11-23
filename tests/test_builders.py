"""Tests for the command builders and constants that tools share with other callers
(e.g. a report that runs several tools' commands in one SSH call).

The contract: a tool sends exactly what its builder or constant builds, so the two can
never drift apart."""
import os
import random
import shlex
import shutil
import subprocess
import sys
import time

import pytest

import mcp_ssh


# ============================================================
# Each tool sends its constant / builder output
# ============================================================

@pytest.mark.parametrize("tool, expected", [
    (mcp_ssh.get_disk_free, mcp_ssh.DISK_FREE_CMD),
    (mcp_ssh.get_inode_usage, mcp_ssh.INODE_USAGE_CMD),
    (mcp_ssh.get_uptime, mcp_ssh.UPTIME_CMD),
    (mcp_ssh.get_distroname_version, mcp_ssh.OS_RELEASE_CMD),
    (mcp_ssh.get_kernel_version, mcp_ssh.KERNEL_VERSION_CMD),
    (mcp_ssh.get_free_memory, mcp_ssh.FREE_MEMORY_CMD),
    (mcp_ssh.get_pressure, mcp_ssh.PRESSURE_CMD),
    (mcp_ssh.get_lsblk, mcp_ssh.LSBLK_CMD),
    (mcp_ssh.get_systemd_list_failed, mcp_ssh.SYSTEMD_FAILED_CMD),
    (mcp_ssh.get_vmstat, mcp_ssh.vmstat_cmd()),
    (mcp_ssh.get_dmesg, mcp_ssh.dmesg_cmd()),
    (mcp_ssh.get_journal_errors, mcp_ssh.journal_errors_cmd(200)),
])
def test_tool_sends_its_shared_command(tool, expected, mock_run_ssh_command):
    tool(host="h", user="u")
    assert mock_run_ssh_command.call_args[0][2] == expected


# The values themselves, so that a change to a shared command is a visible test change
@pytest.mark.parametrize("value, expected", [
    (mcp_ssh.DISK_FREE_CMD, "df -h"),
    (mcp_ssh.INODE_USAGE_CMD, "df -i"),
    (mcp_ssh.UPTIME_CMD, "uptime"),
    (mcp_ssh.OS_RELEASE_CMD, "cat /etc/os-release"),
    (mcp_ssh.KERNEL_VERSION_CMD, "uname -srvm"),
    (mcp_ssh.FREE_MEMORY_CMD, "free -h && echo && cat /proc/meminfo"),
    (mcp_ssh.PRESSURE_CMD,
     """for r in cpu io memory; do echo "== $r =="; cat /proc/pressure/$r 2>/dev/null || echo 'PSI not supported'; done"""),
    (mcp_ssh.LSBLK_CMD, "lsblk"),
    (mcp_ssh.SYSTEMD_FAILED_CMD, "systemctl list-units --state=failed --no-pager"),
])
def test_shared_command_values(value, expected):
    assert value == expected


# ============================================================
# vmstat_cmd
# ============================================================

def test_vmstat_cmd_default_is_the_tools_five_samples():
    assert mcp_ssh.vmstat_cmd() == "vmstat 1 5"


def test_vmstat_cmd_samples():
    assert mcp_ssh.vmstat_cmd(3) == "vmstat 1 3"


# ============================================================
# dmesg_cmd
# ============================================================

def test_dmesg_cmd_runs_as_root():
    assert mcp_ssh.dmesg_cmd() == mcp_ssh.AS_ROOT_PREFIX + "$AS_ROOT dmesg"


def test_dmesg_cmd_since_is_quoted():
    assert mcp_ssh.dmesg_cmd("2026-11-22 10:00") == mcp_ssh.AS_ROOT_PREFIX + "$AS_ROOT dmesg --since '2026-11-22 10:00'"


@pytest.mark.parametrize("since", ["1 hour ago", "today", "2026-11-22 10:00:00", "-30min"])
def test_dmesg_tool_sends_builder_output_for_since(since, mock_run_ssh_command):
    mcp_ssh.get_dmesg(host="h", user="u", since=since)
    assert mock_run_ssh_command.call_args[0][2] == mcp_ssh.dmesg_cmd(mcp_ssh.normalize_since(since))


def test_dmesg_tool_still_rejects_bad_since(mock_run_ssh_command):
    result = mcp_ssh.get_dmesg(host="h", user="u", since="tomorrow; rm -rf /")
    assert result == {"ok": False, "error": mcp_ssh.SINCE_ERROR}
    mock_run_ssh_command.assert_not_called()


# ============================================================
# journal_errors_cmd
# ============================================================

@pytest.mark.parametrize("args, expected", [
    ((200,), "journalctl -p warning -n 200 --no-pager"),
    ((20, True), "journalctl -p warning -n 20 --no-pager -b"),
    ((20, False, "-1h"), "journalctl -p warning -n 20 --no-pager --since -1h"),
    ((5, True, "2026-11-22 10:00"), "journalctl -p warning -n 5 --no-pager -b --since '2026-11-22 10:00'"),
])
def test_journal_errors_cmd(args, expected):
    assert mcp_ssh.journal_errors_cmd(*args) == expected


@pytest.mark.parametrize("kwargs", [
    {"lines": 20}, {"current_boot_only": True}, {"since": "1 hour ago"},
    {"lines": 5, "current_boot_only": True, "since": "2026-11-22 10:00"},
])
def test_journal_errors_tool_sends_builder_output(kwargs, mock_run_ssh_command):
    mcp_ssh.get_journal_errors(host="h", user="u", **kwargs)
    since = kwargs.get("since")
    expected = mcp_ssh.journal_errors_cmd(
        kwargs.get("lines", 200), kwargs.get("current_boot_only", False),
        mcp_ssh.normalize_since(since) if since else None,
    )
    assert mock_run_ssh_command.call_args[0][2] == expected


@pytest.mark.parametrize("kwargs, error", [
    # validation order is unchanged: lines, then current_boot_only, then since
    ({"lines": 0, "since": "bad"}, mcp_ssh.LINES_ERROR),
    ({"current_boot_only": "yes", "since": "bad"}, "Invalid value of current_boot_only, should be Boolean"),
    ({"since": "bad"}, mcp_ssh.SINCE_ERROR),
])
def test_journal_errors_tool_validation_order(kwargs, error, mock_run_ssh_command):
    assert mcp_ssh.get_journal_errors(host="h", user="u", **kwargs) == {"ok": False, "error": error}
    mock_run_ssh_command.assert_not_called()


# ============================================================
# timeout_wrapped: the one way commands are run on the remote host
# ============================================================

def test_timeout_wrapped_format():
    assert mcp_ssh.timeout_wrapped("echo 'a b'; ls", 17) == (
        "sh -c " + shlex.quote(mcp_ssh.TIMEOUT_SCRIPT) + """ 'echo '"'"'a b'"'"'; ls' 17"""
    )


def test_timeout_script_runs_the_launcher():
    assert mcp_ssh.TIMEOUT_SCRIPT.startswith("L=" + shlex.quote(mcp_ssh.SHELL_LAUNCHER) + "\n")


def test_run_cmd_uses_timeout_wrapped(mock_ssh_client):
    mcp_ssh._run_cmd(mock_ssh_client, "uptime; df -h", timeout_s=9)
    assert mock_ssh_client.exec_command.call_args[0][0] == mcp_ssh.timeout_wrapped("uptime; df -h", 9)


# The real runs below put fake tools on PATH. sh, bash and timeout are wrappers that say
# on stderr that they ran, then run the real thing, so a test can see which path ran.
# `timeout` is a fake GNU timeout (it only says so, and drops its duration): the real GNU
# behaviour is checked on live hosts. `setsid` is a real one, written in Python, because
# macOS has none.
FAKE_GNU_TIMEOUT = """echo "ran timeout $1 $2 $3" >&2
case "$1" in --version) echo 'timeout (GNU coreutils) 9.7'; exit 0 ;; esac
shift 3
exec "$@\""""
FAKE_SETSID = f"""#!{sys.executable}
import os, sys
os.setsid()
os.execvp(sys.argv[1], sys.argv[1:])
"""


def _wrapped_run(tmp_path, cmd, timeout_s=5, bash=True, gnu_timeout=False, setsid=True):
    """Runs timeout_wrapped(cmd) for real. Returns (CompletedProcess, seconds). The run is
    capped at 15 s: a wrapper that leaves the output open would otherwise hang the test."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    sh = shutil.which("sh")
    scripts = {"sh": f'echo "ran sh" >&2\nexec {sh} "$@"'}
    if bash:
        scripts["bash"] = f'echo "ran bash" >&2\nexec {shutil.which("bash")} "$@"'
    if gnu_timeout:
        scripts["timeout"] = FAKE_GNU_TIMEOUT
    for name, body in scripts.items():
        (bin_dir / name).write_text(f"#!{sh}\n{body}\n")
    if setsid:
        (bin_dir / "setsid").write_text(FAKE_SETSID)
    for f in bin_dir.iterdir():
        f.chmod(0o755)
    for tool in ("sleep", "cat"):
        (bin_dir / tool).symlink_to(shutil.which(tool))
    started = time.monotonic()
    result = subprocess.run([sh, "-c", mcp_ssh.timeout_wrapped(cmd, timeout_s)],
                            capture_output=True, text=True, env={"PATH": str(bin_dir)}, timeout=15)
    return result, time.monotonic() - started


def _unique_sleep():
    """A sleep whose command line is unique to this test, to look for it afterwards."""
    return f"sleep 30.{random.randrange(10**6):06d}"


def _still_running(pattern):
    ps = subprocess.run(["ps", "-axo", "args"], capture_output=True, text=True).stdout
    return [line for line in ps.splitlines() if line.startswith(pattern)]


def test_timeout_wrapped_runs_in_bash_when_present(tmp_path):
    result, _ = _wrapped_run(tmp_path, "set -o pipefail; false | true; echo rc=$?")
    # sh runs the wrapper, sh the launcher, the launcher runs the command in bash
    assert result.stderr.splitlines() == ["ran sh", "ran sh", "ran bash"]
    assert result.stdout == "rc=1\n"


def test_timeout_wrapped_falls_back_to_sh_without_bash(tmp_path):
    result, _ = _wrapped_run(tmp_path, "echo hello", bash=False)
    assert result.stderr.splitlines() == ["ran sh", "ran sh", "ran sh"]
    assert result.stdout == "hello\n"


def test_timeout_wrapped_keeps_quoting(tmp_path):
    result, _ = _wrapped_run(tmp_path, """printf '%s|' 'a b' "c 'd'" '$x'; echo""")
    assert result.stdout == "a b|c 'd'|$x|\n"


# ---- with GNU timeout: it is used, as before ----

def test_gnu_timeout_is_used_when_present(tmp_path):
    # (the `timeout --version` check runs too, with its stderr sent to /dev/null)
    result, _ = _wrapped_run(tmp_path, "echo hello", gnu_timeout=True)
    assert result.stderr.splitlines() == ["ran sh", "ran timeout -k 2 5s", "ran sh", "ran bash"]
    assert result.stdout == "hello\n"


# ---- without GNU timeout (BusyBox, or none at all): the watchdog ----

def test_watchdog_keeps_output_and_exit_code(tmp_path):
    result, seconds = _wrapped_run(tmp_path, "echo out; echo err >&2; exit 3")
    assert (result.returncode, result.stdout, result.stderr.splitlines()) == (3, "out\n", ["ran sh", "ran sh", "ran bash", "err"])
    assert seconds < 2


def test_watchdog_is_stopped_when_the_command_ends_first(tmp_path):
    result, _ = _wrapped_run(tmp_path, "true", timeout_s=7)
    assert result.returncode == 0
    time.sleep(0.3)
    assert _still_running("sleep 7") == []


def test_watchdog_stops_a_simple_command(tmp_path):
    sleep = _unique_sleep()
    result, seconds = _wrapped_run(tmp_path, f"echo start; {sleep}", timeout_s=1)
    assert (result.returncode, result.stdout) == (124, "start\n")
    assert seconds < 3
    assert _still_running(sleep) == []


@pytest.mark.parametrize("shape", ["{sleep} | cat", "echo start; {sleep} | cat", "{sleep} & wait"])
def test_watchdog_stops_the_whole_process_group(tmp_path, shape):
    # The BusyBox timeout case: the rest of the pipeline, or a background job, used to live
    # on and keep the output open. subprocess.run would then hang until its 15 s cap.
    sleep = _unique_sleep()
    result, seconds = _wrapped_run(tmp_path, shape.format(sleep=sleep), timeout_s=1)
    assert result.returncode == 124
    assert seconds < 3
    time.sleep(0.3)
    assert _still_running(sleep) == []


def test_watchdog_kills_what_ignores_term(tmp_path):
    sleep = _unique_sleep()
    result, seconds = _wrapped_run(tmp_path, f"trap '' TERM; {sleep} | cat", timeout_s=1)
    assert result.returncode == 124
    assert 2.5 < seconds < 5   # TERM at 1 s is ignored, KILL comes 2 s later
    time.sleep(0.3)
    assert _still_running(sleep) == []


def test_watchdog_does_not_report_other_signals_as_timeout(tmp_path):
    result, _ = _wrapped_run(tmp_path, "kill -KILL $$", bash=False, timeout_s=5)
    assert result.returncode == 137


def test_watchdog_without_setsid_still_stops_a_simple_command(tmp_path):
    sleep = _unique_sleep()
    result, seconds = _wrapped_run(tmp_path, sleep, timeout_s=1, setsid=False)
    assert result.returncode == 124
    assert seconds < 3
