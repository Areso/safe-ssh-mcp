"""Tests that every MCP tool handler passes the correct command to run_ssh_command."""
import shutil
import subprocess

import pytest

import mcp_ssh


# ============================================================
# 18 simple tools — each is a thin wrapper around run_ssh_command
# ============================================================

@pytest.mark.parametrize("tool_func, expected_cmd", [
    (mcp_ssh.get_disk_free, "df -h"),
    (mcp_ssh.get_inode_usage, "df -i"),
    (mcp_ssh.get_dmesg, mcp_ssh.AS_ROOT_PREFIX + "$AS_ROOT dmesg"),
    (mcp_ssh.get_uptime, "uptime"),
    (mcp_ssh.get_current_datetime, "date"),
    (mcp_ssh.get_distroname_version, "cat /etc/os-release"),
    (mcp_ssh.get_kernel_version, "uname -srvm"),
    (mcp_ssh.get_hostname, mcp_ssh.HOSTNAME_CMD),
    (mcp_ssh.get_systemd_list_all, "systemctl list-units --all --no-pager"),
    (mcp_ssh.get_systemd_list_failed, "systemctl list-units --state=failed --no-pager"),
    (mcp_ssh.get_systemd_list_timers, "systemctl list-timers --no-pager"),
    (
        mcp_ssh.get_ps_aux_top_cpu_consumers,
        """set -o pipefail; if out=$(ps aux --sort=-%cpu 2>/dev/null); then printf '%s\\n' "$out" | awk 'NR <= 10'; """
        "else echo '# BusyBox: top -b -n 1, sorted by CPU usage at this moment'; "
        "top -b -n 1 | awk 'NR > 3 && NR <= 13'; fi",
    ),
    (
        mcp_ssh.get_ps_aux_top_mem_consumers,
        """set -o pipefail; if out=$(ps aux --sort=-%mem 2>/dev/null); then printf '%s\\n' "$out" | awk 'NR <= 10'; """
        "else echo '# BusyBox: ps -o pid,user,rss,vsz,args, sorted by RSS'; ps -o pid,user,rss,vsz,args | "
        """{ IFS= read -r header && printf '%s\\n' "$header"; """
        """awk '{v = $3 + 0; if ($3 ~ /m$/) v *= 1024; else if ($3 ~ /g$/) v *= 1048576; print v "\\t" $0}' """
        "| sort -n -r | awk 'NR <= 9' | cut -f 2-; }; fi",
    ),
    (mcp_ssh.get_free_memory, "free -h && echo && cat /proc/meminfo"),
    (mcp_ssh.get_memory_pressure, "cat /proc/pressure/memory 2>/dev/null || echo 'PSI not supported'"),
    (
        mcp_ssh.get_pressure,
        'for r in cpu io memory; do echo "== $r =="; '
        "cat /proc/pressure/$r 2>/dev/null || echo 'PSI not supported'; done",
    ),
    (mcp_ssh.get_vmstat, "vmstat 1 5"),
    (mcp_ssh.get_mounts, "if command -v findmnt >/dev/null 2>&1; then findmnt; else cat /proc/mounts; fi"),
    (
        mcp_ssh.get_top,
        """out=$(top -b -n 1 -c 2>&1); rc=$?; if [ "$rc" -eq 0 ]; then printf '%s\\n' "$out"; """
        "elif top --help 2>&1 | grep -q BusyBox; then echo '# BusyBox: top -b -n 1'; top -b -n 1; "
        """else printf '%s\\n' "$out" >&2; exit "$rc"; fi""",
    ),
    (mcp_ssh.get_lsblk, "lsblk"),
    (mcp_ssh.get_docker_ps_all, mcp_ssh.DOCKER_PREFIX + "$DOCKER ps --all"),
    (mcp_ssh.get_docker_images, mcp_ssh.DOCKER_PREFIX + "$DOCKER images --digests"),
    (mcp_ssh.get_crontab_tasks, "crontab -l"),
    (mcp_ssh.get_listening_sockets, mcp_ssh.LISTENING_SOCKETS_CMD),
])
def test_simple_tool_sends_correct_command(tool_func, expected_cmd, mock_run_ssh_command):
    tool_func(host="testhost", user="testuser")
    mock_run_ssh_command.assert_called_once()
    actual_cmd = mock_run_ssh_command.call_args[0][2]
    assert actual_cmd == expected_cmd


# ============================================================
# Simple tools — verify SSH args are forwarded correctly
# ============================================================

def test_tool_forwards_all_ssh_args(mock_run_ssh_command):
    mcp_ssh.get_uptime(
        host="myhost",
        user="myuser",
        port=2222,
        password="secret",
        key_path="/tmp/key",
        timeout=30,
        accept_new_hostkey=True,
    )
    args, kwargs = mock_run_ssh_command.call_args
    assert args[0] == "myhost"
    assert args[1] == "myuser"
    assert args[3] == 2222
    assert args[4] == "secret"
    assert args[5] == "/tmp/key"
    assert args[6] == 30
    assert args[7] is True


def test_tool_uses_default_args(mock_run_ssh_command):
    mcp_ssh.get_uptime(host="h", user="u")
    args, kwargs = mock_run_ssh_command.call_args
    assert args[3] == 22        # port
    assert args[4] is None      # password
    assert args[5] is None      # key_path
    assert args[7] is False     # accept_new_hostkey


# ============================================================
# get_disk_usage — command building (happy path)
# ============================================================

def test_disk_usage_command_building(mock_run_ssh_command):
    mcp_ssh.get_disk_usage(host="h", user="u", abs_path="/data")
    cmd = mock_run_ssh_command.call_args[0][2]
    assert cmd.startswith("find /data ")
    assert "-mindepth 1 -maxdepth 1" in cmd
    assert "-exec du -sh" in cmd
    assert "sort -rh" in cmd
    assert "head -n 20" in cmd


# ============================================================
# get_systemd_status — command building (happy path)
# ============================================================

def test_systemd_status_command_building(mock_run_ssh_command):
    mcp_ssh.get_systemd_status(daemon="nginx", host="h", user="u")
    cmd = mock_run_ssh_command.call_args[0][2]
    assert "systemctl status" in cmd
    assert "nginx" in cmd


# ============================================================
# get_service_logs_from_journalctl — command building (happy path)
# ============================================================

def test_journalctl_command_building(mock_run_ssh_command):
    mcp_ssh.get_service_logs_from_journalctl(service="sshd", host="h", user="u", lines=100)
    cmd = mock_run_ssh_command.call_args[0][2]
    assert "journalctl -xeu" in cmd
    assert "sshd" in cmd
    assert "-n 100" in cmd
    assert "--no-pager" in cmd


def test_journalctl_default_lines(mock_run_ssh_command):
    mcp_ssh.get_service_logs_from_journalctl(service="sshd", host="h", user="u")
    cmd = mock_run_ssh_command.call_args[0][2]
    assert "-n 200" in cmd


# ============================================================
# get_journal_errors — command building (happy path)
# ============================================================

def test_journal_errors_default_command(mock_run_ssh_command):
    mcp_ssh.get_journal_errors(host="h", user="u")
    cmd = mock_run_ssh_command.call_args[0][2]
    assert cmd == "journalctl -p warning -n 200 --no-pager"


def test_journal_errors_custom_lines(mock_run_ssh_command):
    mcp_ssh.get_journal_errors(host="h", user="u", lines=50)
    cmd = mock_run_ssh_command.call_args[0][2]
    assert "-n 50" in cmd


def test_journal_errors_current_boot_only(mock_run_ssh_command):
    mcp_ssh.get_journal_errors(host="h", user="u", current_boot_only=True)
    cmd = mock_run_ssh_command.call_args[0][2]
    assert cmd == "journalctl -p warning -n 200 --no-pager -b"


@pytest.mark.parametrize("lines", [0, -1, 1001, True, "200", 3.14])
def test_journal_errors_invalid_lines_rejected(lines, mock_run_ssh_command):
    result = mcp_ssh.get_journal_errors(host="h", user="u", lines=lines)
    assert result["ok"] is False
    mock_run_ssh_command.assert_not_called()


def test_journal_errors_non_bool_current_boot_rejected(mock_run_ssh_command):
    result = mcp_ssh.get_journal_errors(host="h", user="u", current_boot_only="yes")
    assert result["ok"] is False
    mock_run_ssh_command.assert_not_called()


# ============================================================
# get_last_logins / get_failed_logins — command building (happy path)
# ============================================================

LAST_CHECK = "if ! command -v last >/dev/null 2>&1; then echo 'last is not installed on this host' >&2; exit 127; fi; "
LASTB_CHECK = "if ! command -v lastb >/dev/null 2>&1; then echo 'lastb is not installed on this host' >&2; exit 127; fi; "


def test_last_logins_uses_last(mock_run_ssh_command):
    mcp_ssh.get_last_logins(host="h", user="u")
    cmd = mock_run_ssh_command.call_args[0][2]
    assert cmd == LAST_CHECK + (
        """out=$(last -F -n 50 2>&1); rc=$?; if [ "$rc" -eq 0 ]; then printf '%s\\n' "$out"; """
        "elif last --help 2>&1 | grep -q BusyBox; then echo '# BusyBox: last (short times without the year)'; "
        "set -o pipefail; last | awk 'NR <= 51'; "
        """else printf '%s\\n' "$out" >&2; exit "$rc"; fi"""
    )


def test_failed_logins_uses_lastb(mock_run_ssh_command):
    mcp_ssh.get_failed_logins(host="h", user="u", lines=10)
    cmd = mock_run_ssh_command.call_args[0][2]
    assert cmd == LASTB_CHECK + mcp_ssh.AS_ROOT_PREFIX + "$AS_ROOT lastb -F -n 10"


def test_last_logins_with_since(mock_run_ssh_command):
    mcp_ssh.get_last_logins(host="h", user="u", since="yesterday")
    cmd = mock_run_ssh_command.call_args[0][2]
    assert cmd == LAST_CHECK + (
        """out=$(last -F -n 50 --since yesterday 2>&1); rc=$?; if [ "$rc" -eq 0 ]; then printf '%s\\n' "$out"; """
        "elif last --help 2>&1 | grep -q BusyBox; then "
        "echo 'last on this host is the BusyBox one and cannot filter by time; call without since' >&2; exit 2; "
        """else printf '%s\\n' "$out" >&2; exit "$rc"; fi"""
    )


def test_failed_logins_with_since(mock_run_ssh_command):
    mcp_ssh.get_failed_logins(host="h", user="u", since="1 hour ago")
    cmd = mock_run_ssh_command.call_args[0][2]
    assert cmd == LASTB_CHECK + mcp_ssh.AS_ROOT_PREFIX + "$AS_ROOT lastb -F -n 50 --since -1h"


# ============================================================
# get_coredumps — command building (happy path)
# ============================================================

def test_coredumps_default_lists(mock_run_ssh_command):
    mcp_ssh.get_coredumps(host="h", user="u")
    cmd = mock_run_ssh_command.call_args[0][2]
    assert cmd == "set -o pipefail; coredumpctl list --no-pager" + tail_with_header(50)


def test_coredumps_list_with_pid_and_since(mock_run_ssh_command):
    mcp_ssh.get_coredumps(host="h", user="u", pid=1234, lines=5, since="2 hours ago")
    cmd = mock_run_ssh_command.call_args[0][2]
    assert cmd == "set -o pipefail; coredumpctl list --no-pager --since -2h 1234" + tail_with_header(5)


def test_coredumps_info_defaults_to_latest(mock_run_ssh_command):
    mcp_ssh.get_coredumps(host="h", user="u", command="info")
    cmd = mock_run_ssh_command.call_args[0][2]
    assert cmd == "coredumpctl info --no-pager -1"


def test_coredumps_info_for_pid(mock_run_ssh_command):
    mcp_ssh.get_coredumps(host="h", user="u", command="info", pid=1234)
    cmd = mock_run_ssh_command.call_args[0][2]
    assert cmd == "coredumpctl info --no-pager 1234"


# ==(========================================================
# get_list_of_files — command building (happy path)
# ==(========================================================

def test_list_files_command_building(mock_run_ssh_command):
    mcp_ssh.get_list_of_files(host="h", user="u", abs_path="/data")
    cmd = mock_run_ssh_command.call_args[0][2]
    assert cmd.startswith("ls /data ")
    assert "-lah" in cmd


def test_list_files_root_path(mock_run_ssh_command):
    mcp_ssh.get_list_of_files(host="h", user="u", abs_path="/")
    cmd = mock_run_ssh_command.call_args[0][2]
    assert cmd == "ls / -lah"


def test_list_files_default_path(mock_run_ssh_command):
    mcp_ssh.get_list_of_files(host="h", user="u")
    cmd = mock_run_ssh_command.call_args[0][2]
    assert cmd == "ls / -lah"


def test_list_files_quoted_path(mock_run_ssh_command):
    mcp_ssh.get_list_of_files(host="h", user="u", abs_path="/var/my dir")
    cmd = mock_run_ssh_command.call_args[0][2]
    assert "'/var/my dir'" in cmd


def test_list_files_success_exit_codes(mock_run_ssh_command):
    mcp_ssh.get_list_of_files(host="h", user="u", abs_path="/var")
    kwargs = mock_run_ssh_command.call_args[1]
    assert kwargs.get("success_exit_codes") == (0, 1)


# ==(========================================================
# get_list_of_files_with_filter — command building (happy path)
# ==(========================================================

def test_list_files_filter_command_building(mock_run_ssh_command):
    mcp_ssh.get_list_of_files_with_filter(host="h", user="u", abs_path="/data", filter=".log")
    cmd = mock_run_ssh_command.call_args[0][2]
    assert cmd.startswith("ls /data ")
    assert "-lah" in cmd
    assert "| grep" in cmd
    assert ".log" in cmd


def test_list_files_filter_root_path(mock_run_ssh_command):
    mcp_ssh.get_list_of_files_with_filter(host="h", user="u", abs_path="/", filter="etc")
    cmd = mock_run_ssh_command.call_args[0][2]
    assert "ls /" in cmd
    assert "| grep" in cmd


def test_list_files_filter_default_path(mock_run_ssh_command):
    mcp_ssh.get_list_of_files_with_filter(host="h", user="u", filter="test")
    cmd = mock_run_ssh_command.call_args[0][2]
    assert "ls /" in cmd


def test_list_files_filter_quoted_path_and_filter(mock_run_ssh_command):
    mcp_ssh.get_list_of_files_with_filter(host="h", user="u", abs_path="/var/my dir", filter="test file")
    cmd = mock_run_ssh_command.call_args[0][2]
    assert "'/var/my dir'" in cmd
    assert "'test file'" in cmd


def test_list_files_filter_success_exit_codes(mock_run_ssh_command):
    mcp_ssh.get_list_of_files_with_filter(host="h", user="u", abs_path="/var", filter="log")
    kwargs = mock_run_ssh_command.call_args[1]
    assert kwargs.get("success_exit_codes") == (0, 1)


def test_list_files_filter_empty_filter(mock_run_ssh_command):
    mcp_ssh.get_list_of_files_with_filter(host="h", user="u", abs_path="/data", filter="")
    mock_run_ssh_command.assert_called_once()


# ============================================================
# get_installed_packages — package manager detection chain
# ============================================================

def test_installed_packages_command_building(mock_run_ssh_command):
    mcp_ssh.get_installed_packages(host="h", user="u")
    mock_run_ssh_command.assert_called_once()
    cmd = mock_run_ssh_command.call_args[0][2]
    assert "dpkg-query -W" in cmd
    assert "rpm -qa" in cmd
    assert "apk info -v" in cmd
    # dpkg is preferred over rpm (rpm can be installed on Debian too), rpm over apk
    assert cmd.index("dpkg-query -W") < cmd.index("rpm -qa") < cmd.index("apk info -v")


# ============================================================
# get_libc_version — glibc / musl detection
# ============================================================

def test_libc_version_command_building(mock_run_ssh_command):
    mcp_ssh.get_libc_version(host="h", user="u")
    mock_run_ssh_command.assert_called_once()
    cmd = mock_run_ssh_command.call_args[0][2]
    assert "ls /lib/ld-musl-*" in cmd
    # musl's ldd writes the version to stderr
    assert "ldd --version 2>&1" in cmd

    assert mcp_ssh.LIBC_PACKAGE_MUSL_CMD in cmd
    assert mcp_ssh.LIBC_PACKAGE_GLIBC_CMD in cmd


def _run_libc_package_cmd(tmp_path, cmd, programs):
    """Runs cmd in bash with only the given fake programs (name -> script body) on PATH."""
    for name, body in programs.items():
        f = tmp_path / name
        f.write_text("#!/bin/sh\n" + body + "\n")
        f.chmod(0o755)
    return subprocess.run(
        ["/bin/bash", "-c", cmd], capture_output=True, text=True,
        env={"PATH": f"{tmp_path}:/usr/bin:/bin"},
    )


def test_libc_package_glibc_from_dpkg(tmp_path):
    result = _run_libc_package_cmd(tmp_path, mcp_ssh.LIBC_PACKAGE_GLIBC_CMD, {
        "dpkg-query": "echo 'package: libc6:amd64 2.39-0ubuntu8.9'",
        "rpm": "echo 'package glibc is not installed'; exit 1",
    })
    assert result.returncode == 0
    assert result.stdout == "package: libc6:amd64 2.39-0ubuntu8.9\n"


def test_libc_package_glibc_from_rpm_when_dpkg_missing(tmp_path):
    result = _run_libc_package_cmd(tmp_path, mcp_ssh.LIBC_PACKAGE_GLIBC_CMD, {
        "dpkg-query": "exit 127",
        "rpm": "echo 'package: glibc 2.34-289.el9'",
    })
    assert result.returncode == 0
    assert result.stdout == "package: glibc 2.34-289.el9\n"


def test_libc_package_glibc_prints_nothing_without_package_manager(tmp_path):
    result = _run_libc_package_cmd(tmp_path, mcp_ssh.LIBC_PACKAGE_GLIBC_CMD, {
        "dpkg-query": "exit 127",
        # rpm reports a missing package on stdout; it must not leak into the output
        "rpm": "echo 'package glibc is not installed'; exit 1",
    })
    assert result.returncode == 0
    assert result.stdout == ""


def test_libc_package_musl_from_apk(tmp_path):
    result = _run_libc_package_cmd(tmp_path, mcp_ssh.LIBC_PACKAGE_MUSL_CMD, {
        "apk": "echo musl-1.2.6-r3",
    })
    assert result.returncode == 0
    assert result.stdout == "package: musl 1.2.6-r3\n"


def test_libc_package_musl_prints_nothing_without_apk(tmp_path):
    result = _run_libc_package_cmd(tmp_path, mcp_ssh.LIBC_PACKAGE_MUSL_CMD, {
        "apk": "exit 127",
    })
    assert result.returncode == 0
    assert result.stdout == ""

# ============================================================
# get_hostname — uname -n with fallbacks, optional FQDN
# ============================================================

def _run_hostname_cmd(tmp_path, programs):
    """Runs the command with only the given fake programs (name -> script body) on PATH."""
    for name, body in programs.items():
        f = tmp_path / name
        f.write_text("#!/bin/sh\n" + body + "\n")
        f.chmod(0o755)
    return subprocess.run(
        ["/bin/bash", "-c", mcp_ssh.HOSTNAME_CMD], capture_output=True, text=True,
        env={"PATH": str(tmp_path)},
    )


FAKE_TIMEOUT = 'shift; exec "$@"'
FAKE_HOSTNAME = 'if [ "$1" = -f ]; then echo web1.example.com; else echo web1; fi'


def test_hostname_with_fqdn(tmp_path):
    result = _run_hostname_cmd(tmp_path, {
        "uname": "echo web1", "timeout": FAKE_TIMEOUT, "hostname": FAKE_HOSTNAME,
    })
    assert result.returncode == 0
    assert result.stdout == "hostname: web1\nfqdn: web1.example.com\n"


def test_hostname_without_hostname_program(tmp_path):
    result = _run_hostname_cmd(tmp_path, {"uname": "echo web1", "timeout": FAKE_TIMEOUT})
    assert result.returncode == 0
    assert result.stdout == "hostname: web1\n"
    assert result.stderr == ""


def test_hostname_fqdn_lookup_fails(tmp_path):
    result = _run_hostname_cmd(tmp_path, {
        "uname": "echo web1", "timeout": FAKE_TIMEOUT,
        "hostname": "echo 'hostname: Name or service not known' >&2; exit 1",
    })
    assert result.returncode == 0
    assert result.stdout == "hostname: web1\n"
    assert result.stderr == ""


def test_hostname_fqdn_lookup_times_out(tmp_path):
    result = _run_hostname_cmd(tmp_path, {
        "uname": "echo web1", "timeout": "exit 124", "hostname": FAKE_HOSTNAME,
    })
    assert result.returncode == 0
    assert result.stdout == "hostname: web1\n"


def test_hostname_falls_back_to_hostname_program(tmp_path):
    result = _run_hostname_cmd(tmp_path, {
        "uname": "exit 1", "cat": "exit 1", "timeout": FAKE_TIMEOUT, "hostname": FAKE_HOSTNAME,
    })
    assert result.returncode == 0
    assert result.stdout == "hostname: web1\nfqdn: web1.example.com\n"


def test_hostname_falls_back_to_proc(tmp_path):
    result = _run_hostname_cmd(tmp_path, {"uname": "exit 1", "cat": "echo web1"})
    assert result.returncode == 0
    assert result.stdout == "hostname: web1\n"


def test_hostname_nothing_works(tmp_path):
    result = _run_hostname_cmd(tmp_path, {})
    assert result.returncode == 1
    assert result.stdout == ""
    assert "could not read the hostname" in result.stderr

# ============================================================
# get_listening_sockets — ss, with a netstat fallback
# ============================================================

def _run_listening_sockets_cmd(tmp_path, programs, uid="0"):
    """Runs the command with only the given fake programs (name -> script body) on PATH."""
    programs = {"id": f"echo {uid}", **programs}
    for name, body in programs.items():
        f = tmp_path / name
        f.write_text("#!/bin/sh\n" + body + "\n")
        f.chmod(0o755)
    return subprocess.run(
        ["/bin/bash", "-c", mcp_ssh.LISTENING_SOCKETS_CMD], capture_output=True, text=True,
        env={"PATH": str(tmp_path)},
    )


SUDO_ALLOWED = 'shift; echo "via sudo: $*"'
SUDO_REFUSED = "echo 'sudo: a password is required' >&2; exit 1"
PLAIN_NOTE = mcp_ssh.LISTENING_SOCKETS_PLAIN_NOTE + "\n"


def test_listening_sockets_root_uses_ss_directly(tmp_path):
    result = _run_listening_sockets_cmd(tmp_path, {
        "ss": 'echo "ss $*"', "netstat": 'echo "netstat $*"', "sudo": SUDO_ALLOWED,
    })
    assert result.returncode == 0
    assert result.stdout == "ss -tulpn\n"


def test_listening_sockets_root_falls_back_to_netstat(tmp_path):
    result = _run_listening_sockets_cmd(tmp_path, {"netstat": 'echo "netstat $*"'})
    assert result.returncode == 0
    assert result.stdout == "# ss is not installed: netstat -tulnp\nnetstat -tulnp\n"


def test_listening_sockets_non_root_goes_through_sudo(tmp_path):
    result = _run_listening_sockets_cmd(tmp_path, {
        "ss": 'echo "ss $*"', "sudo": SUDO_ALLOWED,
    }, uid="1000")
    assert result.returncode == 0
    assert result.stdout == "via sudo: ss -tulpn\n"


def test_listening_sockets_non_root_netstat_goes_through_doas(tmp_path):
    result = _run_listening_sockets_cmd(tmp_path, {
        "netstat": 'echo "netstat $*"', "doas": 'shift; echo "via doas: $*"',
    }, uid="1000")
    assert result.returncode == 0
    assert result.stdout == "# ss is not installed: netstat -tulnp\nvia doas: netstat -tulnp\n"


def test_listening_sockets_sudo_refused_runs_plain_with_note(tmp_path):
    result = _run_listening_sockets_cmd(tmp_path, {
        "ss": 'echo "ss $*"', "sudo": SUDO_REFUSED,
    }, uid="1000")
    assert result.returncode == 0
    assert result.stdout == PLAIN_NOTE + "ss -tulpn\n"
    assert "password is required" not in result.stderr


def test_listening_sockets_no_sudo_or_doas_runs_plain_with_note(tmp_path):
    result = _run_listening_sockets_cmd(tmp_path, {"ss": 'echo "ss $*"'}, uid="1000")
    assert result.returncode == 0
    assert result.stdout == PLAIN_NOTE + "ss -tulpn\n"


def test_listening_sockets_ss_failure_is_not_hidden_by_fallback(tmp_path):
    result = _run_listening_sockets_cmd(tmp_path, {
        "ss": "echo 'ss: boom' >&2; exit 3",
        "netstat": 'echo "netstat $*"',
    })
    assert result.returncode == 3
    assert result.stdout == ""
    assert "ss: boom" in result.stderr


def test_listening_sockets_neither_installed(tmp_path):
    result = _run_listening_sockets_cmd(tmp_path, {})
    assert result.returncode == 127
    assert result.stdout == ""
    assert "neither ss nor netstat is installed on this host" in result.stderr

# ============================================================
# get_sshd_effective_config — sshd -T with /usr/sbin fallback
# ============================================================

def test_sshd_effective_config_command_building(mock_run_ssh_command):
    mcp_ssh.get_sshd_effective_config(host="h", user="u")
    mock_run_ssh_command.assert_called_once()
    cmd = mock_run_ssh_command.call_args[0][2]
    assert cmd == (
        "SSHD=$(command -v sshd || echo /usr/sbin/sshd); " + mcp_ssh.AS_ROOT_PREFIX + '$AS_ROOT "$SSHD" -T'
    )


# ============================================================
# get_ps_aux_top_* — BusyBox fallback, run in local bash with a fake ps/top
# ============================================================

BUSYBOX_PS = """#!/bin/sh
case "$*" in
  *--sort*) echo "ps: unrecognized option: sort" >&2; exit 1 ;;
esac
cat <<'OUT'
PID   USER     RSS  VSZ  COMMAND
    1 root      900 1636 /sbin/init
   10 app      1.5g 2.1g java -jar big.jar
   11 app       12m  40m nginx: worker
   12 app      5312 7300 sshd-session: alpine [priv]
    2 root        0    0 [kthreadd]
OUT
"""

BUSYBOX_TOP = """#!/bin/sh
cat <<'OUT'
Mem: 142504K used, 337108K free, 3244K shrd, 9056K buff, 53856K cached
CPU:   0% usr   0% sys   0% nic 100% idle   0% io   0% irq   0% sirq
Load average: 0.00 0.00 0.00 2/88 3284
  PID  PPID USER     STAT   VSZ %VSZ CPU %CPU COMMAND
 2649  2647 alpine   S     7608   2%   0   3% sshd-session: alpine@pts/0
    1     0 root     S     1636   0%   0   0% /sbin/init
OUT
"""

PROCPS_PS = """#!/bin/sh
echo "USER PID %CPU %MEM COMMAND"
# long enough to overflow a pipe buffer: cutting the rows must not end in SIGPIPE
i=0; while [ $i -lt 3000 ]; do echo "root $i 0.0 0.0 proc$i --a-rather-long-argument-list-to-fill-the-pipe"; i=$((i+1)); done
"""


def run_with_fake_bin(tmp_path, cmd, scripts):
    """Runs cmd in local bash with the given fake programs placed first on PATH."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name, body in scripts.items():
        (bin_dir / name).write_text(body)
        (bin_dir / name).chmod(0o755)
    return subprocess.run(
        ["bash", "-c", cmd], capture_output=True, text=True,
        env={"PATH": f"{bin_dir}:/usr/bin:/bin"},
    )


def test_ps_top_cpu_falls_back_to_busybox_top(tmp_path):
    res = run_with_fake_bin(tmp_path, mcp_ssh.PS_TOP_CPU_CMD, {"ps": BUSYBOX_PS, "top": BUSYBOX_TOP})
    assert res.returncode == 0
    assert res.stdout.splitlines() == [
        "# BusyBox: top -b -n 1, sorted by CPU usage at this moment",
        "  PID  PPID USER     STAT   VSZ %VSZ CPU %CPU COMMAND",
        " 2649  2647 alpine   S     7608   2%   0   3% sshd-session: alpine@pts/0",
        "    1     0 root     S     1636   0%   0   0% /sbin/init",
    ]


def test_ps_top_mem_falls_back_to_busybox_ps_sorted_by_rss(tmp_path):
    res = run_with_fake_bin(tmp_path, mcp_ssh.PS_TOP_MEM_CMD, {"ps": BUSYBOX_PS})
    assert res.returncode == 0
    assert res.stdout.splitlines() == [
        "# BusyBox: ps -o pid,user,rss,vsz,args, sorted by RSS",
        "PID   USER     RSS  VSZ  COMMAND",
        "   10 app      1.5g 2.1g java -jar big.jar",
        "   11 app       12m  40m nginx: worker",
        "   12 app      5312 7300 sshd-session: alpine [priv]",
        "    1 root      900 1636 /sbin/init",
        "    2 root        0    0 [kthreadd]",
    ]


@pytest.mark.parametrize("cmd", [mcp_ssh.PS_TOP_CPU_CMD, mcp_ssh.PS_TOP_MEM_CMD])
def test_ps_top_uses_procps_when_it_works(tmp_path, cmd):
    res = run_with_fake_bin(tmp_path, cmd, {"ps": PROCPS_PS})
    assert res.returncode == 0
    lines = res.stdout.splitlines()
    assert lines[0] == "USER PID %CPU %MEM COMMAND"
    assert len(lines) == 10


def test_ps_top_cpu_reports_failure_when_fallback_also_fails(tmp_path):
    failing_top = "#!/bin/sh\necho 'top: broken' >&2\nexit 1\n"
    res = run_with_fake_bin(tmp_path, mcp_ssh.PS_TOP_CPU_CMD, {"ps": BUSYBOX_PS, "top": failing_top})
    assert res.returncode != 0
    assert "top: broken" in res.stderr


# ============================================================
# docker_cmd — direct when the daemon is reachable, else sudo -n / doas -n
# ============================================================

def test_docker_prefix_text():
    assert mcp_ssh.DOCKER_PREFIX == (
        "if ! command -v docker >/dev/null 2>&1; then "
        "echo 'docker is not installed on this host' >&2; exit 127; fi; "
        "DOCKER=docker; if ! docker version >/dev/null 2>&1; then "
        'AS_ROOT=; if [ "$(id -u)" != 0 ]; then '
        "if command -v sudo >/dev/null 2>&1; then AS_ROOT='sudo -n'; "
        "elif command -v doas >/dev/null 2>&1; then AS_ROOT='doas -n'; fi; fi; "
        'DOCKER="$AS_ROOT docker"; fi; '
    )


# a docker whose daemon refuses this user, unless FAKE_ROOT is set (by the fake sudo/doas)
FAKE_DOCKER = """#!/bin/sh
if [ "$DOCKER_GROUP" = 1 ] || [ "$FAKE_ROOT" = 1 ]; then echo "docker $* (root=${FAKE_ROOT:-0})"; exit 0; fi
echo "permission denied while trying to connect to the docker API" >&2; exit 1
"""
FAKE_ESCALATE = '#!/bin/sh\n[ "$1" = -n ] && shift\nFAKE_ROOT=1 exec "$@"\n'
FAKE_ID = "#!/bin/sh\necho 1000\n"


def run_docker_cmd(tmp_path, scripts, docker_group="0"):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name, body in scripts.items():
        (bin_dir / name).write_text(body)
        (bin_dir / name).chmod(0o755)
    # the fake bin dir is the whole PATH, so the real sudo/docker are never found
    return subprocess.run(
        [shutil.which("bash"), "-c", mcp_ssh.docker_cmd("ps --all")], capture_output=True, text=True,
        env={"PATH": str(bin_dir), "DOCKER_GROUP": docker_group},
    )


@pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")
@pytest.mark.parametrize("helpers, docker_group, expected", [
    (["sudo", "doas"], "1", "docker ps --all (root=0)"),   # daemon reachable: no escalation
    (["sudo", "doas"], "0", "docker ps --all (root=1)"),   # sudo -n
    (["doas"], "0", "docker ps --all (root=1)"),           # doas -n (Alpine)
])
def test_docker_cmd_in_bash(tmp_path, helpers, docker_group, expected):
    scripts = {"docker": FAKE_DOCKER, "id": FAKE_ID, **{h: FAKE_ESCALATE for h in helpers}}
    res = run_docker_cmd(tmp_path, scripts, docker_group)
    assert (res.returncode, res.stdout.strip(), res.stderr) == (0, expected, "")


@pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")
def test_docker_cmd_without_access_or_escalation_shows_docker_error(tmp_path):
    res = run_docker_cmd(tmp_path, {"docker": FAKE_DOCKER, "id": FAKE_ID})
    assert res.returncode == 1
    assert "permission denied while trying to connect to the docker API" in res.stderr


@pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")
def test_docker_cmd_reports_missing_docker(tmp_path):
    res = run_docker_cmd(tmp_path, {"id": FAKE_ID})
    assert (res.returncode, res.stdout, res.stderr) == (127, "", "docker is not installed on this host\n")


# ============================================================
# busybox_fallback — run in local bash with a fake program
# ============================================================

FAKE_BUSYBOX_TOOL = """#!/bin/sh
case "$1" in
  --help) echo "BusyBox v1.37.0 multi-call binary." >&2; exit 1 ;;
  "") i=0; echo "HEADER"; while [ $i -lt 5 ]; do echo "row$i"; i=$((i+1)); done ;;
  *) echo "tool: unrecognized option" >&2; exit 1 ;;
esac
"""

FAKE_FULL_TOOL = """#!/bin/sh
case "$1" in
  --help) echo "Usage: tool [options]" ;;
  --bad) echo "tool: real failure" >&2; exit 3 ;;
  *) echo "full output $*" ;;
esac
"""


def test_busybox_fallback_runs_fallback_on_busybox(tmp_path):
    cmd = mcp_ssh.busybox_fallback("tool -x", "tool", "echo '# BusyBox'; tool | awk 'NR <= 3'")
    res = run_with_fake_bin(tmp_path, cmd, {"tool": FAKE_BUSYBOX_TOOL})
    assert res.returncode == 0
    assert res.stdout.splitlines() == ["# BusyBox", "HEADER", "row0", "row1"]
    assert res.stderr == ""


def test_busybox_fallback_keeps_normal_output(tmp_path):
    cmd = mcp_ssh.busybox_fallback("tool -x", "tool", "echo fallback")
    res = run_with_fake_bin(tmp_path, cmd, {"tool": FAKE_FULL_TOOL})
    assert (res.returncode, res.stdout, res.stderr) == (0, "full output -x\n", "")


def test_busybox_fallback_passes_real_failure_through(tmp_path):
    cmd = mcp_ssh.busybox_fallback("tool --bad", "tool", "echo fallback")
    res = run_with_fake_bin(tmp_path, cmd, {"tool": FAKE_FULL_TOOL})
    assert (res.returncode, res.stdout, res.stderr) == (3, "", "tool: real failure\n")


# ============================================================
# as_root — sudo -n / doas -n for the few tools that need root
# ============================================================

def test_last_logins_does_not_escalate(mock_run_ssh_command):
    mcp_ssh.get_last_logins(host="h", user="u")
    assert "AS_ROOT" not in mock_run_ssh_command.call_args[0][2]


def run_as_root_in_bash(tmp_path, uid, helpers):
    """Runs as_root('echo hi there') in local bash with a fake id and fake sudo/doas on PATH."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    scripts = {"id": f"#!/bin/sh\necho {uid}\n"}
    for helper in helpers:
        scripts[helper] = f'#!/bin/sh\necho "{helper} $*"\n'
    for name, body in scripts.items():
        (bin_dir / name).write_text(body)
        (bin_dir / name).chmod(0o755)
    bash = shutil.which("bash")
    # only the fake bin dir is on PATH, so the real sudo is never found; echo is a builtin
    return subprocess.run(
        [bash, "-c", mcp_ssh.as_root("echo hi there")],
        capture_output=True, text=True, check=True, env={"PATH": str(bin_dir)},
    ).stdout.strip()


@pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")
@pytest.mark.parametrize("uid, helpers, expected", [
    (0, ["sudo", "doas"], "hi there"),            # already root: no escalation
    (1000, ["sudo", "doas"], "sudo -n echo hi there"),
    (1000, ["doas"], "doas -n echo hi there"),    # Alpine
    (1000, [], "hi there"),                       # neither: runs as the login user
])
def test_as_root_in_bash(tmp_path, uid, helpers, expected):
    assert run_as_root_in_bash(tmp_path, uid, helpers) == expected


# ============================================================
# get_php_info — CLI / CGI / FPM detection
# ============================================================

def test_php_info_command_building(mock_run_ssh_command):
    mcp_ssh.get_php_info(host="h", user="u")
    mock_run_ssh_command.assert_called_once()
    cmd = mock_run_ssh_command.call_args[0][2]
    assert "php -v" in cmd
    assert "PHP_SAPI" in cmd
    assert "/usr/bin/php-cgi*" in cmd
    assert "/usr/sbin/php-fpm*" in cmd
    assert "pgrep -a" in cmd


def test_php_info_checks_mod_php(mock_run_ssh_command):
    mcp_ssh.get_php_info(host="h", user="u")
    cmd = mock_run_ssh_command.call_args[0][2]
    assert "command -v apache2 || command -v httpd" in cmd
    assert "/etc/apache2/mods-enabled/*.load" in cmd
    assert "/etc/httpd/conf.modules.d/*.conf" in cmd
    assert "apachectl -M" in cmd


# ============================================================
# get_lockfiles — command building
# ============================================================

def test_lockfiles_command_building(mock_run_ssh_command):
    mcp_ssh.get_lockfiles(host="h", user="u", abs_paths=["/var/www/app", "/srv/my app"])
    cmd = mock_run_ssh_command.call_args[0][2]
    assert cmd.startswith("find /var/www/app '/srv/my app' -maxdepth 4 ")
    assert (
        r"\( -name node_modules -o -name vendor -o -name .git -o -name venv -o -name .venv \) -prune -o "
        r"-type f \( -name composer.lock -o -name package-lock.json -o -name yarn.lock -o -name pnpm-lock.yaml "
        r"-o -name 'requirements*.txt' -o -name poetry.lock -o -name uv.lock -o -name Pipfile.lock "
        r"-o -name Gemfile.lock -o -name go.sum -o -name Cargo.lock \)"
    ) in cmd
    assert "-exec ls -l {} +" in cmd
    assert "head -c" not in cmd
    assert mock_run_ssh_command.call_args[1].get("success_exit_codes") == (0, 1)


def test_lockfiles_include_contents(mock_run_ssh_command):
    mcp_ssh.get_lockfiles(host="h", user="u", abs_paths=["/app"], include_contents=True, max_depth=2)
    cmd = mock_run_ssh_command.call_args[0][2]
    assert "-maxdepth 2 " in cmd
    assert "head -n 20" in cmd
    # whole file or a 'skipped' line, never a cut-off file
    assert "head -c" not in cmd
    assert 'cat "$f"' in cmd
    assert '[ "$size" -gt 5000000 ]' in cmd
    assert "[ $((total + size)) -gt 10000000 ]" in cmd


@pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")
def test_lockfiles_contents_are_whole_or_skipped_in_bash(mock_run_ssh_command, tmp_path, monkeypatch):
    monkeypatch.setattr(mcp_ssh, "LOCKFILE_MAX_BYTES_PER_FILE", 100)
    monkeypatch.setattr(mcp_ssh, "LOCKFILE_MAX_BYTES_TOTAL", 150)
    for name, size in (("a/go.sum", 80), ("b/Cargo.lock", 80), ("c/uv.lock", 101), ("d/yarn.lock", 60)):
        (tmp_path / name).parent.mkdir()
        (tmp_path / name).write_text(name[0] * size)
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "yarn.lock").write_text("pruned")
    (tmp_path / "notes.txt").write_text("not a lockfile")

    mcp_ssh.get_lockfiles(host="h", user="u", abs_paths=[str(tmp_path)], include_contents=True)
    cmd = mock_run_ssh_command.call_args[0][2]
    out = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True, check=True).stdout

    blocks = {}
    for block in out.split("===== ")[1:]:
        header, _, body = block.partition(" =====\n")
        blocks[header.split(" ", 1)[0].rsplit("/", 1)[1]] = (header.split(" ", 1)[1], body.strip())
    assert set(blocks) == {"go.sum", "Cargo.lock", "uv.lock", "yarn.lock"}
    assert blocks["uv.lock"] == ("(skipped: 101 bytes, over the 100 byte per-file limit)", "")
    # every other file is either complete or skipped with its size, never partial
    sizes = {"go.sum": ("a", 80), "Cargo.lock": ("b", 80), "yarn.lock": ("d", 60)}
    whole = 0
    for name, (char, size) in sizes.items():
        note, body = blocks[name]
        if note == f"({size} bytes)":
            assert body == char * size
            whole += size
        else:
            assert note == f"(skipped: {size} bytes, would exceed the 150 byte total limit)"
            assert body == ""
    assert 0 < whole <= 150


# ============================================================
# get_docker_logs / get_docker_stats / get_docker_inspect — command building
# ============================================================

def test_docker_logs_default_command(mock_run_ssh_command):
    mcp_ssh.get_docker_logs(container="web", host="h", user="u")
    cmd = mock_run_ssh_command.call_args[0][2]
    assert cmd == mcp_ssh.DOCKER_PREFIX + "$DOCKER logs --tail 200 web 2>&1"


def test_docker_logs_by_id_with_lines_and_since(mock_run_ssh_command):
    mcp_ssh.get_docker_logs(container="0123456789ab", host="h", user="u", lines=50, since="30 min ago")
    cmd = mock_run_ssh_command.call_args[0][2]
    assert cmd == mcp_ssh.DOCKER_PREFIX + "$DOCKER logs --tail 50 --since 30m 0123456789ab 2>&1"


def test_docker_logs_absolute_since_is_rfc3339(mock_run_ssh_command):
    mcp_ssh.get_docker_logs(container="web", host="h", user="u", since="2026-11-10 14:00")
    cmd = mock_run_ssh_command.call_args[0][2]
    assert "--since 2026-11-10T14:00:00 " in cmd


def test_docker_stats_command(mock_run_ssh_command):
    mcp_ssh.get_docker_stats(host="h", user="u")
    cmd = mock_run_ssh_command.call_args[0][2]
    assert cmd == mcp_ssh.DOCKER_PREFIX + "$DOCKER stats --no-stream"


def test_docker_inspect_command(mock_run_ssh_command):
    mcp_ssh.get_docker_inspect(container="web_1", host="h", user="u")
    cmd = mock_run_ssh_command.call_args[0][2]
    assert cmd.startswith(mcp_ssh.DOCKER_PREFIX + "$DOCKER inspect --type container --format '")
    assert cmd.endswith("' web_1")
    assert "{{json .State}}" in cmd


def test_docker_inspect_never_exposes_env(mock_run_ssh_command):
    mcp_ssh.get_docker_inspect(container="web", host="h", user="u")
    cmd = mock_run_ssh_command.call_args[0][2]
    assert "Env" not in cmd
    assert "{{json .Config}}" not in cmd
    assert "{{json .}}" not in cmd


# ============================================================
# kubectl tools — command building
# ============================================================

def test_kubectl_logs_default_command(mock_run_ssh_command):
    mcp_ssh.get_kubectl_logs(pod="web-7d4b9c-x2x", host="h", user="u")
    cmd = mock_run_ssh_command.call_args[0][2]
    assert cmd == "kubectl logs --tail=200 --namespace=default web-7d4b9c-x2x"


def test_kubectl_logs_all_options(mock_run_ssh_command):
    mcp_ssh.get_kubectl_logs(
        pod="web-0", host="h", user="u", namespace="prod", container="app",
        previous=True, lines=50, since="30 min ago",
    )
    cmd = mock_run_ssh_command.call_args[0][2]
    assert cmd == "kubectl logs --tail=50 --namespace=prod --container=app --previous --since=30m web-0"


def test_kubectl_logs_absolute_since_uses_since_time(mock_run_ssh_command):
    mcp_ssh.get_kubectl_logs(pod="web-0", host="h", user="u", since="2026-11-10T14:00:00Z")
    cmd = mock_run_ssh_command.call_args[0][2]
    assert "--since-time=2026-11-10T14:00:00Z" in cmd
    assert "--since=" not in cmd


def test_kubectl_describe_command(mock_run_ssh_command):
    mcp_ssh.get_kubectl_describe(resource_type="pod", name="web-0", host="h", user="u", namespace="prod")
    cmd = mock_run_ssh_command.call_args[0][2]
    assert cmd == "kubectl describe pod web-0 --namespace=prod"


@pytest.mark.parametrize("resource_type, expected", [
    ("po", "pod"), ("Pods", "pod"), ("deploy", "deployment"), ("svc", "service"),
    ("ingresses", "ingress"), ("node", "node"), ("pvc", "persistentvolumeclaim"), (" hpa ", "horizontalpodautoscaler"),
])
def test_kubectl_describe_resource_type_aliases(resource_type, expected, mock_run_ssh_command):
    mcp_ssh.get_kubectl_describe(resource_type=resource_type, name="x1", host="h", user="u")
    cmd = mock_run_ssh_command.call_args[0][2]
    assert cmd == f"kubectl describe {expected} x1 --namespace=default"


def test_kubectl_events_default_all_namespaces(mock_run_ssh_command):
    mcp_ssh.get_kubectl_events(host="h", user="u")
    cmd = mock_run_ssh_command.call_args[0][2]
    assert cmd == (
        "set -o pipefail; kubectl get events --sort-by=.lastTimestamp --all-namespaces" + tail_with_header(200)
    )


def test_kubectl_events_namespace_and_warnings(mock_run_ssh_command):
    mcp_ssh.get_kubectl_events(host="h", user="u", namespace="prod", warnings_only=True, lines=20)
    cmd = mock_run_ssh_command.call_args[0][2]
    assert cmd == (
        "set -o pipefail; kubectl get events --sort-by=.lastTimestamp --namespace=prod "
        "--field-selector=type=Warning" + tail_with_header(20)
    )


# ============================================================
# crictl tools — command building
# ============================================================

@pytest.mark.parametrize("tool_func, expected_cmd", [
    (mcp_ssh.get_crictl_ps, "crictl ps --all"),
    (mcp_ssh.get_crictl_images, "crictl images"),
    (mcp_ssh.get_crictl_imagefsinfo, "crictl imagefsinfo"),
])
def test_crictl_simple_tools(tool_func, expected_cmd, mock_run_ssh_command):
    tool_func(host="h", user="u")
    assert mock_run_ssh_command.call_args[0][2] == expected_cmd


def test_crictl_logs_default_command(mock_run_ssh_command):
    mcp_ssh.get_crictl_logs(container_id="0123456789abc", host="h", user="u")
    cmd = mock_run_ssh_command.call_args[0][2]
    assert cmd == "crictl logs --tail=200 0123456789abc 2>&1"


def test_crictl_logs_with_lines_and_since(mock_run_ssh_command):
    mcp_ssh.get_crictl_logs(container_id="0123456789abc", host="h", user="u", lines=10, since="2 hours ago")
    cmd = mock_run_ssh_command.call_args[0][2]
    assert cmd == "crictl logs --tail=10 --since=2h 0123456789abc 2>&1"


def _ssh_result(stdout, exit_code=0, stderr=""):
    return {
        "ok": exit_code == 0,
        "host": "testhost",
        "collected_at_utc": "2025-01-01T00:00:00+00:00",
        "data": {"command": "test", "exit_code": exit_code, "stdout": stdout, "stderr": stderr},
    }


CRICTL_INSPECT_JSON = """{
  "status": {"id": "0123456789abc", "state": "CONTAINER_RUNNING", "exitCode": 0},
  "info": {
    "config": {"envs": [{"key": "DB_PASSWORD", "value": "hunter2"}]},
    "runtimeSpec": {"process": {"env": ["PATH=/usr/bin", "API_TOKEN=s3cr3t=="], "args": ["app"]}}
  }
}"""


def test_crictl_inspect_command_and_redaction(mock_run_ssh_command):
    mock_run_ssh_command.return_value = _ssh_result(CRICTL_INSPECT_JSON)
    result = mcp_ssh.get_crictl_inspect(container_id="0123456789abc", host="h", user="u")
    assert mock_run_ssh_command.call_args[0][2] == "crictl inspect --output json 0123456789abc"
    assert result["ok"] is True
    stdout = result["data"]["stdout"]
    assert "hunter2" not in stdout and "s3cr3t" not in stdout and "/usr/bin" not in stdout
    parsed = mcp_ssh.json.loads(stdout)
    assert parsed["status"]["state"] == "CONTAINER_RUNNING"
    assert parsed["info"]["config"]["envs"] == [{"key": "DB_PASSWORD", "value": "<redacted>"}]
    assert parsed["info"]["runtimeSpec"]["process"]["env"] == ["PATH=<redacted>", "API_TOKEN=<redacted>"]
    assert parsed["info"]["runtimeSpec"]["process"]["args"] == ["app"]


def test_crictl_inspect_image_command_and_redaction(mock_run_ssh_command):
    mock_run_ssh_command.return_value = _ssh_result(
        '{"status": {"repoTags": ["nginx:1.27"]}, "info": {"imageSpec": {"config": {"Env": ["NPM_TOKEN=abc"]}}}}'
    )
    result = mcp_ssh.get_crictl_inspect_image(image="registry.k8s.io/pause:3.9", host="h", user="u")
    assert mock_run_ssh_command.call_args[0][2] == "crictl inspecti --output json registry.k8s.io/pause:3.9"
    parsed = mcp_ssh.json.loads(result["data"]["stdout"])
    assert parsed["status"]["repoTags"] == ["nginx:1.27"]
    assert parsed["info"]["imageSpec"]["config"]["Env"] == ["NPM_TOKEN=<redacted>"]


@pytest.mark.parametrize("tool_func, kwargs", [
    (mcp_ssh.get_crictl_inspect, {"container_id": "0123456789abc"}),
    (mcp_ssh.get_crictl_inspect_image, {"image": "nginx"}),
])
def test_crictl_inspect_unparseable_output_is_dropped(tool_func, kwargs, mock_run_ssh_command):
    mock_run_ssh_command.return_value = _ssh_result("env: SECRET=hunter2 (not json)")
    result = tool_func(host="h", user="u", **kwargs)
    assert result["ok"] is False
    assert result["data"]["stdout"] == ""
    assert "hunter2" not in str(result)


def test_crictl_inspect_failure_passes_stderr_through(mock_run_ssh_command):
    mock_run_ssh_command.return_value = _ssh_result("", exit_code=1, stderr="container not found")
    result = mcp_ssh.get_crictl_inspect(container_id="0123456789abc", host="h", user="u")
    assert result["ok"] is False
    assert result["data"]["stderr"] == "container not found"


def test_crictl_inspect_connection_error_passes_through(mock_run_ssh_command):
    mock_run_ssh_command.return_value = {"ok": False, "error": "Network error"}
    result = mcp_ssh.get_crictl_inspect(container_id="0123456789abc", host="h", user="u")
    assert result == {"ok": False, "error": "Network error"}


# ============================================================
# get_ip_addr / get_ip_route — command building
# ============================================================

def test_ip_addr_command(mock_run_ssh_command):
    mcp_ssh.get_ip_addr(host="h", user="u")
    assert mock_run_ssh_command.call_args[0][2] == "ip addr show"


def test_ip_route_covers_ipv4_and_ipv6(mock_run_ssh_command):
    mcp_ssh.get_ip_route(host="h", user="u")
    cmd = mock_run_ssh_command.call_args[0][2]
    assert cmd == "echo '== IPv4 =='; ip route show; echo '== IPv6 =='; ip -6 route show"


# ============================================================
# get_dns_lookup — command building
# ============================================================

RESOLV_CONF_PREFIX = "echo '== /etc/resolv.conf =='; cat /etc/resolv.conf; echo; "


def test_dns_lookup_default_uses_getent_ahosts(mock_run_ssh_command):
    mcp_ssh.get_dns_lookup(name="example.com", host="h", user="u")
    cmd = mock_run_ssh_command.call_args[0][2]
    assert cmd == RESOLV_CONF_PREFIX + (
        "echo '== getent ahosts example.com =='; getent ahosts example.com; rc=$?; "
        '[ "$rc" -eq 0 ] || echo "not resolved (getent exit code $rc)"; exit "$rc"'
    )


@pytest.mark.parametrize("address", ["192.0.2.10", "2001:db8::1"])
def test_dns_lookup_ip_uses_getent_hosts(address, mock_run_ssh_command):
    mcp_ssh.get_dns_lookup(name=address, host="h", user="u")
    cmd = mock_run_ssh_command.call_args[0][2]
    assert f"; getent hosts {address}; rc=$?" in cmd
    assert "ahosts" not in cmd


def test_dns_lookup_dig_checks_availability_first(mock_run_ssh_command):
    mcp_ssh.get_dns_lookup(name="example.com", host="h", user="u", use_dig=True)
    cmd = mock_run_ssh_command.call_args[0][2]
    assert cmd == RESOLV_CONF_PREFIX + (
        "echo '== dig +time=2 +tries=2 example.com A =='; "
        "if ! command -v dig >/dev/null 2>&1; then "
        "echo 'dig is not installed on this host, call again with use_dig=False' >&2; exit 127; fi; "
        "dig +time=2 +tries=2 example.com A"
    )
    assert "getent" not in cmd
    assert "+short" not in cmd


def test_dns_lookup_dig_reverse_for_ip(mock_run_ssh_command):
    mcp_ssh.get_dns_lookup(name="192.0.2.10", host="h", user="u", use_dig=True)
    cmd = mock_run_ssh_command.call_args[0][2]
    assert cmd.endswith("fi; dig +time=2 +tries=2 -x 192.0.2.10")


@pytest.mark.parametrize("record_type, expected", [("MX", "MX"), ("txt", "TXT"), (" aaaa ", "AAAA"), ("A", "A")])
def test_dns_lookup_dig_record_type(record_type, expected, mock_run_ssh_command):
    mcp_ssh.get_dns_lookup(name="example.com", host="h", user="u", use_dig=True, record_type=record_type)
    cmd = mock_run_ssh_command.call_args[0][2]
    assert cmd.endswith(f"fi; dig +time=2 +tries=2 example.com {expected}")


@pytest.mark.parametrize("server", ["8.8.8.8", "2001:4860:4860::8888", "ns1.example.com"])
def test_dns_lookup_dig_server(server, mock_run_ssh_command):
    mcp_ssh.get_dns_lookup(name="example.com", host="h", user="u", use_dig=True, record_type="NS", server=server)
    cmd = mock_run_ssh_command.call_args[0][2]
    assert cmd.endswith(f"fi; dig +time=2 +tries=2 @{server} example.com NS")
    assert f"echo '== dig +time=2 +tries=2 @{server} example.com NS =='" in cmd


@pytest.mark.parametrize("record_type", ["A", "PTR", "ptr"])
def test_dns_lookup_dig_reverse_with_server(record_type, mock_run_ssh_command):
    mcp_ssh.get_dns_lookup(
        name="192.0.2.10", host="h", user="u", use_dig=True, record_type=record_type, server="8.8.8.8"
    )
    cmd = mock_run_ssh_command.call_args[0][2]
    assert cmd.endswith("fi; dig +time=2 +tries=2 @8.8.8.8 -x 192.0.2.10")


# ============================================================
# check_tcp_connect — command building
# ============================================================

NC_CHECK_PREFIX = (
    "if ! command -v nc >/dev/null 2>&1; then "
    "echo 'nc is not installed on this host' >&2; exit 127; fi; "
)


@pytest.mark.parametrize("target_host", ["db.internal", "192.0.2.10", "2001:db8::1", "::1"])
def test_tcp_connect_command(target_host, mock_run_ssh_command):
    mcp_ssh.check_tcp_connect(target_host=target_host, target_port=5432, host="h", user="u")
    cmd = mock_run_ssh_command.call_args[0][2]
    assert cmd == NC_CHECK_PREFIX + f"nc -vz -w 3 {target_host} 5432"


def test_tcp_connect_target_is_not_the_ssh_connection(mock_run_ssh_command):
    mcp_ssh.check_tcp_connect(target_host="db.internal", target_port=5432, host="h", user="u", port=2222)
    args = mock_run_ssh_command.call_args[0]
    assert args[0] == "h"
    assert args[3] == 2222
    assert args[2].endswith("nc -vz -w 3 db.internal 5432")


# ============================================================
# tail_keeping_header — the header row survives the tail
# ============================================================

def tail_with_header(lines):
    """The pipe that tail_keeping_header appends to a command."""
    return " | { IFS= read -r header && printf '%s\\n' \"$header\"; tail -n " + str(lines) + "; }"


def test_tail_keeping_header_command():
    assert mcp_ssh.tail_keeping_header("some cmd", 7) == "set -o pipefail; some cmd" + tail_with_header(7)


def run_in_bash(cmd):
    return subprocess.run(["bash", "-c", cmd], capture_output=True, text=True, timeout=10)


@pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")
class TestTailKeepingHeaderInBash:
    """Runs the generated command in a local bash, the same shell run_ssh_command uses remotely."""

    def test_more_rows_than_lines_keeps_header_and_last_rows(self):
        result = run_in_bash(mcp_ssh.tail_keeping_header("printf 'HEADER\\n1\\n2\\n3\\n4\\n5\\n'", 2))
        assert result.stdout == "HEADER\n4\n5\n"
        assert result.returncode == 0

    def test_fewer_rows_than_lines_returns_everything_once(self):
        result = run_in_bash(mcp_ssh.tail_keeping_header("printf 'HEADER\\n1\\n2\\n'", 50))
        assert result.stdout == "HEADER\n1\n2\n"

    def test_header_only(self):
        result = run_in_bash(mcp_ssh.tail_keeping_header("printf 'HEADER\\n'", 50))
        assert result.stdout == "HEADER\n"

    def test_header_whitespace_and_backslashes_preserved(self):
        result = run_in_bash(mcp_ssh.tail_keeping_header("printf '%s\\n' '  TIME   PID \\x  ' 'row'", 5))
        assert result.stdout == "  TIME   PID \\x  \nrow\n"

    def test_no_output_prints_nothing_and_keeps_exit_code(self):
        result = run_in_bash(mcp_ssh.tail_keeping_header("sh -c 'echo \"No coredumps found.\" >&2; exit 1'", 50))
        assert result.stdout == ""
        assert result.returncode == 1

    def test_missing_command_keeps_exit_code_127(self):
        result = run_in_bash(mcp_ssh.tail_keeping_header("no_such_command_xyz list", 50))
        assert result.stdout == ""
        assert result.returncode == 127

    def test_failure_after_output_keeps_exit_code(self):
        result = run_in_bash(mcp_ssh.tail_keeping_header("sh -c 'printf \"HEADER\\n1\\n\"; exit 3'", 50))
        assert result.stdout == "HEADER\n1\n"
        assert result.returncode == 3


# ============================================================
# get_installed_packages — dpkg lists only installed packages
# ============================================================

def test_installed_packages_dpkg_command(mock_run_ssh_command):
    mcp_ssh.get_installed_packages(host="h", user="u")
    cmd = mock_run_ssh_command.call_args[0][2]
    assert cmd.startswith(
        "set -o pipefail; if command -v dpkg-query >/dev/null 2>&1; then "
        "echo '# dpkg, tab-separated: package version architecture status source_package source_version'; "
    )
    assert (
        r"dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${db:Status-Abbrev}"
        r"\t${source:Package}\t${source:Version}\n' | "
        r"""awk -F'\t' 'substr($4, 2, 1) == "i"'; elif"""
    ) in cmd


def test_installed_packages_apk_reads_database_for_origin(mock_run_ssh_command):
    mcp_ssh.get_installed_packages(host="h", user="u")
    cmd = mock_run_ssh_command.call_args[0][2]
    assert (
        "elif [ -r /lib/apk/db/installed ]; then "
        "echo '# apk, tab-separated: package version architecture origin'; awk '"
    ) in cmd
    assert "' /lib/apk/db/installed; elif command -v apk" in cmd
    # the database is preferred; apk info -v (no origin) is only the fallback
    assert cmd.index("/lib/apk/db/installed") < cmd.index("apk info -v")


needs_bash_and_awk = pytest.mark.skipif(
    shutil.which("bash") is None or shutil.which("awk") is None, reason="needs bash and awk"
)


@needs_bash_and_awk
def test_dpkg_installed_filter_drops_removed_packages():
    rows = [
        "bash\t5.2.15-2+b2\tamd64\tii \tbash\t5.2.15-2",
        "nginx-common\t1.26.3-3+deb13u10\tall\trc \tnginx\t1.26.3-3+deb13u10",  # removed, config left
        "linux-image-amd64\t6.1.90-1\tamd64\thi \tlinux-signed-amd64\t6.1.90+1",  # held, but installed
        "broken\t1.0\tamd64\tiH \tbroken\t1.0",
        "unpacked-only\t2.0\tamd64\tiU \tunpacked-only\t2.0",
        "half-configured\t2.0\tamd64\tiF \thalf-configured\t2.0",
        "openssh-server\t1:9.2p1-2+deb12u3\tamd64\tii \topenssh\t1:9.2p1-2+deb12u3",
        "reinst-required\t3.0\tamd64\tiiR\treinst-required\t3.0",
    ]
    result = subprocess.run(
        ["bash", "-c", mcp_ssh.DPKG_INSTALLED_FILTER],
        input="\n".join(rows) + "\n", capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 0
    assert result.stdout.splitlines() == [rows[0], rows[2], rows[6], rows[7]]


APK_DB_SAMPLE = """C:Q1abcdefghijklmnopqrstuvwxyz0=
P:libcrypto3
V:3.3.2-r1
A:x86_64
S:1789456
I:4734976
T:Crypto library from openssl
U:https://www.openssl.org/
L:Apache-2.0
o:openssl
m:Natanael Copa <ncopa@alpinelinux.org>
t:1725386894
c:1234567890abcdef
D:so:libc.musl-x86_64.so.1
p:so:libcrypto.so.3=3
F:usr/lib
R:libcrypto.so.3
a:0:0:755
Z:Q1abcdefghijklmnopqrstuvwxyz0=

C:Q1zyxwvutsrqponmlkjihgfedcba0=
P:musl
V:1.2.5-r0
A:x86_64
o:musl
F:lib
R:ld-musl-x86_64.so.1

C:Q1zzzzzzzzzzzzzzzzzzzzzzzzzz0=
P:busybox-binsh
V:1.36.1-r29
A:x86_64
o:busybox
"""


@needs_bash_and_awk
@pytest.mark.parametrize("database", [APK_DB_SAMPLE, APK_DB_SAMPLE + "\n"])
def test_apk_database_to_tsv(database):
    """The last record is printed whether or not the file ends with an empty line."""
    result = subprocess.run(
        ["bash", "-c", mcp_ssh.APK_DB_TO_TSV],
        input=database, capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 0
    assert result.stdout == (
        "libcrypto3\t3.3.2-r1\tx86_64\topenssl\n"
        "musl\t1.2.5-r0\tx86_64\tmusl\n"
        "busybox-binsh\t1.36.1-r29\tx86_64\tbusybox\n"
    )
