"""Tests that every MCP tool handler passes the correct command to run_ssh_command."""
import pytest

import mcp_ssh


# ============================================================
# 18 simple tools — each is a thin wrapper around run_ssh_command
# ============================================================

@pytest.mark.parametrize("tool_func, expected_cmd", [
    (mcp_ssh.get_disk_free, "df -h"),
    (mcp_ssh.get_inode_usage, "df -i"),
    (mcp_ssh.get_dmesg, "dmesg"),
    (mcp_ssh.get_uptime, "uptime"),
    (mcp_ssh.get_current_datetime, "date"),
    (mcp_ssh.get_distroname_version, "cat /etc/os-release"),
    (mcp_ssh.get_kernel_version, "uname -srvm"),
    (mcp_ssh.get_systemd_list_all, "systemctl list-units --all --no-pager"),
    (mcp_ssh.get_systemd_list_failed, "systemctl list-units --state=failed --no-pager"),
    (mcp_ssh.get_systemd_list_timers, "systemctl list-timers --no-pager"),
    (mcp_ssh.get_ps_aux_top_cpu_consumers, "ps aux --sort=-%cpu | head -n 10"),
    (mcp_ssh.get_ps_aux_top_mem_consumers, "ps aux --sort=-%mem | head -n 10"),
    (mcp_ssh.get_free_memory, "free -h && echo && cat /proc/meminfo"),
    (mcp_ssh.get_memory_pressure, "cat /proc/pressure/memory 2>/dev/null || echo 'PSI not supported'"),
    (mcp_ssh.get_top, "top -b -n 1 -c"),
    (mcp_ssh.get_lsblk, "lsblk"),
    (mcp_ssh.get_docker_ps_all, "docker ps --all"),
    (mcp_ssh.get_docker_images, "docker images --digests"),
    (mcp_ssh.get_crontab_tasks, "crontab -l"),
    (mcp_ssh.get_listening_sockets, "ss -tulpn"),
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


# ============================================================
# get_sshd_effective_config — sshd -T with /usr/sbin fallback
# ============================================================

def test_sshd_effective_config_command_building(mock_run_ssh_command):
    mcp_ssh.get_sshd_effective_config(host="h", user="u")
    mock_run_ssh_command.assert_called_once()
    cmd = mock_run_ssh_command.call_args[0][2]
    assert '"$SSHD" -T' in cmd
    assert "/usr/sbin/sshd" in cmd


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
    assert "-name composer.lock" in cmd
    assert "-name package-lock.json" in cmd
    assert "-name 'requirements*.txt'" in cmd
    assert "-name node_modules" in cmd and "-prune" in cmd
    assert "-exec ls -l {} +" in cmd
    assert "head -c" not in cmd
    assert mock_run_ssh_command.call_args[1].get("success_exit_codes") == (0, 1)


def test_lockfiles_include_contents(mock_run_ssh_command):
    mcp_ssh.get_lockfiles(host="h", user="u", abs_paths=["/app"], include_contents=True, max_depth=2)
    cmd = mock_run_ssh_command.call_args[0][2]
    assert "-maxdepth 2 " in cmd
    assert "head -n 20" in cmd
    assert 'head -c 100000 "$f"' in cmd
