"""Tests for input validation in tools with user-supplied parameters."""
import pytest

import mcp_ssh


# ============================================================
# get_disk_usage — path validation
# ============================================================

class TestDiskUsagePathValidation:
    """Validate abs_path parameter of get_disk_usage."""

    def test_non_string_path_rejected(self, mock_run_ssh_command):
        result = mcp_ssh.get_disk_usage(host="h", user="u", abs_path=123)
        assert result == {"ok": False, "error": "Path must be a string"}
        mock_run_ssh_command.assert_not_called()

    def test_relative_path_rejected(self, mock_run_ssh_command):
        result = mcp_ssh.get_disk_usage(host="h", user="u", abs_path="var/log")
        assert result == {"ok": False, "error": "Path must be absolute"}
        mock_run_ssh_command.assert_not_called()

    @pytest.mark.parametrize("char", ["|", "&", ";", "<", ">", "(", ")", "$", "`", "{", "}"])
    def test_forbidden_char_rejected(self, char, mock_run_ssh_command):
        result = mcp_ssh.get_disk_usage(host="h", user="u", abs_path=f"/tmp/{char}evil")
        assert result["ok"] is False
        assert "forbidden characters" in result["error"]
        mock_run_ssh_command.assert_not_called()

    def test_valid_absolute_path(self, mock_run_ssh_command):
        mcp_ssh.get_disk_usage(host="h", user="u", abs_path="/var/log")
        mock_run_ssh_command.assert_called_once()
        cmd = mock_run_ssh_command.call_args[0][2]
        assert "/var/log" in cmd

    def test_root_path(self, mock_run_ssh_command):
        mcp_ssh.get_disk_usage(host="h", user="u", abs_path="/")
        mock_run_ssh_command.assert_called_once()

    def test_path_normalization(self, mock_run_ssh_command):
        mcp_ssh.get_disk_usage(host="h", user="u", abs_path="/var/../var/log")
        cmd = mock_run_ssh_command.call_args[0][2]
        assert "/var/log" in cmd

    def test_path_with_spaces(self, mock_run_ssh_command):
        mcp_ssh.get_disk_usage(host="h", user="u", abs_path="/var/my dir")
        cmd = mock_run_ssh_command.call_args[0][2]
        assert "'/var/my dir'" in cmd

    def test_success_result_contains_path_key(self, mock_run_ssh_command):
        mock_run_ssh_command.return_value = {
            "ok": True, "host": "h", "collected_at_utc": "t",
            "data": {"command": "x", "exit_code": 0, "stdout": "", "stderr": ""},
        }
        result = mcp_ssh.get_disk_usage(host="h", user="u", abs_path="/var")
        assert result["path"] == "/var"

    def test_failure_result_has_no_path_key(self, mock_run_ssh_command):
        mock_run_ssh_command.return_value = {"ok": False, "error": "boom"}
        result = mcp_ssh.get_disk_usage(host="h", user="u", abs_path="/var")
        assert "path" not in result

    def test_passes_success_exit_codes_0_1(self, mock_run_ssh_command):
        mcp_ssh.get_disk_usage(host="h", user="u", abs_path="/var")
        kwargs = mock_run_ssh_command.call_args[1]
        assert kwargs.get("success_exit_codes") == (0, 1)

    def test_command_uses_find_du_sort_head(self, mock_run_ssh_command):
        mcp_ssh.get_disk_usage(host="h", user="u", abs_path="/data")
        cmd = mock_run_ssh_command.call_args[0][2]
        assert cmd.startswith("find ")
        assert "du -sh" in cmd
        assert "sort -rh" in cmd
        assert "head -n 20" in cmd


# ============================================================
# get_systemd_status — daemon name validation
# ============================================================

class TestSystemdStatusValidation:
    """Validate daemon parameter of get_systemd_status."""

    def test_valid_daemon_nginx(self, mock_run_ssh_command):
        mcp_ssh.get_systemd_status(daemon="nginx", host="h", user="u")
        cmd = mock_run_ssh_command.call_args[0][2]
        assert cmd == "systemctl status 'nginx'" or cmd == "systemctl status nginx"

    def test_valid_daemon_with_dot(self, mock_run_ssh_command):
        mcp_ssh.get_systemd_status(daemon="sshd.service", host="h", user="u")
        mock_run_ssh_command.assert_called_once()

    def test_valid_daemon_with_at(self, mock_run_ssh_command):
        mcp_ssh.get_systemd_status(daemon="user@1000", host="h", user="u")
        mock_run_ssh_command.assert_called_once()

    def test_valid_daemon_with_colon(self, mock_run_ssh_command):
        mcp_ssh.get_systemd_status(daemon="dbus-org.freedesktop:slot1", host="h", user="u")
        mock_run_ssh_command.assert_called_once()

    def test_injection_semicolon_rejected(self, mock_run_ssh_command):
        result = mcp_ssh.get_systemd_status(daemon="nginx; rm -rf /", host="h", user="u")
        assert result["ok"] is False
        assert "Invalid daemon name" in result["error"]
        mock_run_ssh_command.assert_not_called()

    def test_empty_string_rejected(self, mock_run_ssh_command):
        result = mcp_ssh.get_systemd_status(daemon="", host="h", user="u")
        assert result["ok"] is False
        mock_run_ssh_command.assert_not_called()

    def test_space_rejected(self, mock_run_ssh_command):
        result = mcp_ssh.get_systemd_status(daemon="nginx service", host="h", user="u")
        assert result["ok"] is False
        mock_run_ssh_command.assert_not_called()

    def test_pipe_rejected(self, mock_run_ssh_command):
        result = mcp_ssh.get_systemd_status(daemon="nginx|cat", host="h", user="u")
        assert result["ok"] is False
        mock_run_ssh_command.assert_not_called()

    def test_fstring_bug_error_contains_literal_daemon(self, mock_run_ssh_command):
        """Document the f-string bug: error returns literal '{daemon}' not the value."""
        result = mcp_ssh.get_systemd_status(daemon="bad input!", host="h", user="u")
        assert result["ok"] is False
        # BUG: the error message uses a non-f-string, so it contains the literal '{daemon}'
        assert "bad input!" in result["error"]


# ============================================================
# get_service_logs_from_journalctl — service + lines validation
# ============================================================

class TestJournalctlValidation:
    """Validate service and lines parameters of get_service_logs_from_journalctl."""

    # -- service name --

    def test_valid_service(self, mock_run_ssh_command):
        mcp_ssh.get_service_logs_from_journalctl(service="nginx", host="h", user="u", lines=50)
        cmd = mock_run_ssh_command.call_args[0][2]
        assert "journalctl" in cmd
        assert "'nginx'" in cmd or "nginx" in cmd
        assert "-n 50" in cmd

    def test_service_injection_rejected(self, mock_run_ssh_command):
        result = mcp_ssh.get_service_logs_from_journalctl(
            service="nginx; cat /etc/shadow", host="h", user="u"
        )
        assert result["ok"] is False
        assert "Invalid service name" in result["error"]
        mock_run_ssh_command.assert_not_called()

    def test_service_empty_rejected(self, mock_run_ssh_command):
        result = mcp_ssh.get_service_logs_from_journalctl(service="", host="h", user="u")
        assert result["ok"] is False
        mock_run_ssh_command.assert_not_called()

    def test_fstring_bug_error_contains_literal_service(self, mock_run_ssh_command):
        """Document the f-string bug: error returns literal '{service}' not the value."""
        result = mcp_ssh.get_service_logs_from_journalctl(service="bad!", host="h", user="u")
        assert result["ok"] is False
        assert "'{service}'" in result["error"]

    # -- lines parameter --

    def test_lines_zero_rejected(self, mock_run_ssh_command):
        result = mcp_ssh.get_service_logs_from_journalctl(service="nginx", host="h", user="u", lines=0)
        assert result["ok"] is False
        assert "Integer from 1 to 1000" in result["error"]

    def test_lines_negative_rejected(self, mock_run_ssh_command):
        result = mcp_ssh.get_service_logs_from_journalctl(service="nginx", host="h", user="u", lines=-1)
        assert result["ok"] is False

    def test_lines_1001_rejected(self, mock_run_ssh_command):
        result = mcp_ssh.get_service_logs_from_journalctl(service="nginx", host="h", user="u", lines=1001)
        assert result["ok"] is False

    def test_lines_true_rejected(self, mock_run_ssh_command):
        result = mcp_ssh.get_service_logs_from_journalctl(service="nginx", host="h", user="u", lines=True)
        assert result["ok"] is False

    def test_lines_false_rejected(self, mock_run_ssh_command):
        result = mcp_ssh.get_service_logs_from_journalctl(service="nginx", host="h", user="u", lines=False)
        assert result["ok"] is False

    def test_lines_string_rejected(self, mock_run_ssh_command):
        result = mcp_ssh.get_service_logs_from_journalctl(service="nginx", host="h", user="u", lines="200")
        assert result["ok"] is False

    def test_lines_float_rejected(self, mock_run_ssh_command):
        result = mcp_ssh.get_service_logs_from_journalctl(service="nginx", host="h", user="u", lines=3.14)
        assert result["ok"] is False

    def test_lines_boundary_1_accepted(self, mock_run_ssh_command):
        mcp_ssh.get_service_logs_from_journalctl(service="nginx", host="h", user="u", lines=1)
        cmd = mock_run_ssh_command.call_args[0][2]
        assert "-n 1 " in cmd

    def test_lines_boundary_1000_accepted(self, mock_run_ssh_command):
        mcp_ssh.get_service_logs_from_journalctl(service="nginx", host="h", user="u", lines=1000)
        cmd = mock_run_ssh_command.call_args[0][2]
        assert "-n 1000 " in cmd
