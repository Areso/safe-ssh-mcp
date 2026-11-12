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
        result = mcp_ssh.get_systemd_status(daemon="bad input!", host="h", user="u")
        assert result["ok"] is False
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
        result = mcp_ssh.get_service_logs_from_journalctl(service="bad input!", host="h", user="u")
        assert result["ok"] is False
        assert "bad input!" in result["error"]

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


# ============================================================
# get_list_of_files — path validation
# ============================================================

class TestListFilesPathValidation:
    """Validate abs_path parameter of get_list_of_files."""

    def test_non_string_path_rejected(self, mock_run_ssh_command):
        result = mcp_ssh.get_list_of_files(host="h", user="u", abs_path=123)
        assert result == {"ok": False, "error": "Path must be a string"}
        mock_run_ssh_command.assert_not_called()

    def test_relative_path_rejected(self, mock_run_ssh_command):
        result = mcp_ssh.get_list_of_files(host="h", user="u", abs_path="var/log")
        assert result == {"ok": False, "error": "Path must be absolute"}
        mock_run_ssh_command.assert_not_called()

    @pytest.mark.parametrize("char", ["|", "&", ";", "<", ">", "(", ")", "$", "`", "{", "}"])
    def test_forbidden_char_rejected(self, char, mock_run_ssh_command):
        result = mcp_ssh.get_list_of_files(host="h", user="u", abs_path=f"/tmp/{char}evil")
        assert result["ok"] is False
        assert "forbidden characters" in result["error"]
        mock_run_ssh_command.assert_not_called()

    def test_valid_absolute_path(self, mock_run_ssh_command):
        mcp_ssh.get_list_of_files(host="h", user="u", abs_path="/var/log")
        mock_run_ssh_command.assert_called_once()
        cmd = mock_run_ssh_command.call_args[0][2]
        assert "/var/log" in cmd

    def test_root_path(self, mock_run_ssh_command):
        mcp_ssh.get_list_of_files(host="h", user="u", abs_path="/")
        mock_run_ssh_command.assert_called_once()

    def test_path_normalization(self, mock_run_ssh_command):
        mcp_ssh.get_list_of_files(host="h", user="u", abs_path="/var/../var/log")
        cmd = mock_run_ssh_command.call_args[0][2]
        assert "/var/log" in cmd

    def test_path_with_spaces(self, mock_run_ssh_command):
        mcp_ssh.get_list_of_files(host="h", user="u", abs_path="/var/my dir")
        cmd = mock_run_ssh_command.call_args[0][2]
        assert "'/var/my dir'" in cmd

    def test_success_result_contains_path_key(self, mock_run_ssh_command):
        mock_run_ssh_command.return_value = {
            "ok": True, "host": "h", "collected_at_utc": "t",
            "data": {"command": "x", "exit_code": 0, "stdout": "", "stderr": ""},
        }
        result = mcp_ssh.get_list_of_files(host="h", user="u", abs_path="/var")
        assert result["path"] == "/var"

    def test_failure_result_has_no_path_key(self, mock_run_ssh_command):
        mock_run_ssh_command.return_value = {"ok": False, "error": "boom"}
        result = mcp_ssh.get_list_of_files(host="h", user="u", abs_path="/var")
        assert "path" not in result

    def test_passes_success_exit_codes_0_1(self, mock_run_ssh_command):
        mcp_ssh.get_list_of_files(host="h", user="u", abs_path="/var")
        kwargs = mock_run_ssh_command.call_args[1]
        assert kwargs.get("success_exit_codes") == (0, 1)


# ============================================================
# get_list_of_files_with_filter — path + filter validation
# ============================================================

class TestListFilesWithFilterValidation:
    """Validate abs_path and filter parameters of get_list_of_files_with_filter."""

    # -- abs_path validation (mirrors get_list_of_files) --

    def test_non_string_path_rejected(self, mock_run_ssh_command):
        result = mcp_ssh.get_list_of_files_with_filter(host="h", user="u", abs_path=123)
        assert result == {"ok": False, "error": "Path must be a string"}
        mock_run_ssh_command.assert_not_called()

    def test_relative_path_rejected(self, mock_run_ssh_command):
        result = mcp_ssh.get_list_of_files_with_filter(host="h", user="u", abs_path="var/log")
        assert result == {"ok": False, "error": "Path must be absolute"}
        mock_run_ssh_command.assert_not_called()

    @pytest.mark.parametrize("char", ["|", "&", ";", "<", ">", "(", ")", "$", "`", "{", "}"])
    def test_path_forbidden_char_rejected(self, char, mock_run_ssh_command):
        result = mcp_ssh.get_list_of_files_with_filter(host="h", user="u", abs_path=f"/tmp/{char}evil", filter="log")
        assert result["ok"] is False
        assert "forbidden characters" in result["error"]
        mock_run_ssh_command.assert_not_called()

    def test_valid_absolute_path(self, mock_run_ssh_command):
        mcp_ssh.get_list_of_files_with_filter(host="h", user="u", abs_path="/var/log", filter=".log")
        mock_run_ssh_command.assert_called_once()
        cmd = mock_run_ssh_command.call_args[0][2]
        assert "/var/log" in cmd

    def test_root_path(self, mock_run_ssh_command):
        mcp_ssh.get_list_of_files_with_filter(host="h", user="u", abs_path="/", filter="etc")
        mock_run_ssh_command.assert_called_once()

    def test_path_normalization(self, mock_run_ssh_command):
        mcp_ssh.get_list_of_files_with_filter(host="h", user="u", abs_path="/var/../var/log", filter="*.log")
        cmd = mock_run_ssh_command.call_args[0][2]
        assert "/var/log" in cmd

    def test_path_with_spaces(self, mock_run_ssh_command):
        mcp_ssh.get_list_of_files_with_filter(host="h", user="u", abs_path="/var/my dir", filter="test")
        cmd = mock_run_ssh_command.call_args[0][2]
        assert "'/var/my dir'" in cmd

    def test_success_result_contains_path_key(self, mock_run_ssh_command):
        mock_run_ssh_command.return_value = {
            "ok": True, "host": "h", "collected_at_utc": "t",
            "data": {"command": "x", "exit_code": 0, "stdout": "", "stderr": ""},
        }
        result = mcp_ssh.get_list_of_files_with_filter(host="h", user="u", abs_path="/var", filter="log")
        assert result["path"] == "/var"

    def test_failure_result_has_no_path_key(self, mock_run_ssh_command):
        mock_run_ssh_command.return_value = {"ok": False, "error": "boom"}
        result = mcp_ssh.get_list_of_files_with_filter(host="h", user="u", abs_path="/var", filter="log")
        assert "path" not in result

    def test_passes_success_exit_codes_0_1(self, mock_run_ssh_command):
        mcp_ssh.get_list_of_files_with_filter(host="h", user="u", abs_path="/var", filter="log")
        kwargs = mock_run_ssh_command.call_args[1]
        assert kwargs.get("success_exit_codes") == (0, 1)

    # -- filter validation --

    def test_non_string_filter_rejected(self, mock_run_ssh_command):
        result = mcp_ssh.get_list_of_files_with_filter(host="h", user="u", abs_path="/", filter=123)
        assert result == {"ok": False, "error": "Filter must be a string"}
        mock_run_ssh_command.assert_not_called()

    @pytest.mark.parametrize("char", ["|", "&", ";", "<", ">", "(", ")", "$", "`", "{", "}"])
    def test_filter_forbidden_char_rejected(self, char, mock_run_ssh_command):
        result = mcp_ssh.get_list_of_files_with_filter(host="h", user="u", abs_path="/", filter=f"log{char}evil")
        assert result["ok"] is False
        assert "forbidden characters" in result["error"]
        mock_run_ssh_command.assert_not_called()

    def test_empty_filter_accepted(self, mock_run_ssh_command):
        mcp_ssh.get_list_of_files_with_filter(host="h", user="u", abs_path="/", filter="")
        mock_run_ssh_command.assert_called_once()

    def test_filter_is_quoted_in_command(self, mock_run_ssh_command):
        mcp_ssh.get_list_of_files_with_filter(host="h", user="u", abs_path="/var/log", filter="test file")
        cmd = mock_run_ssh_command.call_args[0][2]
        assert "'test file'" in cmd

    def test_command_contains_ls_and_grep(self, mock_run_ssh_command):
        mcp_ssh.get_list_of_files_with_filter(host="h", user="u", abs_path="/data", filter="\\.txt")
        cmd = mock_run_ssh_command.call_args[0][2]
        assert cmd.startswith("ls ")
        assert "-lah" in cmd
        assert "| grep" in cmd


# ============================================================
# get_lockfiles — input validation
# ============================================================

class TestLockfilesValidation:
    @pytest.mark.parametrize("abs_paths", [[], "/app", None, ["/a"] * 11])
    def test_bad_path_list_rejected(self, abs_paths, mock_run_ssh_command):
        result = mcp_ssh.get_lockfiles(host="h", user="u", abs_paths=abs_paths)
        assert result["ok"] is False
        mock_run_ssh_command.assert_not_called()

    def test_relative_path_rejected(self, mock_run_ssh_command):
        result = mcp_ssh.get_lockfiles(host="h", user="u", abs_paths=["/ok", "relative/app"])
        assert result["ok"] is False
        assert "absolute" in result["error"]
        mock_run_ssh_command.assert_not_called()

    @pytest.mark.parametrize("char", list("|&;<>()$`{}"))
    def test_forbidden_char_rejected(self, char, mock_run_ssh_command):
        result = mcp_ssh.get_lockfiles(host="h", user="u", abs_paths=[f"/app{char}x"])
        assert result["ok"] is False
        assert "forbidden characters" in result["error"]
        mock_run_ssh_command.assert_not_called()

    @pytest.mark.parametrize("max_depth", [0, 11, True, "3"])
    def test_bad_max_depth_rejected(self, max_depth, mock_run_ssh_command):
        result = mcp_ssh.get_lockfiles(host="h", user="u", abs_paths=["/app"], max_depth=max_depth)
        assert result["ok"] is False
        mock_run_ssh_command.assert_not_called()

    def test_path_normalized(self, mock_run_ssh_command):
        result = mcp_ssh.get_lockfiles(host="h", user="u", abs_paths=["/var/www/../app/"])
        assert result["paths"] == ["/var/app"]


# ============================================================
# normalize_since — shared `since` validator
# ============================================================

class TestNormalizeSince:
    @pytest.mark.parametrize("value, expected", [
        ("30 min ago", "-30min"),
        ("30min ago", "-30min"),
        ("2 hours ago", "-2h"),
        ("1 hour ago", "-1h"),
        ("-15min", "-15min"),
        ("-1d", "-1d"),
        ("- 3 days", "-3d"),
        ("45 seconds ago", "-45s"),
        ("5 m ago", "-5min"),
        ("2 weeks ago", "-2w"),
        ("  10   MIN   AGO ", "-10min"),
        ("007 min ago", "-7min"),
        ("now", "now"),
        ("today", "today"),
        ("Yesterday", "yesterday"),
        ("today\n", "today"),  # surrounding whitespace is stripped, never passed on
        ("2026-11-10", "2026-11-10"),
        ("2026-11-10 14:00", "2026-11-10 14:00"),
        ("2026-11-10 14:00:59", "2026-11-10 14:00:59"),
    ])
    def test_valid_values_normalized(self, value, expected):
        assert mcp_ssh.normalize_since(value) == expected

    @pytest.mark.parametrize("value", [
        "", " ", "ago", "min ago", "30", "30 min", "-30 min ago", "+30min", "tomorrow",
        "0 min ago", "-0h", "30 fortnights ago", "1.5 hours ago", "1234567 min ago",
        "5 months ago", "1 year ago", "2 hours 30 min ago",
        "2026-13-01", "2026-02-30", "2026-11-10 25:00", "2026-1-5", "2026-11-10T14:00:00",
        "14:00", "@1700000000",
        "now; id", "$(id)", "`id`", "1 min ago; rm -rf /", "yesterday | cat",
        "-1d --output=json", "--since",
        None, 30, True, 1.5, ["now"],
    ])
    def test_invalid_values_rejected(self, value):
        assert mcp_ssh.normalize_since(value) is None

    @pytest.mark.parametrize("value", [
        "30 min ago", "-2h", "today", "2026-11-10 14:00:59",
    ])
    def test_result_has_only_safe_characters(self, value):
        assert mcp_ssh.re.fullmatch(r"[0-9a-z:\- ]+", mcp_ssh.normalize_since(value))


# ============================================================
# `since` parameter of the journalctl / dmesg / last / coredumpctl tools
# ============================================================

SINCE_TOOLS = [
    (mcp_ssh.get_service_logs_from_journalctl, {"service": "nginx"}),
    (mcp_ssh.get_journal_errors, {}),
    (mcp_ssh.get_dmesg, {}),
    (mcp_ssh.get_last_logins, {}),
    (mcp_ssh.get_failed_logins, {}),
    (mcp_ssh.get_coredumps, {}),
]


class TestSinceParameter:
    @pytest.mark.parametrize("tool_func, kwargs", SINCE_TOOLS)
    def test_since_appended_normalized_and_quoted(self, tool_func, kwargs, mock_run_ssh_command):
        tool_func(host="h", user="u", since="30 min ago", **kwargs)
        cmd = mock_run_ssh_command.call_args[0][2]
        assert "--since -30min" in cmd

    @pytest.mark.parametrize("tool_func, kwargs", SINCE_TOOLS)
    def test_absolute_since_is_shell_quoted(self, tool_func, kwargs, mock_run_ssh_command):
        tool_func(host="h", user="u", since="2026-11-10 14:00", **kwargs)
        cmd = mock_run_ssh_command.call_args[0][2]
        assert "--since '2026-11-10 14:00'" in cmd

    @pytest.mark.parametrize("tool_func, kwargs", SINCE_TOOLS)
    def test_no_since_by_default(self, tool_func, kwargs, mock_run_ssh_command):
        tool_func(host="h", user="u", **kwargs)
        cmd = mock_run_ssh_command.call_args[0][2]
        assert "--since" not in cmd

    @pytest.mark.parametrize("tool_func, kwargs", SINCE_TOOLS)
    @pytest.mark.parametrize("since", ["", "now; id", "$(id)", "tomorrow", 30])
    def test_invalid_since_rejected(self, tool_func, kwargs, since, mock_run_ssh_command):
        result = tool_func(host="h", user="u", since=since, **kwargs)
        assert result["ok"] is False
        assert "since" in result["error"]
        mock_run_ssh_command.assert_not_called()


# ============================================================
# get_last_logins / get_failed_logins — lines validation
# ============================================================

class TestLoginsValidation:
    @pytest.mark.parametrize("tool_func", [mcp_ssh.get_last_logins, mcp_ssh.get_failed_logins])
    @pytest.mark.parametrize("lines", [0, -1, 1001, True, "50", 3.14])
    def test_invalid_lines_rejected(self, tool_func, lines, mock_run_ssh_command):
        result = tool_func(host="h", user="u", lines=lines)
        assert result["ok"] is False
        mock_run_ssh_command.assert_not_called()


# ============================================================
# get_coredumps — command + pid + lines validation
# ============================================================

class TestCoredumpsValidation:
    @pytest.mark.parametrize("command", [
        "debug", "gdb", "dump", "", "LIST", "list; id", "info --output=/tmp/x", None, 1,
    ])
    def test_command_outside_closed_list_rejected(self, command, mock_run_ssh_command):
        result = mcp_ssh.get_coredumps(host="h", user="u", command=command)
        assert result["ok"] is False
        assert "list, info" in result["error"]
        mock_run_ssh_command.assert_not_called()

    @pytest.mark.parametrize("pid", [0, -1, 4194305, True, "123", "1; id", 1.5])
    def test_invalid_pid_rejected(self, pid, mock_run_ssh_command):
        result = mcp_ssh.get_coredumps(host="h", user="u", pid=pid)
        assert result["ok"] is False
        mock_run_ssh_command.assert_not_called()

    @pytest.mark.parametrize("lines", [0, -1, 1001, True, "50"])
    def test_invalid_lines_rejected(self, lines, mock_run_ssh_command):
        result = mcp_ssh.get_coredumps(host="h", user="u", lines=lines)
        assert result["ok"] is False
        mock_run_ssh_command.assert_not_called()


# ============================================================
# normalize_since_docker — `since` validator for docker logs
# ============================================================

class TestNormalizeSinceDocker:
    @pytest.mark.parametrize("value, expected", [
        # native Go durations
        ("30m", "30m"),
        ("2h", "2h"),
        ("45s", "45s"),
        ("1h30m", "1h30m"),
        ("1h0m30s", "1h0m30s"),
        ("1H30M", "1h30m"),
        ("007m", "7m"),
        # same relative syntax as normalize_since
        ("30 min ago", "30m"),
        ("2 hours ago", "2h"),
        ("-15min", "15m"),
        ("45 seconds ago", "45s"),
        ("1 day ago", "24h"),
        ("-2d", "48h"),
        ("1 week ago", "168h"),
        # absolute
        ("2026-11-10", "2026-11-10"),
        ("2026-11-10 14:00", "2026-11-10T14:00:00"),
        ("2026-11-10 14:00:59", "2026-11-10T14:00:59"),
        ("2026-11-10T14:00:59", "2026-11-10T14:00:59"),
        ("2026-11-10t14:00:59z", "2026-11-10T14:00:59Z"),
        ("  2026-11-10   14:00 ", "2026-11-10T14:00:00"),
    ])
    def test_valid_values_normalized(self, value, expected):
        assert mcp_ssh.normalize_since_docker(value) == expected

    @pytest.mark.parametrize("value", [
        "", " ", "now", "today", "yesterday", "tomorrow",
        "0m", "0h0m0s", "30", "h", "m", "30x", "30m1h", "1.5h", "1d", "1w", "-30m ago",
        "30 min", "+30m", "1234567m",
        "2026-13-01", "2026-02-30T10:00:00", "2026-11-10T25:00:00", "2026-11-10T14:00",
        "2026-11-10T14:00:00+01:00", "1700000000",
        "30m; id", "$(id)", "`id`", "2h | cat", "30m --follow", "--follow", "-f",
        None, 30, True, 1.5, ["30m"],
    ])
    def test_invalid_values_rejected(self, value):
        assert mcp_ssh.normalize_since_docker(value) is None

    @pytest.mark.parametrize("value", ["30 min ago", "1h30m", "2026-11-10 14:00", "2026-11-10t14:00:59z"])
    def test_result_has_only_safe_characters(self, value):
        assert mcp_ssh.re.fullmatch(r"[0-9A-Za-z:\-]+", mcp_ssh.normalize_since_docker(value))


# ============================================================
# container name / ID validators
# ============================================================

VALID_CONTAINER_NAMES = ["web", "my-app_1", "db.replica-2", "a1", "0web", "A" * 255]
VALID_CONTAINER_IDS = ["0123456789ab", "a" * 64, "deadbeefcafe0123"]
INVALID_CONTAINER_REFS = [
    "", "a", "-web", "--help", ".hidden", "_web", "web app", "web;id", "web|cat", "$(id)", "`id`",
    "web/1", "web\n", "веб", "A" * 256, None, 123, True, ["web"],
]


class TestContainerValidators:
    @pytest.mark.parametrize("name", VALID_CONTAINER_NAMES)
    def test_valid_names(self, name):
        assert mcp_ssh.is_valid_container_name(name) is True

    @pytest.mark.parametrize("name", INVALID_CONTAINER_REFS)
    def test_invalid_names(self, name):
        assert mcp_ssh.is_valid_container_name(name) is False

    @pytest.mark.parametrize("container_id", VALID_CONTAINER_IDS)
    def test_valid_ids(self, container_id):
        assert mcp_ssh.is_valid_container_id(container_id) is True

    @pytest.mark.parametrize("container_id", INVALID_CONTAINER_REFS + [
        "0123456789a",          # 11 chars - too short
        "a" * 65,               # too long
        "0123456789AB",         # uppercase hex
        "0123456789ag",         # not hex
        "sha256:0123456789ab",
    ])
    def test_invalid_ids(self, container_id):
        assert mcp_ssh.is_valid_container_id(container_id) is False

    @pytest.mark.parametrize("container", VALID_CONTAINER_NAMES + VALID_CONTAINER_IDS)
    def test_ref_accepts_names_and_ids(self, container):
        assert mcp_ssh.is_valid_container_ref(container) is True

    @pytest.mark.parametrize("container", INVALID_CONTAINER_REFS)
    def test_ref_rejects_everything_else(self, container):
        assert mcp_ssh.is_valid_container_ref(container) is False


# ============================================================
# get_docker_logs / get_docker_inspect — parameter validation
# ============================================================

class TestDockerToolsValidation:
    @pytest.mark.parametrize("tool_func", [mcp_ssh.get_docker_logs, mcp_ssh.get_docker_inspect])
    @pytest.mark.parametrize("container", ["", "-f", "--help", "web; id", "$(id)", "web app", None, 1])
    def test_invalid_container_rejected(self, tool_func, container, mock_run_ssh_command):
        result = tool_func(container=container, host="h", user="u")
        assert result["ok"] is False
        assert "container" in result["error"]
        mock_run_ssh_command.assert_not_called()

    @pytest.mark.parametrize("lines", [0, -1, 1001, True, "200", 3.14])
    def test_logs_invalid_lines_rejected(self, lines, mock_run_ssh_command):
        result = mcp_ssh.get_docker_logs(container="web", host="h", user="u", lines=lines)
        assert result["ok"] is False
        mock_run_ssh_command.assert_not_called()

    @pytest.mark.parametrize("since", ["", "today", "yesterday", "30m; id", "$(id)", "--follow", 30])
    def test_logs_invalid_since_rejected(self, since, mock_run_ssh_command):
        result = mcp_ssh.get_docker_logs(container="web", host="h", user="u", since=since)
        assert result["ok"] is False
        assert "since" in result["error"]
        mock_run_ssh_command.assert_not_called()


# ============================================================
# image name / ID validators
# ============================================================

VALID_IMAGE_NAMES = [
    "nginx", "nginx:1.27", "nginx:latest", "library/nginx", "registry.k8s.io/pause:3.9",
    "localhost:5000/team/app", "localhost:5000/team/app:v1.2.3-rc_1",
    "ghcr.io/org/my-app__x.y:sha-abc123", "docker.io/library/busybox@sha256:" + "a" * 64,
    "repo/app:tag@sha256:" + "0" * 64, "Registry.Example.COM/app",
]
VALID_IMAGE_IDS = ["0123456789abc", "a" * 64, "sha256:" + "b" * 64, "sha256:0123456789ab"]
INVALID_IMAGE_REFS = [
    "", "-nginx", "--help", ".nginx", "/nginx", "nginx/", "nginx:", "nginx:-tag", "nginx:tag:tag",
    "nginx@sha256:abc", "nginx@md5:" + "a" * 64, "repo//app", "repo/App", "nginx latest",
    "nginx;id", "nginx|cat", "$(id)", "`id`", "nginx\n", "nginx:" + "t" * 129, "a" * 513,
    None, 123, True, ["nginx"],
]


class TestImageValidators:
    @pytest.mark.parametrize("image", VALID_IMAGE_NAMES)
    def test_valid_names(self, image):
        assert mcp_ssh.is_valid_image_name(image) is True

    @pytest.mark.parametrize("image", INVALID_IMAGE_REFS)
    def test_invalid_names(self, image):
        assert mcp_ssh.is_valid_image_name(image) is False

    @pytest.mark.parametrize("image_id", VALID_IMAGE_IDS)
    def test_valid_ids(self, image_id):
        assert mcp_ssh.is_valid_image_id(image_id) is True

    @pytest.mark.parametrize("image_id", INVALID_IMAGE_REFS + [
        "0123456789a", "a" * 65, "0123456789AB", "sha512:" + "a" * 64, "nginx:1.27",
    ])
    def test_invalid_ids(self, image_id):
        assert mcp_ssh.is_valid_image_id(image_id) is False

    @pytest.mark.parametrize("image", VALID_IMAGE_NAMES + VALID_IMAGE_IDS)
    def test_ref_accepts_names_and_ids(self, image):
        assert mcp_ssh.is_valid_image_ref(image) is True

    @pytest.mark.parametrize("image", INVALID_IMAGE_REFS)
    def test_ref_rejects_everything_else(self, image):
        assert mcp_ssh.is_valid_image_ref(image) is False


# ============================================================
# kubernetes name validators
# ============================================================

INVALID_K8S_NAMES = [
    "", "-web", "web-", "--help", "Web", "web_1", "web app", "web;id", "web/1", "$(id)", "веб",
    "web\n", None, 1, True, ["web"],
]


class TestKubernetesNameValidators:
    @pytest.mark.parametrize("value", ["a", "default", "kube-system", "ns1", "a" * 63])
    def test_valid_dns_labels(self, value):
        assert mcp_ssh.is_valid_dns_label(value) is True

    @pytest.mark.parametrize("value", INVALID_K8S_NAMES + ["a.b", ".a", "a" * 64])
    def test_invalid_dns_labels(self, value):
        assert mcp_ssh.is_valid_dns_label(value) is False

    @pytest.mark.parametrize("value", [
        "a", "web-7d4b9c-x2x", "node-1.example.com", "ip-10-0-0-1.eu-west-1.compute.internal", "a" * 253,
    ])
    def test_valid_dns_subdomains(self, value):
        assert mcp_ssh.is_valid_dns_subdomain(value) is True

    @pytest.mark.parametrize("value", INVALID_K8S_NAMES + [".a", "a.", "a" * 254])
    def test_invalid_dns_subdomains(self, value):
        assert mcp_ssh.is_valid_dns_subdomain(value) is False

    @pytest.mark.parametrize("value", [
        "secret", "secrets", "configmap", "cm", "all", "pod,secret", "pod/web", "", "pod; id",
        "serviceaccount", "*", None, 1, ["pod"],
    ])
    def test_resource_types_outside_closed_list_rejected(self, value):
        assert mcp_ssh.normalize_k8s_resource_type(value) is None

    def test_resource_type_aliases_are_unambiguous(self):
        spellings = [
            spelling
            for canonical, aliases in mcp_ssh.K8S_DESCRIBE_RESOURCE_TYPES.items()
            for spelling in (canonical, *aliases)
        ]
        assert len(spellings) == len(set(spellings))


# ============================================================
# normalize_since_kubernetes / is_go_duration
# ============================================================

class TestNormalizeSinceKubernetes:
    @pytest.mark.parametrize("value, expected", [
        ("30m", "30m"), ("1h30m", "1h30m"), ("30 min ago", "30m"), ("-2h", "2h"), ("1 day ago", "24h"),
        ("2026-11-10T14:00:00Z", "2026-11-10T14:00:00Z"), ("2026-11-10t14:00:00z", "2026-11-10T14:00:00Z"),
    ])
    def test_valid_values_normalized(self, value, expected):
        assert mcp_ssh.normalize_since_kubernetes(value) == expected

    @pytest.mark.parametrize("value", [
        "", "today", "yesterday", "now", "2026-11-10", "2026-11-10 14:00", "2026-11-10T14:00:00",
        "2026-13-10T14:00:00Z", "0m", "30m; id", "$(id)", "--follow", None, 30,
    ])
    def test_invalid_values_rejected(self, value):
        assert mcp_ssh.normalize_since_kubernetes(value) is None

    @pytest.mark.parametrize("value, expected", [
        ("30m", True), ("1h30m", True), ("45s", True),
        ("", False), ("2026-11-10T14:00:00Z", False), ("30", False), (None, False), (30, False),
    ])
    def test_is_go_duration(self, value, expected):
        assert mcp_ssh.is_go_duration(value) is expected


# ============================================================
# redact_env_values
# ============================================================

class TestRedactEnvValues:
    def test_string_entries_keep_names(self):
        assert mcp_ssh.redact_env_values({"env": ["A=1", "B=x=y", "NOEQ"]}) == {
            "env": ["A=<redacted>", "B=<redacted>", "NOEQ=<redacted>"]
        }

    def test_dict_entries_keep_key_and_name(self):
        assert mcp_ssh.redact_env_values({"envs": [{"key": "A", "value": "1"}, {"name": "B", "value": "2"}]}) == {
            "envs": [{"key": "A", "value": "<redacted>"}, {"name": "B", "value": "<redacted>"}]
        }

    def test_key_match_is_case_insensitive_and_nested(self):
        data = {"a": [{"b": {"Env": ["S=1"], "ENVS": "raw", "other": "kept"}}]}
        assert mcp_ssh.redact_env_values(data) == {
            "a": [{"b": {"Env": ["S=<redacted>"], "ENVS": "<redacted>", "other": "kept"}}]
        }

    def test_input_is_not_mutated(self):
        data = {"env": ["A=1"]}
        mcp_ssh.redact_env_values(data)
        assert data == {"env": ["A=1"]}

    def test_non_env_keys_untouched(self):
        data = {"environment": "prod", "args": ["--env=x"], "n": 1, "none": None}
        assert mcp_ssh.redact_env_values(data) == data


# ============================================================
# kubectl / crictl tools — parameter validation
# ============================================================

BAD_K8S_VALUES = ["", "-n", "--help", "web; id", "$(id)", "Web", "web app"]


class TestKubectlToolsValidation:
    @pytest.mark.parametrize("pod", BAD_K8S_VALUES + [None, 1])
    def test_logs_invalid_pod_rejected(self, pod, mock_run_ssh_command):
        result = mcp_ssh.get_kubectl_logs(pod=pod, host="h", user="u")
        assert result["ok"] is False
        mock_run_ssh_command.assert_not_called()

    @pytest.mark.parametrize("namespace", BAD_K8S_VALUES + [None, 1, "a.b"])
    def test_logs_invalid_namespace_rejected(self, namespace, mock_run_ssh_command):
        result = mcp_ssh.get_kubectl_logs(pod="web-0", host="h", user="u", namespace=namespace)
        assert result["ok"] is False
        assert "namespace" in result["error"]
        mock_run_ssh_command.assert_not_called()

    @pytest.mark.parametrize("container", BAD_K8S_VALUES + [1, "a.b"])
    def test_logs_invalid_container_rejected(self, container, mock_run_ssh_command):
        result = mcp_ssh.get_kubectl_logs(pod="web-0", host="h", user="u", container=container)
        assert result["ok"] is False
        assert "container" in result["error"]
        mock_run_ssh_command.assert_not_called()

    @pytest.mark.parametrize("kwargs", [
        {"previous": "yes"}, {"previous": 1}, {"lines": 0}, {"lines": 1001}, {"lines": True}, {"lines": "5"},
        {"since": "today"}, {"since": "2026-11-10 14:00"}, {"since": "30m; id"}, {"since": 30},
    ])
    def test_logs_invalid_options_rejected(self, kwargs, mock_run_ssh_command):
        result = mcp_ssh.get_kubectl_logs(pod="web-0", host="h", user="u", **kwargs)
        assert result["ok"] is False
        mock_run_ssh_command.assert_not_called()

    @pytest.mark.parametrize("resource_type", ["secret", "configmap", "cm", "all", "pod,secret", "", "pod; id", None])
    def test_describe_resource_type_outside_closed_list_rejected(self, resource_type, mock_run_ssh_command):
        result = mcp_ssh.get_kubectl_describe(resource_type=resource_type, name="x1", host="h", user="u")
        assert result["ok"] is False
        assert "resource_type" in result["error"]
        mock_run_ssh_command.assert_not_called()

    @pytest.mark.parametrize("kwargs", [
        {"name": ""}, {"name": "--all"}, {"name": "web; id"}, {"name": None},
        {"name": "web-0", "namespace": "--all-namespaces"}, {"name": "web-0", "namespace": ""},
    ])
    def test_describe_invalid_name_or_namespace_rejected(self, kwargs, mock_run_ssh_command):
        result = mcp_ssh.get_kubectl_describe(resource_type="pod", host="h", user="u", **kwargs)
        assert result["ok"] is False
        mock_run_ssh_command.assert_not_called()

    @pytest.mark.parametrize("kwargs", [
        {"namespace": ""}, {"namespace": "-A"}, {"namespace": "a; id"}, {"namespace": 1},
        {"warnings_only": "yes"}, {"warnings_only": 1},
        {"lines": 0}, {"lines": 1001}, {"lines": True}, {"lines": "5"},
    ])
    def test_events_invalid_options_rejected(self, kwargs, mock_run_ssh_command):
        result = mcp_ssh.get_kubectl_events(host="h", user="u", **kwargs)
        assert result["ok"] is False
        mock_run_ssh_command.assert_not_called()


class TestCrictlToolsValidation:
    @pytest.mark.parametrize("tool_func", [mcp_ssh.get_crictl_logs, mcp_ssh.get_crictl_inspect])
    @pytest.mark.parametrize("container_id", ["", "web", "-f", "0123456789a", "0123456789AB", "0123456789ab; id", None, 1])
    def test_invalid_container_id_rejected(self, tool_func, container_id, mock_run_ssh_command):
        result = tool_func(container_id=container_id, host="h", user="u")
        assert result["ok"] is False
        assert "container_id" in result["error"]
        mock_run_ssh_command.assert_not_called()

    @pytest.mark.parametrize("kwargs", [
        {"lines": 0}, {"lines": 1001}, {"lines": True}, {"lines": "5"},
        {"since": "today"}, {"since": "2026-11-10 14:00"}, {"since": "30m; id"}, {"since": 30},
    ])
    def test_logs_invalid_options_rejected(self, kwargs, mock_run_ssh_command):
        result = mcp_ssh.get_crictl_logs(container_id="0123456789abc", host="h", user="u", **kwargs)
        assert result["ok"] is False
        mock_run_ssh_command.assert_not_called()

    @pytest.mark.parametrize("image", ["", "-q", "--help", "nginx; id", "$(id)", "nginx latest", None, 1])
    def test_inspect_image_invalid_image_rejected(self, image, mock_run_ssh_command):
        result = mcp_ssh.get_crictl_inspect_image(image=image, host="h", user="u")
        assert result["ok"] is False
        assert "image" in result["error"]
        mock_run_ssh_command.assert_not_called()


# ============================================================
# hostname / IP address validators
# ============================================================

INVALID_HOSTS_AND_IPS = [
    "", " ", ".", "-example.com", "example-.com", "--help", "-x", "exa mple.com", "example..com",
    ".example.com", "example.com;id", "example.com|cat", "$(id)", "`id`", "example.com\n",
    "http://example.com", "example.com/path", "user@example.com", "пример.рф", "@8.8.8.8",
    "+short", "a" * 64 + ".com", ".".join(["a" * 60] * 5), None, 1, True, ["example.com"],
]


class TestHostnameAndIpValidators:
    @pytest.mark.parametrize("name", [
        "example.com", "example.com.", "localhost", "a", "sub-1.example.co.uk", "_dmarc.example.com",
        "xn--e1afmkfd.xn--p1ai", "EXAMPLE.Com", "db_1", "10.in-addr.arpa", "a" * 63 + ".com",
    ])
    def test_valid_hostnames(self, name):
        assert mcp_ssh.is_valid_hostname(name) is True

    @pytest.mark.parametrize("name", INVALID_HOSTS_AND_IPS)
    def test_invalid_hostnames(self, name):
        assert mcp_ssh.is_valid_hostname(name) is False

    @pytest.mark.parametrize("address", [
        "192.0.2.10", "127.0.0.1", "0.0.0.0", "::1", "2001:db8::1", "fe80::1", "::ffff:192.0.2.1",
        "2001:0db8:0000:0000:0000:0000:0000:0001",
    ])
    def test_valid_ip_addresses(self, address):
        assert mcp_ssh.is_valid_ip_address(address) is True

    @pytest.mark.parametrize("address", INVALID_HOSTS_AND_IPS + [
        "256.1.1.1", "1.2.3", "1.2.3.4.5", "192.0.2.10/24", "fe80::1%eth0", "fe80::1%$(id)",
        "2001:db8::g", "example.com", "192.0.2.10 ", "[::1]", "192.0.2.10:53",
    ])
    def test_invalid_ip_addresses(self, address):
        assert mcp_ssh.is_valid_ip_address(address) is False


# ============================================================
# get_dns_lookup — parameter validation
# ============================================================

class TestDnsLookupValidation:
    @pytest.mark.parametrize("name", [
        "", "-x", "--help", "+short", "@8.8.8.8", "example.com; id", "$(id)", "exa mple.com",
        "fe80::1%eth0", "192.0.2.10/24", None, 1,
    ])
    @pytest.mark.parametrize("use_dig", [False, True])
    def test_invalid_name_rejected(self, name, use_dig, mock_run_ssh_command):
        result = mcp_ssh.get_dns_lookup(name=name, host="h", user="u", use_dig=use_dig)
        assert result["ok"] is False
        assert "name" in result["error"]
        mock_run_ssh_command.assert_not_called()

    @pytest.mark.parametrize("use_dig", ["true", 1, 0, None])
    def test_non_bool_use_dig_rejected(self, use_dig, mock_run_ssh_command):
        result = mcp_ssh.get_dns_lookup(name="example.com", host="h", user="u", use_dig=use_dig)
        assert result["ok"] is False
        mock_run_ssh_command.assert_not_called()

    @pytest.mark.parametrize("record_type", [
        "ANY", "AXFR", "IXFR", "*", "", "A MX", "A;id", "+short", "-x", "@8.8.8.8", "TYPE255", None, 1, ["A"],
    ])
    @pytest.mark.parametrize("use_dig", [False, True])
    def test_record_type_outside_closed_list_rejected(self, record_type, use_dig, mock_run_ssh_command):
        result = mcp_ssh.get_dns_lookup(
            name="example.com", host="h", user="u", use_dig=use_dig, record_type=record_type
        )
        assert result["ok"] is False
        assert "record_type" in result["error"]
        mock_run_ssh_command.assert_not_called()

    @pytest.mark.parametrize("server", [
        "", "@8.8.8.8", "-x", "+short", "8.8.8.8; id", "$(id)", "8.8.8.8 +short", "8.8.8.8#53",
        "fe80::1%eth0", "8.8.8.8/32", 8, True,
    ])
    def test_invalid_server_rejected(self, server, mock_run_ssh_command):
        result = mcp_ssh.get_dns_lookup(name="example.com", host="h", user="u", use_dig=True, server=server)
        assert result["ok"] is False
        assert "server" in result["error"]
        mock_run_ssh_command.assert_not_called()

    @pytest.mark.parametrize("kwargs", [{"record_type": "MX"}, {"server": "8.8.8.8"}])
    def test_dig_only_parameters_rejected_with_getent(self, kwargs, mock_run_ssh_command):
        result = mcp_ssh.get_dns_lookup(name="example.com", host="h", user="u", **kwargs)
        assert result["ok"] is False
        assert "use_dig=True" in result["error"]
        mock_run_ssh_command.assert_not_called()

    @pytest.mark.parametrize("record_type", ["MX", "AAAA", "TXT"])
    def test_ip_with_forward_record_type_rejected(self, record_type, mock_run_ssh_command):
        result = mcp_ssh.get_dns_lookup(
            name="192.0.2.10", host="h", user="u", use_dig=True, record_type=record_type
        )
        assert result["ok"] is False
        mock_run_ssh_command.assert_not_called()


class TestNormalizeDnsRecordType:
    @pytest.mark.parametrize("record_type", mcp_ssh.DNS_RECORD_TYPES)
    def test_every_listed_type_accepted_in_any_case(self, record_type):
        assert mcp_ssh.normalize_dns_record_type(record_type.lower()) == record_type

    @pytest.mark.parametrize("record_type", ["ANY", "AXFR", "", "A MX", None, 1])
    def test_others_rejected(self, record_type):
        assert mcp_ssh.normalize_dns_record_type(record_type) is None


# ============================================================
# check_tcp_connect — parameter validation
# ============================================================

class TestIsValidTcpPort:
    @pytest.mark.parametrize("port", [1, 22, 443, 5432, 65535])
    def test_valid_ports(self, port):
        assert mcp_ssh.is_valid_tcp_port(port) is True

    @pytest.mark.parametrize("port", [0, -1, 65536, 100000, "443", "80; id", 443.0, True, False, None, [443]])
    def test_invalid_ports(self, port):
        assert mcp_ssh.is_valid_tcp_port(port) is False


class TestTcpConnectValidation:
    @pytest.mark.parametrize("target_host", [
        "", "-e", "--help", "-l", "example.com; id", "$(id)", "exa mple.com", "example.com 80",
        "fe80::1%eth0", "192.0.2.10/24", "192.0.2.10:80", None, 1,
    ])
    def test_invalid_target_host_rejected(self, target_host, mock_run_ssh_command):
        result = mcp_ssh.check_tcp_connect(target_host=target_host, target_port=80, host="h", user="u")
        assert result["ok"] is False
        assert "target_host" in result["error"]
        mock_run_ssh_command.assert_not_called()

    @pytest.mark.parametrize("target_port", [0, -1, 65536, "80", "80-90", "80; id", 80.0, True, None])
    def test_invalid_target_port_rejected(self, target_port, mock_run_ssh_command):
        result = mcp_ssh.check_tcp_connect(
            target_host="example.com", target_port=target_port, host="h", user="u"
        )
        assert result["ok"] is False
        assert "target_port" in result["error"]
        mock_run_ssh_command.assert_not_called()


# ============================================================
# is_valid_lines / is_valid_pid / is_valid_coredump_command
# ============================================================

class TestIsValidLines:
    @pytest.mark.parametrize("lines", [1, 50, 200, 1000])
    def test_valid_lines(self, lines):
        assert mcp_ssh.is_valid_lines(lines) is True

    @pytest.mark.parametrize("lines", [0, -1, 1001, "50", "50; id", 50.0, True, False, None, [50]])
    def test_invalid_lines(self, lines):
        assert mcp_ssh.is_valid_lines(lines) is False


class TestIsValidPid:
    @pytest.mark.parametrize("pid", [1, 1234, 4194304])
    def test_valid_pids(self, pid):
        assert mcp_ssh.is_valid_pid(pid) is True

    @pytest.mark.parametrize("pid", [0, -1, 4194305, "1234", "1; id", 12.0, True, False, None, [1]])
    def test_invalid_pids(self, pid):
        assert mcp_ssh.is_valid_pid(pid) is False


class TestIsValidCoredumpCommand:
    @pytest.mark.parametrize("command", ["list", "info"])
    def test_listed_commands_accepted(self, command):
        assert mcp_ssh.is_valid_coredump_command(command) is True

    @pytest.mark.parametrize("command", [
        "debug", "dump", "gdb", "", "LIST", " list", "list; id", "list info", "--help", None, 1, ["list"],
    ])
    def test_others_rejected(self, command):
        assert mcp_ssh.is_valid_coredump_command(command) is False


# \d also matches non-ASCII digits (e.g. Arabic-Indic), which must not get through
@pytest.mark.parametrize("image", ["reg:\u0665\u0660\u0660\u0660/app", "localhost:\uff15\uff10\uff10\uff10/app"])
def test_image_name_port_must_be_ascii_digits(image):
    assert mcp_ssh.is_valid_image_name(image) is False
    assert mcp_ssh.is_valid_image_ref(image) is False


def test_image_name_ascii_port_still_accepted():
    assert mcp_ssh.is_valid_image_name("localhost:5000/team/app:1.2") is True


NON_ASCII_SINCE = [
    "\u0663 min ago", "-\u0663h", "202\u0663-11-10", "2026-11-10 1\u0664:00", "\uff13 days ago",
]


@pytest.mark.parametrize("since", NON_ASCII_SINCE)
def test_normalize_since_rejects_non_ascii_digits(since):
    assert mcp_ssh.normalize_since(since) is None


@pytest.mark.parametrize("since", NON_ASCII_SINCE + ["\u0663m", "1h\u0663\u0660m", "202\u0663-11-10T10:00:00", "2026-11-10T1\u0664:00:00Z"])
def test_normalize_since_docker_and_kubernetes_reject_non_ascii_digits(since):
    assert mcp_ssh.normalize_since_docker(since) is None
    assert mcp_ssh.normalize_since_kubernetes(since) is None
