"""Tests for run_ssh_command orchestration and error handling."""
import socket
from datetime import datetime, timezone

import paramiko
import pytest

import mcp_ssh
from tests.conftest import stream_chunks


class TestRunSshCommandSuccess:

    def test_successful_command_returns_ok_true(self, mock_ssh_client):
        result = mcp_ssh.run_ssh_command("h", "u", "echo ok")
        assert result["ok"] is True
        assert result["host"] == "h"
        assert "collected_at_utc" in result
        assert result["data"]["exit_code"] == 0

    def test_collected_at_utc_is_valid_iso(self, mock_ssh_client):
        result = mcp_ssh.run_ssh_command("h", "u", "echo ok")
        ts = result["collected_at_utc"]
        parsed = datetime.fromisoformat(ts)
        assert parsed.tzinfo is not None

    def test_nonzero_exit_code_returns_ok_false(self, mock_ssh_client):
        stdout_mock = mock_ssh_client.exec_command.return_value[1]
        stdout_mock.channel.recv_exit_status.return_value = 1
        result = mcp_ssh.run_ssh_command("h", "u", "failing-cmd")
        assert result["ok"] is False
        assert result["data"]["exit_code"] == 1

    def test_command_runs_in_bash_with_sh_fallback(self, mock_ssh_client):
        mcp_ssh.run_ssh_command("h", "u", "echo 'it works'", timeout_s=7)
        remote_cmd = mock_ssh_client.exec_command.call_args[0][0]
        assert remote_cmd == mcp_ssh.timeout_wrapped("echo 'it works'", 7)
        assert remote_cmd.endswith(""" 'echo '"'"'it works'"'"'' 7""")

    @pytest.mark.parametrize("exit_code", [124, -1])
    def test_timeout_is_reported(self, mock_ssh_client, mocker, exit_code):
        mock_ssh_client.exec_command.return_value[1].channel.recv_exit_status.return_value = exit_code
        mocker.patch("mcp_ssh.time.monotonic", side_effect=[100.0, 107.2])
        result = mcp_ssh.run_ssh_command("h", "u", "sleep 60", timeout_s=7)
        assert result["ok"] is False
        assert result["data"]["timed_out"] is True
        assert result["error"].startswith("The command probably timed out: it was stopped after the 7s timeout")

    @pytest.mark.parametrize("exit_code, elapsed", [
        (124, 0.3),   # a command that itself exits 124 quickly
        (-1, 0.3),    # killed by a signal for another reason
        (137, 9.0),   # killed with KILL for another reason (e.g. out of memory)
        (1, 9.0),     # slow, but an ordinary failure
        (0, 9.0),
    ])
    def test_no_timeout_reported(self, mock_ssh_client, mocker, exit_code, elapsed):
        mock_ssh_client.exec_command.return_value[1].channel.recv_exit_status.return_value = exit_code
        mocker.patch("mcp_ssh.time.monotonic", side_effect=[100.0, 100.0 + elapsed])
        result = mcp_ssh.run_ssh_command("h", "u", "cmd", timeout_s=7)
        assert "timed_out" not in result["data"]
        assert "error" not in result

    def test_custom_success_exit_codes(self, mock_ssh_client):
        stdout_mock = mock_ssh_client.exec_command.return_value[1]
        stdout_mock.channel.recv_exit_status.return_value = 1
        result = mcp_ssh.run_ssh_command("h", "u", "cmd", success_exit_codes=(0, 1))
        assert result["ok"] is True

    def test_data_contains_stdout_stderr(self, mock_ssh_client):
        result = mcp_ssh.run_ssh_command("h", "u", "echo ok")
        assert "stdout" in result["data"]
        assert "stderr" in result["data"]
        assert "command" in result["data"]


class TestRunCmdReading:

    def test_output_in_chunks_is_joined_before_decoding(self, mock_ssh_client):
        channel = mock_ssh_client.exec_command.return_value[1].channel
        euro = "€".encode()
        channel.recv.side_effect = stream_chunks(b"price: " + euro[:1], euro[1:] + b" 5")
        channel.recv_stderr.side_effect = stream_chunks(b"warn", b"ing")
        result = mcp_ssh.run_ssh_command("h", "u", "cmd")
        assert (result["data"]["stdout"], result["data"]["stderr"]) == ("price: € 5", "warning")

    def test_stdout_is_read_to_the_end_before_stderr_and_exit_status(self, mock_ssh_client):
        channel = mock_ssh_client.exec_command.return_value[1].channel
        order = []
        channel.recv.side_effect = lambda n: order.append("stdout") or b""
        channel.recv_stderr.side_effect = lambda n: order.append("stderr") or b""
        channel.recv_exit_status.side_effect = lambda: order.append("exit") or 0
        mcp_ssh.run_ssh_command("h", "u", "cmd")
        assert order == ["stdout", "stderr", "exit"]

    def _never_ending(self, mock_ssh_client, stderr_ready):
        channel = mock_ssh_client.exec_command.return_value[1].channel
        channel.recv.side_effect = stream_chunks(b"start\n", b"more", socket.timeout())
        channel.recv_stderr.side_effect = stream_chunks(*stderr_ready)
        channel.recv_stderr_ready.side_effect = [True] * len(stderr_ready) + [False]
        return channel

    def test_output_that_never_ends_is_a_timeout_with_the_output_so_far(self, mock_ssh_client):
        channel = self._never_ending(mock_ssh_client, [b"err so far"])
        result = mcp_ssh.run_ssh_command("h", "u", "du / | sort", timeout_s=7)
        assert result["ok"] is False
        assert result["data"] == {
            "command": "du / | sort", "exit_code": -1, "stdout": "start\nmore", "stderr": "err so far",
            "timed_out": True, "output_never_ended": True,
        }
        assert result["error"].startswith("The command timed out: its output was still open 7s + 5s")
        assert "may still be running on the host" in result["error"]
        # waiting for the exit status would hang for ever; the channel is closed instead
        channel.recv_exit_status.assert_not_called()
        channel.close.assert_called_once()

    def test_output_that_never_ends_takes_only_the_stderr_already_there(self, mock_ssh_client):
        channel = self._never_ending(mock_ssh_client, [])
        result = mcp_ssh.run_ssh_command("h", "u", "cmd")
        assert result["data"]["stderr"] == ""
        channel.recv_stderr.assert_not_called()

    def test_output_that_never_ends_is_not_a_network_error(self, mock_ssh_client):
        self._never_ending(mock_ssh_client, [])
        assert "Network error" not in mcp_ssh.run_ssh_command("h", "u", "cmd")["error"]

    def test_a_timeout_while_connecting_is_still_a_network_error(self, mocker):
        mocker.patch("mcp_ssh.get_ssh_client", side_effect=socket.timeout("timed out"))
        assert mcp_ssh.run_ssh_command("h", "u", "cmd")["error"].startswith("Network error")


class TestRunSshCommandKeyPath:

    def test_nonexistent_key_path(self):
        result = mcp_ssh.run_ssh_command("h", "u", "cmd", key_path="/nonexistent/key_xyz")
        assert result["ok"] is False
        assert "does not exist" in result["error"]

    def test_tilde_expansion(self, mock_ssh_client, mocker, tmp_path):
        key_file = tmp_path / "id_rsa"
        key_file.write_text("fake-key")
        mocker.patch("mcp_ssh.os.path.expanduser", return_value=str(key_file))
        result = mcp_ssh.run_ssh_command("h", "u", "cmd", key_path="~/fake")
        assert result["ok"] is True

    def test_none_key_path_skips_file_check(self, mock_ssh_client):
        result = mcp_ssh.run_ssh_command("h", "u", "cmd", key_path=None)
        assert result["ok"] is True


class TestRunSshCommandAuthErrors:

    def test_auth_error_with_key(self, mocker):
        mocker.patch(
            "mcp_ssh.get_ssh_client",
            side_effect=paramiko.AuthenticationException(),
        )
        result = mcp_ssh.run_ssh_command("h", "u", "cmd", key_path=None)
        # key_path=None so no file check, but we need to provide a key_path
        # that passes the file check to reach the auth error with key message.
        assert result["ok"] is False
        assert "No valid SSH key or password" in result["error"]

    def test_auth_error_with_key_path(self, mocker, tmp_path):
        key_file = tmp_path / "id_rsa"
        key_file.write_text("fake")
        mocker.patch(
            "mcp_ssh.get_ssh_client",
            side_effect=paramiko.AuthenticationException(),
        )
        result = mcp_ssh.run_ssh_command("h", "u", "cmd", key_path=str(key_file))
        assert result["ok"] is False
        assert "key" in result["error"].lower()
        assert str(key_file) in result["error"]

    def test_auth_error_with_password(self, mocker):
        mocker.patch(
            "mcp_ssh.get_ssh_client",
            side_effect=paramiko.AuthenticationException(),
        )
        result = mcp_ssh.run_ssh_command("h", "u", "cmd", password="bad-pass")
        assert result["ok"] is False
        assert "password was rejected" in result["error"]

    def test_auth_error_no_credentials(self, mocker):
        mocker.patch(
            "mcp_ssh.get_ssh_client",
            side_effect=paramiko.AuthenticationException(),
        )
        result = mcp_ssh.run_ssh_command("h", "u", "cmd")
        assert result["ok"] is False
        assert "No valid SSH key or password" in result["error"]


class TestRunSshCommandNetworkErrors:

    def test_socket_error(self, mocker):
        mocker.patch(
            "mcp_ssh.get_ssh_client",
            side_effect=socket.error("Connection refused"),
        )
        result = mcp_ssh.run_ssh_command("h", "u", "cmd")
        assert result["ok"] is False
        assert "Network error" in result["error"]
        assert "h:22" in result["error"]

    def test_ssh_exception(self, mocker):
        mocker.patch(
            "mcp_ssh.get_ssh_client",
            side_effect=paramiko.SSHException("bad packet"),
        )
        result = mcp_ssh.run_ssh_command("h", "u", "cmd")
        assert result["ok"] is False
        assert "SSH protocol error" in result["error"]

    def test_generic_exception(self, mocker):
        mocker.patch(
            "mcp_ssh.get_ssh_client",
            side_effect=RuntimeError("boom"),
        )
        result = mcp_ssh.run_ssh_command("h", "u", "cmd")
        assert result["ok"] is False
        assert "Unexpected error" in result["error"]
