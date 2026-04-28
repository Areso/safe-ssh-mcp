"""Tests for SSH connection pool management and janitor cleanup."""
import time

import paramiko
import pytest

import mcp_ssh


# ============================================================
# get_ssh_client — pool logic
# ============================================================

class TestGetSshClient:

    def test_new_connection_created_when_pool_empty(self, mock_paramiko_client):
        client = mcp_ssh.get_ssh_client("host1", "user1", 22)
        mock_paramiko_client.connect.assert_called_once()
        assert "user1@host1:22" in mcp_ssh.SSH_POOL

    def test_pool_key_format(self, mock_paramiko_client):
        mcp_ssh.get_ssh_client("10.0.0.1", "admin", 2222)
        assert "admin@10.0.0.1:2222" in mcp_ssh.SSH_POOL

    def test_reuse_existing_live_connection(self, mock_paramiko_client):
        client1 = mcp_ssh.get_ssh_client("h", "u", 22)
        mock_paramiko_client.connect.reset_mock()

        client2 = mcp_ssh.get_ssh_client("h", "u", 22)
        mock_paramiko_client.connect.assert_not_called()
        assert client1 is client2

    def test_stale_connection_transport_dead(self, mocker):
        old_client = mocker.MagicMock(spec=paramiko.SSHClient)
        dead_transport = mocker.MagicMock()
        dead_transport.is_active.return_value = False
        old_client.get_transport.return_value = dead_transport
        mcp_ssh.SSH_POOL["u@h:22"] = {"client": old_client, "last_used": time.time()}

        new_client = mocker.MagicMock(spec=paramiko.SSHClient)
        new_transport = mocker.MagicMock()
        new_transport.is_active.return_value = True
        new_client.get_transport.return_value = new_transport
        mocker.patch("mcp_ssh.paramiko.SSHClient", return_value=new_client)

        result = mcp_ssh.get_ssh_client("h", "u", 22)
        assert result is new_client
        old_client.close.assert_called()
        new_client.connect.assert_called_once()

    def test_stale_connection_send_ignore_eoferror(self, mocker):
        old_client = mocker.MagicMock(spec=paramiko.SSHClient)
        transport = mocker.MagicMock()
        transport.is_active.return_value = True
        transport.send_ignore.side_effect = EOFError
        old_client.get_transport.return_value = transport
        mcp_ssh.SSH_POOL["u@h:22"] = {"client": old_client, "last_used": time.time()}

        new_client = mocker.MagicMock(spec=paramiko.SSHClient)
        new_transport = mocker.MagicMock()
        new_transport.is_active.return_value = True
        new_client.get_transport.return_value = new_transport
        mocker.patch("mcp_ssh.paramiko.SSHClient", return_value=new_client)

        result = mcp_ssh.get_ssh_client("h", "u", 22)
        assert result is new_client
        old_client.close.assert_called()

    def test_stale_connection_transport_none(self, mocker):
        old_client = mocker.MagicMock(spec=paramiko.SSHClient)
        old_client.get_transport.return_value = None
        mcp_ssh.SSH_POOL["u@h:22"] = {"client": old_client, "last_used": time.time()}

        new_client = mocker.MagicMock(spec=paramiko.SSHClient)
        new_transport = mocker.MagicMock()
        new_transport.is_active.return_value = True
        new_client.get_transport.return_value = new_transport
        mocker.patch("mcp_ssh.paramiko.SSHClient", return_value=new_client)

        result = mcp_ssh.get_ssh_client("h", "u", 22)
        assert result is new_client

    def test_last_used_updated_on_reuse(self, mock_paramiko_client):
        mcp_ssh.get_ssh_client("h", "u", 22)
        first_ts = mcp_ssh.SSH_POOL["u@h:22"]["last_used"]

        time.sleep(0.01)
        mcp_ssh.get_ssh_client("h", "u", 22)
        second_ts = mcp_ssh.SSH_POOL["u@h:22"]["last_used"]
        assert second_ts > first_ts

    def test_accept_new_hostkey_true_uses_auto_add(self, mock_paramiko_client):
        mcp_ssh.get_ssh_client("h", "u", 22, accept_new_hostkey=True)
        calls = mock_paramiko_client.set_missing_host_key_policy.call_args_list
        assert any(isinstance(c[0][0], paramiko.AutoAddPolicy) for c in calls)

    def test_accept_new_hostkey_false_uses_reject(self, mock_paramiko_client):
        mcp_ssh.get_ssh_client("h", "u", 22, accept_new_hostkey=False)
        calls = mock_paramiko_client.set_missing_host_key_policy.call_args_list
        assert any(isinstance(c[0][0], paramiko.RejectPolicy) for c in calls)


# ============================================================
# _cleanup_idle_connections — janitor logic
# ============================================================

class _StopJanitor(Exception):
    pass


class TestCleanupIdleConnections:

    def _run_one_janitor_pass(self, mocker):
        """Let the loop body execute once, then exit infinite loop."""
        mocker.patch(
            "mcp_ssh.shutdown_event.wait", 
            side_effect=[None, _StopJanitor]
        )
        with pytest.raises(_StopJanitor):
            mcp_ssh._cleanup_idle_connections()

    def test_idle_connection_removed(self, mocker):
        mock_client = mocker.MagicMock()
        mcp_ssh.SSH_POOL["u@h:22"] = {
            "client": mock_client,
            "last_used": time.time() - 600,
        }
        self._run_one_janitor_pass(mocker)
        assert "u@h:22" not in mcp_ssh.SSH_POOL
        mock_client.close.assert_called_once()

    def test_active_connection_kept(self, mocker):
        mock_client = mocker.MagicMock()
        mcp_ssh.SSH_POOL["u@h:22"] = {
            "client": mock_client,
            "last_used": time.time(),
        }
        self._run_one_janitor_pass(mocker)
        assert "u@h:22" in mcp_ssh.SSH_POOL
        mock_client.close.assert_not_called()

    def test_close_exception_ignored(self, mocker):
        mock_client = mocker.MagicMock()
        mock_client.close.side_effect = Exception("already dead")
        mcp_ssh.SSH_POOL["u@h:22"] = {
            "client": mock_client,
            "last_used": time.time() - 600,
        }
        self._run_one_janitor_pass(mocker)
        assert "u@h:22" not in mcp_ssh.SSH_POOL

    def test_mixed_pool_only_stale_removed(self, mocker):
        stale_client = mocker.MagicMock()
        active_client = mocker.MagicMock()
        mcp_ssh.SSH_POOL["stale@h:22"] = {
            "client": stale_client,
            "last_used": time.time() - 600,
        }
        mcp_ssh.SSH_POOL["active@h:22"] = {
            "client": active_client,
            "last_used": time.time(),
        }
        self._run_one_janitor_pass(mocker)
        assert "stale@h:22" not in mcp_ssh.SSH_POOL
        assert "active@h:22" in mcp_ssh.SSH_POOL
        stale_client.close.assert_called_once()
        active_client.close.assert_not_called()
