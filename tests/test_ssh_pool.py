"""Tests for SSH connection pool management and janitor cleanup."""
import hashlib
import time

import paramiko
import pytest

import mcp_ssh


def make_pool_key(host, user, port, password=None, key_path=None, timeout=10, accept_new_hostkey=False):
    """Build the same pool_key used by get_ssh_client."""
    conn_str = f"{host}:{port}:{user}:{password}:{key_path}:{timeout}:{accept_new_hostkey}"
    conn_hash = hashlib.sha256(conn_str.encode()).hexdigest()[:16]
    return f"{conn_hash}:{user}@{host}:{port}"


# ============================================================
# get_ssh_client — pool logic
# ============================================================

class TestGetSshClient:

    def test_new_connection_created_when_pool_empty(self, mock_paramiko_client):
        client = mcp_ssh.get_ssh_client("host1", "user1", 22)
        mock_paramiko_client.connect.assert_called_once()
        assert make_pool_key("host1", "user1", 22) in mcp_ssh.SSH_POOL

    def test_env_var_passphrase_is_used_for_private_key(
        self, mock_paramiko_client, monkeypatch
    ):
        monkeypatch.setattr(
            mcp_ssh,
            "ssh_key_passphrase_method",
            mcp_ssh.SSH_KEY_PASSPHRASE_METHOD_ENV_VAR,
        )
        monkeypatch.setenv("SSH_KEY_PASSPHRASE", "key-passphrase")

        mcp_ssh.get_ssh_client(
            "host1",
            "user1",
            password="account-password",
            key_path="/tmp/id_ed25519",
        )

        assert mock_paramiko_client.connect.call_args.kwargs == {
            "hostname": "host1",
            "port": 22,
            "username": "user1",
            "password": "account-password",
            "timeout": 10,
            "banner_timeout": 10,
            "auth_timeout": 10,
            "key_filename": "/tmp/id_ed25519",
            "passphrase": "key-passphrase",
            "allow_agent": False,
            "look_for_keys": True,
        }

    def test_keychain_uses_ssh_agent_without_reading_key_file(
        self, mock_paramiko_client, monkeypatch
    ):
        monkeypatch.setattr(
            mcp_ssh,
            "ssh_key_passphrase_method",
            mcp_ssh.SSH_KEY_PASSPHRASE_METHOD_KEYCHAIN,
        )

        mcp_ssh.get_ssh_client("host1", "user1", key_path="/tmp/id_ed25519")

        assert mock_paramiko_client.connect.call_args.kwargs == {
            "hostname": "host1",
            "port": 22,
            "username": "user1",
            "password": None,
            "timeout": 10,
            "banner_timeout": 10,
            "auth_timeout": 10,
            "key_filename": None,
            "passphrase": None,
            "allow_agent": True,
            "look_for_keys": False,
        }

    def test_pool_key_format(self, mock_paramiko_client):
        mcp_ssh.get_ssh_client("10.0.0.1", "admin", 2222)
        assert make_pool_key("10.0.0.1", "admin", 2222) in mcp_ssh.SSH_POOL

    def test_reuse_existing_live_connection(self, mock_paramiko_client):
        client1 = mcp_ssh.get_ssh_client("h", "u", 22)
        mock_paramiko_client.connect.reset_mock()

        client2 = mcp_ssh.get_ssh_client("h", "u", 22)
        mock_paramiko_client.connect.assert_not_called()
        assert client1 is client2

    def test_stale_connection_transport_dead(self, mocker):
        pk = make_pool_key("h", "u", 22)
        old_client = mocker.MagicMock(spec=paramiko.SSHClient)
        dead_transport = mocker.MagicMock()
        dead_transport.is_active.return_value = False
        old_client.get_transport.return_value = dead_transport
        mcp_ssh.SSH_POOL[pk] = {"client": old_client, "last_used": time.time()}

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
        pk = make_pool_key("h", "u", 22)
        old_client = mocker.MagicMock(spec=paramiko.SSHClient)
        transport = mocker.MagicMock()
        transport.is_active.return_value = True
        transport.send_ignore.side_effect = EOFError
        old_client.get_transport.return_value = transport
        mcp_ssh.SSH_POOL[pk] = {"client": old_client, "last_used": time.time()}

        new_client = mocker.MagicMock(spec=paramiko.SSHClient)
        new_transport = mocker.MagicMock()
        new_transport.is_active.return_value = True
        new_client.get_transport.return_value = new_transport
        mocker.patch("mcp_ssh.paramiko.SSHClient", return_value=new_client)

        result = mcp_ssh.get_ssh_client("h", "u", 22)
        assert result is new_client
        old_client.close.assert_called()

    def test_stale_connection_transport_none(self, mocker):
        pk = make_pool_key("h", "u", 22)
        old_client = mocker.MagicMock(spec=paramiko.SSHClient)
        old_client.get_transport.return_value = None
        mcp_ssh.SSH_POOL[pk] = {"client": old_client, "last_used": time.time()}

        new_client = mocker.MagicMock(spec=paramiko.SSHClient)
        new_transport = mocker.MagicMock()
        new_transport.is_active.return_value = True
        new_client.get_transport.return_value = new_transport
        mocker.patch("mcp_ssh.paramiko.SSHClient", return_value=new_client)

        result = mcp_ssh.get_ssh_client("h", "u", 22)
        assert result is new_client

    def test_last_used_updated_on_reuse(self, mock_paramiko_client):
        pk = make_pool_key("h", "u", 22)
        mcp_ssh.get_ssh_client("h", "u", 22)
        first_ts = mcp_ssh.SSH_POOL[pk]["last_used"]

        time.sleep(0.01)
        mcp_ssh.get_ssh_client("h", "u", 22)
        second_ts = mcp_ssh.SSH_POOL[pk]["last_used"]
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
        pk = make_pool_key("h", "u", 22)
        mock_client = mocker.MagicMock()
        mcp_ssh.SSH_POOL[pk] = {
            "client": mock_client,
            "last_used": time.time() - 600,
        }
        self._run_one_janitor_pass(mocker)
        assert pk not in mcp_ssh.SSH_POOL
        mock_client.close.assert_called_once()

    def test_active_connection_kept(self, mocker):
        pk = make_pool_key("h", "u", 22)
        mock_client = mocker.MagicMock()
        mcp_ssh.SSH_POOL[pk] = {
            "client": mock_client,
            "last_used": time.time(),
        }
        self._run_one_janitor_pass(mocker)
        assert pk in mcp_ssh.SSH_POOL
        mock_client.close.assert_not_called()

    def test_close_exception_ignored(self, mocker):
        pk = make_pool_key("h", "u", 22)
        mock_client = mocker.MagicMock()
        mock_client.close.side_effect = Exception("already dead")
        mcp_ssh.SSH_POOL[pk] = {
            "client": mock_client,
            "last_used": time.time() - 600,
        }
        self._run_one_janitor_pass(mocker)
        assert pk not in mcp_ssh.SSH_POOL

    def test_mixed_pool_only_stale_removed(self, mocker):
        stale_pk = make_pool_key("h", "stale", 22)
        active_pk = make_pool_key("h", "active", 22)
        stale_client = mocker.MagicMock()
        active_client = mocker.MagicMock()
        mcp_ssh.SSH_POOL[stale_pk] = {
            "client": stale_client,
            "last_used": time.time() - 600,
        }
        mcp_ssh.SSH_POOL[active_pk] = {
            "client": active_client,
            "last_used": time.time(),
        }
        self._run_one_janitor_pass(mocker)
        assert stale_pk not in mcp_ssh.SSH_POOL
        assert active_pk in mcp_ssh.SSH_POOL
        stale_client.close.assert_called_once()
        active_client.close.assert_not_called()
