"""Shared fixtures for safe-ssh-mcp tests."""
import threading
import time

import pytest
import paramiko

# ---------------------------------------------------------------------------
# Suppress the janitor daemon thread that starts at mcp_ssh import time.
# Must happen BEFORE `import mcp_ssh`.
# ---------------------------------------------------------------------------
_original_thread_start = threading.Thread.start


def _safe_thread_start(self):
    target = getattr(self, "_target", None)
    if target is not None and getattr(target, "__name__", "") == "_cleanup_idle_connections":
        return  # silently skip janitor
    _original_thread_start(self)


threading.Thread.start = _safe_thread_start

import mcp_ssh  # noqa: E402  — must come after the patch above


# ---------------------------------------------------------------------------
# Autouse: isolate SSH_POOL between every test
# ---------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def isolate_ssh_pool():
    mcp_ssh.SSH_POOL.clear()
    yield
    mcp_ssh.SSH_POOL.clear()


# ---------------------------------------------------------------------------
# Common SSH kwargs reused across many tests
# ---------------------------------------------------------------------------
@pytest.fixture
def common_ssh_args():
    return {
        "host": "testhost",
        "user": "testuser",
        "port": 22,
        "password": None,
        "key_path": None,
        "timeout": 20,
        "accept_new_hostkey": False,
    }


# ---------------------------------------------------------------------------
# Patches mcp_ssh.run_ssh_command — used by test_tools.py
# ---------------------------------------------------------------------------
@pytest.fixture
def mock_run_ssh_command(mocker):
    mock = mocker.patch("mcp_ssh.run_ssh_command")
    mock.return_value = {
        "ok": True,
        "host": "testhost",
        "collected_at_utc": "2025-01-01T00:00:00+00:00",
        "data": {"command": "test", "exit_code": 0, "stdout": "ok", "stderr": ""},
    }
    return mock


# ---------------------------------------------------------------------------
# Patches mcp_ssh.get_ssh_client — used by test_run_ssh_command.py
# ---------------------------------------------------------------------------
@pytest.fixture
def mock_ssh_client(mocker):
    """Return a mock SSHClient and patch get_ssh_client to return it."""
    mock_client = mocker.MagicMock(spec=paramiko.SSHClient)

    mock_stdout = mocker.MagicMock()
    mock_stdout.channel.recv_exit_status.return_value = 0
    mock_stdout.read.return_value = b"output"
    mock_stderr = mocker.MagicMock()
    mock_stderr.read.return_value = b""
    mock_client.exec_command.return_value = (mocker.MagicMock(), mock_stdout, mock_stderr)

    mocker.patch("mcp_ssh.get_ssh_client", return_value=mock_client)
    return mock_client


# ---------------------------------------------------------------------------
# Patches paramiko.SSHClient class — used by test_ssh_pool.py
# ---------------------------------------------------------------------------
@pytest.fixture
def mock_paramiko_client(mocker):
    """Patch paramiko.SSHClient so get_ssh_client never opens a real connection."""
    mock_cls = mocker.patch("mcp_ssh.paramiko.SSHClient")
    instance = mock_cls.return_value
    transport = mocker.MagicMock()
    transport.is_active.return_value = True
    instance.get_transport.return_value = transport
    return instance
