"""Tests for the log file location, rotation and failure handling."""
import logging
import os
from logging.handlers import RotatingFileHandler

import pytest

import mcp_ssh


# ============================================================
# default_log_path — per-user log directory on each platform
# ============================================================

def test_default_log_path_linux_without_xdg():
    path = mcp_ssh.default_log_path(platform="linux", environ={}, home="/home/u")
    assert path == "/home/u/.local/state/safe-ssh-mcp/safe-ssh-mcp.log"


def test_default_log_path_linux_with_xdg_state_home():
    path = mcp_ssh.default_log_path(platform="linux", environ={"XDG_STATE_HOME": "/var/state"}, home="/home/u")
    assert path == "/var/state/safe-ssh-mcp/safe-ssh-mcp.log"


@pytest.mark.parametrize("xdg", ["", "relative/state", "."])
def test_default_log_path_linux_ignores_relative_xdg_state_home(xdg):
    path = mcp_ssh.default_log_path(platform="linux", environ={"XDG_STATE_HOME": xdg}, home="/home/u")
    assert path == "/home/u/.local/state/safe-ssh-mcp/safe-ssh-mcp.log"


def test_default_log_path_macos():
    path = mcp_ssh.default_log_path(platform="darwin", environ={"XDG_STATE_HOME": "/var/state"}, home="/Users/u")
    assert path == "/Users/u/Library/Logs/safe-ssh-mcp/safe-ssh-mcp.log"


def test_default_log_path_windows_with_localappdata():
    path = mcp_ssh.default_log_path(platform="win32", environ={"LOCALAPPDATA": "/appdata"}, home="/home/u")
    assert path == os.path.join("/appdata", "safe-ssh-mcp", "Logs", "safe-ssh-mcp.log")


def test_default_log_path_windows_without_localappdata():
    path = mcp_ssh.default_log_path(platform="win32", environ={}, home="/home/u")
    assert path == os.path.join("/home/u", "AppData", "Local", "safe-ssh-mcp", "Logs", "safe-ssh-mcp.log")


def test_default_log_path_unknown_platform_uses_the_linux_rule():
    path = mcp_ssh.default_log_path(platform="freebsd14", environ={}, home="/home/u")
    assert path == "/home/u/.local/state/safe-ssh-mcp/safe-ssh-mcp.log"


def test_default_log_path_is_absolute_on_this_machine():
    assert os.path.isabs(mcp_ssh.default_log_path())


# ============================================================
# open_log_handler — rotation, directory creation, failures
# ============================================================

def test_open_log_handler_creates_missing_directory(tmp_path):
    path = tmp_path / "a" / "b" / "x.log"
    handler = mcp_ssh.open_log_handler(str(path))
    try:
        assert isinstance(handler, RotatingFileHandler)
        assert path.parent.is_dir()
    finally:
        handler.close()


@pytest.mark.skipif(os.name == "nt", reason="POSIX permissions")
def test_open_log_handler_new_directory_is_owner_only(tmp_path):
    path = tmp_path / "logs" / "x.log"
    handler = mcp_ssh.open_log_handler(str(path))
    handler.close()
    assert (path.parent.stat().st_mode & 0o077) == 0


def test_open_log_handler_rotation_settings(tmp_path):
    handler = mcp_ssh.open_log_handler(str(tmp_path / "x.log"))
    try:
        assert handler.maxBytes == 5_000_000
        assert handler.backupCount == 3
    finally:
        handler.close()


def test_open_log_handler_relative_path_in_current_directory(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    handler = mcp_ssh.open_log_handler("x.log")
    try:
        assert handler is not None
        assert (tmp_path / "x.log").exists()
    finally:
        handler.close()


def test_log_rotates_and_keeps_three_old_files(tmp_path, monkeypatch):
    monkeypatch.setattr(mcp_ssh, "LOG_MAX_BYTES", 200)
    handler = mcp_ssh.open_log_handler(str(tmp_path / "x.log"))
    test_logger = logging.getLogger("safe-ssh-mcp-rotation-test")
    test_logger.addHandler(handler)
    test_logger.setLevel(logging.INFO)
    try:
        for i in range(200):
            test_logger.info("line %d %s", i, "x" * 50)
    finally:
        test_logger.removeHandler(handler)
        handler.close()
    assert sorted(p.name for p in tmp_path.iterdir()) == ["x.log", "x.log.1", "x.log.2", "x.log.3"]


def test_open_log_handler_cannot_create_directory(tmp_path, capsys):
    blocker = tmp_path / "file"
    blocker.write_text("")
    path = str(blocker / "sub" / "x.log")  # a file is in the way of the directory
    assert mcp_ssh.open_log_handler(path) is None
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "cannot write the log file" in captured.err
    assert path in captured.err
    assert "SAFE_SSH_MCP_LOG_FILE" in captured.err


def test_open_log_handler_path_is_a_directory(tmp_path, capsys):
    assert mcp_ssh.open_log_handler(str(tmp_path)) is None
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "logging is off" in captured.err


@pytest.mark.skipif(os.name == "nt" or (hasattr(os, "geteuid") and os.geteuid() == 0),
                    reason="needs POSIX permissions and a non-root user")
def test_open_log_handler_read_only_directory(tmp_path, capsys):
    read_only = tmp_path / "ro"
    read_only.mkdir()
    read_only.chmod(0o500)
    try:
        assert mcp_ssh.open_log_handler(str(read_only / "x.log")) is None
    finally:
        read_only.chmod(0o700)
    assert "cannot write the log file" in capsys.readouterr().err


# ============================================================
# setup_logger — defaults, env overrides, starting without a log
# ============================================================

@pytest.fixture
def fresh_logger(monkeypatch):
    """Lets setup_logger configure the shared logger from scratch, then restores it."""
    shared = logging.getLogger("safe-ssh-mcp")
    saved_handlers, saved_level = shared.handlers[:], shared.level
    shared.handlers = []
    monkeypatch.delenv("SAFE_SSH_MCP_LOG_FILE", raising=False)
    monkeypatch.delenv("SAFE_SSH_MCP_LOG_LEVEL", raising=False)
    monkeypatch.delenv("SAFE_SSH_MCP_DEV_LOGGER", raising=False)
    yield shared
    for handler in shared.handlers:
        handler.close()
    shared.handlers, shared.level = saved_handlers, saved_level


def test_setup_logger_default_level_is_info(fresh_logger, tmp_path):
    result = mcp_ssh.setup_logger(path=str(tmp_path / "x.log"))
    assert result.level == logging.INFO


def test_setup_logger_uses_default_log_path(fresh_logger, tmp_path, monkeypatch):
    target = tmp_path / "state" / "safe-ssh-mcp.log"
    monkeypatch.setattr(mcp_ssh, "default_log_path", lambda: str(target))
    result = mcp_ssh.setup_logger()
    result.info("hello")
    assert "hello" in target.read_text()


def test_setup_logger_env_file_overrides_default(fresh_logger, tmp_path, monkeypatch):
    target = tmp_path / "custom.log"
    monkeypatch.setenv("SAFE_SSH_MCP_LOG_FILE", str(target))
    monkeypatch.setattr(mcp_ssh, "default_log_path", lambda: str(tmp_path / "default.log"))
    mcp_ssh.setup_logger().info("hello")
    assert "hello" in target.read_text()
    assert not (tmp_path / "default.log").exists()


def test_setup_logger_empty_env_file_means_default(fresh_logger, tmp_path, monkeypatch):
    target = tmp_path / "default.log"
    monkeypatch.setenv("SAFE_SSH_MCP_LOG_FILE", "")
    monkeypatch.setattr(mcp_ssh, "default_log_path", lambda: str(target))
    mcp_ssh.setup_logger().info("hello")
    assert target.exists()


def test_setup_logger_env_level_debug(fresh_logger, tmp_path, monkeypatch):
    monkeypatch.setenv("SAFE_SSH_MCP_LOG_LEVEL", "debug")
    assert mcp_ssh.setup_logger(path=str(tmp_path / "x.log")).level == logging.DEBUG


def test_setup_logger_debug_lines_are_not_written_by_default(fresh_logger, tmp_path):
    target = tmp_path / "x.log"
    result = mcp_ssh.setup_logger(path=str(target))
    result.debug("quiet")
    result.info("loud")
    text = target.read_text()
    assert "loud" in text
    assert "quiet" not in text


def test_setup_logger_survives_unwritable_path(fresh_logger, tmp_path, capsys):
    """The server must start even when the log cannot be written."""
    result = mcp_ssh.setup_logger(path=str(tmp_path))  # a directory, not a file
    assert any(isinstance(h, logging.NullHandler) for h in result.handlers)
    result.info("goes nowhere")
    result.error("goes nowhere")
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.count("cannot write the log file") == 1
