#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import inspect
import socket
import configparser
import json
import os
from datetime import datetime, timezone
from typing import Optional, Dict, Any, Callable, ContextManager, List, Tuple
from contextlib import contextmanager
import signal
import threading
import time
import argparse
import sys
import re
import shlex
import logging
from logging.handlers import RotatingFileHandler
import ipaddress

import paramiko
#pip install mcp
#from mcp.server.fastmcp import FastMCP
#pip install fastmcp
from fastmcp import FastMCP


class JSONFormatter(logging.Formatter):
    """Minimal JSON log formatter (no external dependencies)."""

    def format(self, record: logging.LogRecord) -> str:
        log_record = {
            "level": record.levelname,
            "time": self.formatTime(record),
            "message": record.getMessage(),
            "name": record.name,
            "filename": record.filename,
            "lineno": record.lineno,
        }
        if record.exc_info:
            log_record["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_record)

def _setup_dev_logger() -> Optional[logging.Logger]:
    """Use the richer `json-dev-logger` (a dev-only extra) if it is both
    explicitly enabled via SAFE_SSH_MCP_DEV_LOGGER=1 and actually installed.
    Returns None so the caller can fall back to the built-in logger."""
    if os.environ.get("SAFE_SSH_MCP_DEV_LOGGER") != "1":
        return None
    try:
        from py_logger import setup_logger as _dev_setup_logger  # type: ignore
    except ImportError:
        return None
    dev_logger = _dev_setup_logger()
    # Keep only file handlers: json-dev-logger also attaches a StreamHandler,
    # which would corrupt the JSON-RPC stream when running over stdio.
    dev_logger.handlers = [h for h in dev_logger.handlers if isinstance(h, logging.FileHandler)]
    return dev_logger

LOG_DIR_NAME = "safe-ssh-mcp"
LOG_FILE_NAME = "safe-ssh-mcp.log"
# The log is rotated: at most LOG_MAX_BYTES in the current file plus LOG_BACKUP_COUNT old ones
LOG_MAX_BYTES = 5_000_000
LOG_BACKUP_COUNT = 3

def default_log_path(
    platform: str = sys.platform,
    environ: Optional[Dict[str, str]] = None,
    home: Optional[str] = None,
) -> str:
    """
    Returns the default log file path: an absolute path in the user's own log directory,
    so it does not depend on the directory the MCP client started the server in.
      Linux and others: $XDG_STATE_HOME/safe-ssh-mcp/ or ~/.local/state/safe-ssh-mcp/
      macOS:            ~/Library/Logs/safe-ssh-mcp/
      Windows:          %LOCALAPPDATA%/safe-ssh-mcp/Logs/
    """
    environ = os.environ if environ is None else environ
    home = os.path.expanduser("~") if home is None else home
    if platform == "darwin":
        log_dir = os.path.join(home, "Library", "Logs", LOG_DIR_NAME)
    elif platform.startswith("win"):
        base = environ.get("LOCALAPPDATA") or os.path.join(home, "AppData", "Local")
        log_dir = os.path.join(base, LOG_DIR_NAME, "Logs")
    else:
        base = environ.get("XDG_STATE_HOME", "")
        # the XDG spec says a relative path here is invalid and must be ignored
        if not os.path.isabs(base):
            base = os.path.join(home, ".local", "state")
        log_dir = os.path.join(base, LOG_DIR_NAME)
    return os.path.join(log_dir, LOG_FILE_NAME)

def open_log_handler(path: str) -> Optional[logging.Handler]:
    """
    Opens the rotating log file, creating its directory (owner-only) when it is missing.
    Returns None when that fails, after saying why on stderr: a log that cannot be
    written must not stop the server from starting. stderr is safe, stdout carries MCP.
    """
    try:
        log_dir = os.path.dirname(path)
        if log_dir:
            os.makedirs(log_dir, mode=0o700, exist_ok=True)
        return RotatingFileHandler(
            path, mode="a", maxBytes=LOG_MAX_BYTES, backupCount=LOG_BACKUP_COUNT, encoding="utf-8",
        )
    except OSError as e:
        print(
            f"safe-ssh-mcp: cannot write the log file {path!r} ({e}); logging is off. "
            "Set SAFE_SSH_MCP_LOG_FILE to a writable path to turn it on.",
            file=sys.stderr,
        )
        return None

def setup_logger(
    path: Optional[str] = None,
    level: int = logging.INFO,
) -> logging.Logger:
    """Configure a JSON file logger. Path/level are configurable via env vars
    (SAFE_SSH_MCP_LOG_FILE, SAFE_SSH_MCP_LOG_LEVEL); the default path is
    default_log_path() and the default level is INFO.

    By default this uses a dependency-free stdlib logger. Set
    SAFE_SSH_MCP_DEV_LOGGER=1 (with the `dev` extra installed) to opt into the
    richer git-aware `json-dev-logger` instead."""
    dev_logger = _setup_dev_logger()
    if dev_logger is not None:
        dev_logger.propagate = False
        return dev_logger

    path = os.environ.get("SAFE_SSH_MCP_LOG_FILE") or path or default_log_path()
    env_level = os.environ.get("SAFE_SSH_MCP_LOG_LEVEL")
    if env_level:
        level = getattr(logging, env_level.upper(), level)

    logger_c = logging.getLogger("safe-ssh-mcp")
    if not logger_c.handlers:
        handler = open_log_handler(path)
        if handler is None:
            handler = logging.NullHandler()
        else:
            handler.setFormatter(JSONFormatter())
        logger_c.addHandler(handler)
        logger_c.setLevel(level)
    logger_c.propagate = False
    return logger_c


# 0. Init the logger
logger = setup_logger()
logger.debug("Init logger")

# Initialize MCP Server
mcp = FastMCP("SRE Collector")

def load_config():
    config = configparser.ConfigParser()
    # Default values
    settings = {
        "transport": "stdio",  # streamable-http, http, sse, stdio
        "host": "127.0.0.1",
        "port": "8000"
    }
    script_dir = os.path.dirname(os.path.abspath(__file__))
    config_file_name = os.path.join(script_dir, "mcp_config.ini")
    if os.path.exists(config_file_name):
        config.read(config_file_name)
        if "server" in config:
            settings.update(dict(config.items("server")))     
    return settings

# ---- SSH helpers ----
SSH_KEY_PASSPHRASE_METHOD_ENV_VAR = "ENV_VAR"
SSH_KEY_PASSPHRASE_METHOD_KEYCHAIN = "KEYCHAIN"
SSH_KEY_PASSPHRASE_METHODS = {
    SSH_KEY_PASSPHRASE_METHOD_ENV_VAR,
    SSH_KEY_PASSPHRASE_METHOD_KEYCHAIN,
}
ssh_key_passphrase_method = SSH_KEY_PASSPHRASE_METHOD_ENV_VAR


def get_ssh_auth_options(key_path: Optional[str]) -> Dict[str, Any]:
    """Build Paramiko authentication options from the configured key source."""
    if ssh_key_passphrase_method == SSH_KEY_PASSPHRASE_METHOD_ENV_VAR:
        return {
            "key_filename": key_path,
            "passphrase": os.environ.get("SSH_KEY_PASSPHRASE"),
            "allow_agent": False,
            "look_for_keys": True,
        }

    if ssh_key_passphrase_method == SSH_KEY_PASSPHRASE_METHOD_KEYCHAIN:
        # The key is already unlocked in ssh-agent; do not read key_path directly.
        return {
            "key_filename": None,
            "passphrase": None,
            "allow_agent": True,
            "look_for_keys": False,
        }

    raise ValueError(
        f"Unsupported ssh_key_passphrase_method: {ssh_key_passphrase_method}"
    )


# The `timeout` every tool takes, in seconds: it comes from the caller (an LLM), so it is
# checked; 0 would mean no limit at all to GNU timeout.
TIMEOUT_DEFAULT_S = 60
TIMEOUT_MIN_S = 1
TIMEOUT_MAX_S = 360
TIMEOUT_ERROR = f"Invalid timeout: an integer from {TIMEOUT_MIN_S} to {TIMEOUT_MAX_S} (seconds)"

def is_valid_timeout(timeout: Any) -> bool:
    return (isinstance(timeout, int) and not isinstance(timeout, bool)
            and TIMEOUT_MIN_S <= timeout <= TIMEOUT_MAX_S)


def connect_ssh_client(
    client: paramiko.SSHClient,
    host: str,
    user: str,
    port: int,
    password: Optional[str],
    key_path: Optional[str],
    timeout: int,
) -> None:
    """Connect using the configured SSH key passphrase source."""
    client.connect(
        hostname=host,
        port=port,
        username=user,
        password=password,
        timeout=timeout,
        banner_timeout=timeout,
        auth_timeout=timeout,
        **get_ssh_auth_options(key_path),
    )


SSH_POOL: Dict[str, Dict[str, Any]] = {}
pool_lock = threading.Lock()
IDLE_TIMEOUT_SECONDS = 300

shutdown_event = threading.Event()

def _cleanup_idle_connections():
    """Background janitor thread to close stale SSH connections."""
    while not shutdown_event.is_set():
        shutdown_event.wait(60) # Wake up and check every 60 seconds
        if shutdown_event.is_set():
            break
        
        current_time = time.time()
        
        with pool_lock:
            keys_to_delete = []
            for pool_key, data in SSH_POOL.items():
                if current_time - data["last_used"] > IDLE_TIMEOUT_SECONDS:
                    # Connection has been idle too long, close it
                    try:
                        data["client"].close()
                    except Exception:
                        pass # Ignore errors if it's already dead
                    keys_to_delete.append(pool_key)
            
            # Remove closed connections from the pool
            for key in keys_to_delete:
                del SSH_POOL[key]
                logger.info(f"[SSH Pool Janitor] Closed idle connection: {key}")

janitor_thread = threading.Thread(target=_cleanup_idle_connections, daemon=True)
janitor_thread.start()

def shutdown_gracefully(signum, frame):
    logger.info("\n[Shutdown] Received shutdown signal, cleaning up...")
    shutdown_event.set()
    janitor_thread.join(timeout=5)
    for pool_key, data in SSH_POOL.items():
        try:
            data["client"].close()
        except Exception:
            pass
    SSH_POOL.clear()
    sys.exit(0)

signal.signal(signal.SIGTERM, shutdown_gracefully)
signal.signal(signal.SIGINT, shutdown_gracefully)


@contextmanager
def ssh_session(
    host: str,
    user: str,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = TIMEOUT_DEFAULT_S,
    accept_new_hostkey: bool = False,
) -> ContextManager[paramiko.SSHClient]:
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(
        paramiko.AutoAddPolicy() if accept_new_hostkey else paramiko.RejectPolicy()
    )

    try:
        connect_ssh_client(client, host, user, port, password, key_path, timeout)
        yield client
    finally:
        client.close()

def get_ssh_client(
    host: str,
    user: str,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = TIMEOUT_DEFAULT_S,
    accept_new_hostkey: bool = False,
) -> paramiko.SSHClient:
    """Retrieves an active SSH client from the pool or creates a new one."""
    conn_str = f"{host}:{port}:{user}:{password}:{key_path}:{timeout}:{accept_new_hostkey}"
    conn_hash = hashlib.sha256(conn_str.encode()).hexdigest()[:16]
    pool_key = f"{conn_hash}:{user}@{host}:{port}"
    
    with pool_lock:
        # 1. Check if we already have a connection
        if pool_key in SSH_POOL:
            pool_data = SSH_POOL[pool_key]
            client = pool_data["client"]
            transport = client.get_transport()
            
            # Check if connection is still alive
            if transport is not None and transport.is_active():
                try:
                    # Ping the server
                    transport.send_ignore()
                    # SUCCESS: Update the "last used" timestamp so the janitor leaves it alone
                    pool_data["last_used"] = time.time()
                    return client
                except EOFError:
                    pass
                except Exception:
                    pass
            
            # If dead, clean it up before creating a new one
            client.close()
            del SSH_POOL[pool_key]

        # 2. Create a new connection
        client = paramiko.SSHClient()
        client.load_system_host_keys()
        client.set_missing_host_key_policy(
            paramiko.AutoAddPolicy() if accept_new_hostkey else paramiko.RejectPolicy()
        )

        connect_ssh_client(client, host, user, port, password, key_path, timeout)
        
        # 3. Save to pool WITH the current timestamp
        SSH_POOL[pool_key] = {
            "client": client,
            "last_used": time.time()
        }
        return client

# Runs the command (passed as $0) in bash when the host has it, and in sh otherwise:
# Alpine and other BusyBox systems ship no bash, so tool commands must also work in sh.
SHELL_LAUNCHER = 'exec "$(command -v bash || echo sh)" -c "$0"'

# How a command stopped at the timeout reports back: 124, from GNU timeout or from the
# watchdog in TIMEOUT_SCRIPT. -1 when the remote command left no exit status: GNU timeout
# that had to send KILL (it kills its own process group, itself included), or _run_cmd
# when the output never ended (see there).
TIMEOUT_EXIT_CODES = (124, -1)

# Runs the command ($0) with a time limit of $1 seconds, then stops it AND everything it
# started. GNU timeout does that (it signals the whole process group), so it is used when
# the host has it, with -k 2: without it a command that ignores TERM is never stopped,
# with it GNU timeout sends KILL 2 s later. BusyBox timeout (Alpine)
# signals only the one process it started: the rest of a pipeline (`du | sort`) or
# anything started with `&` lives on, keeps the SSH channel open, and keeps running on
# the host after the tool has returned. Elsewhere the
# command therefore runs in its own session (setsid), and a watchdog stops that session's
# whole process group: TERM at the limit, KILL 2 s later, exit code 124 like GNU timeout.
# The watchdog tells the waiting shell with USR1, so a timeout is not mistaken for a command
# that was killed for another reason. Its own output goes to /dev/null, so it cannot hold
# the channel open, and it is stopped when the command ends first. Without setsid only the
# command's shell can be signalled, as with BusyBox timeout; _run_cmd's read deadline then
# still ends the call. ash's `kill` takes no `--`, hence `kill -TERM -PGID`; `wait` sends
# ash's "Terminated" notice to /dev/null, as it is about the wrapper, not the command.
TIMEOUT_SCRIPT = f"""L={shlex.quote(SHELL_LAUNCHER)}
case "$(timeout --version 2>/dev/null)" in
*'GNU coreutils'*) exec timeout -k 2 "$1"s sh -c "$L" "$0" ;;
esac
g=
command -v setsid >/dev/null 2>&1 && g=-
fired=
trap fired=1 USR1
${{g:+setsid}} sh -c "$L" "$0" & pid=$!
${{g:+setsid}} sh -c 'sleep "$1"; kill -USR1 "$2"; kill -TERM "$3"; sleep 2; kill -KILL "$3"' watchdog "$1" $$ "$g$pid" </dev/null >/dev/null 2>&1 & dog=$!
wait "$pid" 2>/dev/null; rc=$?
if [ -n "$fired" ]; then wait "$pid" 2>/dev/null; exit 124; fi
kill -TERM "$g$dog" 2>/dev/null
exit "$rc\""""

def is_probable_timeout(exit_code: int, elapsed_s: float, timeout_s: int) -> bool:
    """Checks whether the command was most likely killed by the remote `timeout` wrapper:
    it ended with one of the timeout exit codes AND ran for at least the timeout."""
    return exit_code in TIMEOUT_EXIT_CODES and elapsed_s >= timeout_s

def timeout_wrapped(cmd: str, timeout_s: int) -> str:
    """Wraps cmd the way every command is run on the remote host: with a time limit that
    stops the command and everything it started (TIMEOUT_SCRIPT), in bash when the host has
    it and in sh otherwise (SHELL_LAUNCHER). Anything that runs a tool's command must use
    this, or a command that relies on bash (set -o pipefail, read) breaks."""
    return f"sh -c {shlex.quote(TIMEOUT_SCRIPT)} {shlex.quote(cmd)} {int(timeout_s)}"

def _recv_all(recv, ready=None) -> tuple:
    """Collects a channel stream until it ends. Returns (bytes, ended): ended is False when
    a read hit the channel timeout, and the bytes are then what arrived until then. With
    `ready`, only reads what has already arrived and never waits."""
    chunks = []
    try:
        while ready is None or ready():
            chunk = recv(32768)
            if not chunk:
                return b"".join(chunks), True
            chunks.append(chunk)
    except socket.timeout:
        return b"".join(chunks), False
    return b"".join(chunks), False

def _run_cmd(client: paramiko.SSHClient, cmd: str, timeout_s: int = 20) -> Dict[str, Any]:
    channel_timeout_s = 5
    timeout_cmd = timeout_wrapped(cmd, timeout_s)
    started = time.monotonic()
    stdin, stdout, stderr = client.exec_command(timeout_cmd, timeout=timeout_s+channel_timeout_s)
    channel = stdout.channel
    # Read the output BEFORE waiting for the exit status: once the unread output fills the
    # SSH window (about 2 MB) the remote command blocks, and waiting for its exit status
    # first would hang until the timeout and return cut-off output.
    # stderr is read only after stdout has ended: see decision_records/run_cmd_output_reading.md
    # Bytes are collected and decoded once, so a chunk boundary cannot split a character.
    out, ended = _recv_all(channel.recv)
    if ended:
        err, _ = _recv_all(channel.recv_stderr)
        exit_code = channel.recv_exit_status()
    else:
        # The output did not end within timeout_s + channel_timeout_s: something on the host
        # still holds it open after the time limit. Keep what arrived, take only the stderr
        # that is already here (waiting for more would hang again), and give up on the exit
        # status, which would wait forever.
        err, _ = _recv_all(channel.recv_stderr, ready=channel.recv_stderr_ready)
        exit_code = -1
        channel.close()
    result = {
        "command": cmd,
        "exit_code": exit_code,
        "stdout": out.decode(errors="replace").strip(),
        "stderr": err.decode(errors="replace").strip(),
    }
    if not ended or is_probable_timeout(exit_code, time.monotonic() - started, timeout_s):
        result["timed_out"] = True
    if not ended:
        result["output_never_ended"] = True
    return result

# ---- MCP Tool Boilerplate Helper ----

def run_ssh_command(
    host: str,
    user: str,
    cmd_str: str,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout_s: int = TIMEOUT_DEFAULT_S,
    accept_new_hostkey: bool = False,
    success_exit_codes: tuple = (0,)
) -> Dict[str, Any]:
    """Helper to run an SSH command and capture generalized return payload/errors."""
    collected_at = datetime.now(timezone.utc).isoformat()
    if not is_valid_timeout(timeout_s):
        return {"ok": False, "error": TIMEOUT_ERROR}
    
    # 1. Expand the path and validate it BEFORE attempting to connect
    if key_path:
        key_path = os.path.expanduser(key_path)
        if not os.path.isfile(key_path):
            return {
                "ok": False, 
                "error": f"Configuration error: The SSH key file '{key_path}' does not exist."
            }

    try:
        client = get_ssh_client(
            host, user, port, password, key_path, timeout_s, accept_new_hostkey
        )
        result = _run_cmd(client, cmd_str, timeout_s=timeout_s)
        payload = {
            "ok": result["exit_code"] in success_exit_codes,
            "host": host,
            "collected_at_utc": collected_at,
            "data": result,
        }
        if result.get("output_never_ended"):
            payload["error"] = (
                f"The command timed out: its output was still open {timeout_s}s + 5s after it "
                "started, so the server stopped reading. The output shown is what arrived until "
                "then, and some of the command's processes may still be running on the host. "
                "Retry with a larger timeout or a narrower request."
            )
        elif result.get("timed_out"):
            payload["error"] = (
                f"The command probably timed out: it was stopped after the {timeout_s}s timeout "
                f"(exit code {result['exit_code']}). Any output is incomplete. "
                "Retry with a larger timeout or a narrower request."
            )
        return payload
        
    # 2. Provide hyper-specific feedback for authentication failures
    except paramiko.AuthenticationException:
        auth_msg = "Authentication failed. "
        if key_path:
            auth_msg += f"The key at '{key_path}' was rejected. Verify it is correct and unlocked."
        elif password:
            auth_msg += "The provided password was rejected."
        else:
            auth_msg += "No valid SSH key or password was provided, and the server rejected default keys."
        return {"ok": False, "error": auth_msg}
        
    # 3. Catch specific network/protocol errors for better AI debugging
    except socket.error as e:
        return {"ok": False, "error": f"Network error: Could not connect to {host}:{port}. ({str(e)})"}
    except paramiko.PasswordRequiredException:
        return {
            "ok": False,
            "error": (
                "The SSH key is passphrase-protected. Set SSH_KEY_PASSPHRASE "
                "or set ssh_key_passphrase_method=KEYCHAIN and unlock the key "
                "with ssh-add."
            ),
        }
    except paramiko.SSHException as e:
        return {"ok": False, "error": f"SSH protocol error: {str(e)}"}
    except Exception as e:
        return {"ok": False, "error": f"Unexpected error: {str(e)}"}

# ---- Shared validators ----

# Unit spellings accepted in a relative `since`, mapped to one canonical form that both
# systemd (journalctl, coredumpctl) and util-linux (dmesg, last, lastb) parse the same way.
SINCE_UNITS = {
    "s": "s", "sec": "s", "second": "s", "seconds": "s",
    "m": "min", "min": "min", "minute": "min", "minutes": "min",
    "h": "h", "hr": "h", "hour": "h", "hours": "h",
    "d": "d", "day": "d", "days": "d",
    "w": "w", "week": "w", "weeks": "w",
}
SINCE_KEYWORDS = ("now", "today", "yesterday")
# re.ASCII everywhere below: without it \d also matches non-ASCII digits (e.g. Arabic-Indic)
SINCE_RELATIVE_PATTERN = re.compile(r"(-)?\s*(\d{1,6})\s*([a-z]+)(\s+ago)?", re.ASCII)
SINCE_ABSOLUTE_FORMATS = ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d")
SINCE_ERROR = (
    "Invalid value of since. Use a relative time ('30 min ago', '2 hours ago', '-1d'; "
    "units: s, min, h, d, w), a keyword ('today', 'yesterday') or an absolute time in the "
    "remote host's timezone ('YYYY-MM-DD', 'YYYY-MM-DD HH:MM' or 'YYYY-MM-DD HH:MM:SS')."
)

def normalize_since(since: Any) -> Optional[str]:
    """Validates a `since` time spec and returns it in canonical form, or None if invalid.

    Accepts only the subset of the systemd.time syntax that util-linux understands too,
    so the same value works for journalctl, coredumpctl, dmesg, last and lastb:
      - relative: '30 min ago', '2h ago', '-15min'  -> '-30min', '-2h', '-15min'
      - keywords: 'now', 'today', 'yesterday'
      - absolute: 'YYYY-MM-DD', 'YYYY-MM-DD HH:MM', 'YYYY-MM-DD HH:MM:SS'
    The result contains only [0-9a-z:- ] characters, but callers must still shlex.quote it.
    """
    if not isinstance(since, str):
        return None
    value = " ".join(since.strip().lower().split())

    if value in SINCE_KEYWORDS:
        return value

    relative = SINCE_RELATIVE_PATTERN.fullmatch(value)
    if relative:
        minus, amount, unit, ago = relative.groups()
        # Exactly one of the two "in the past" markers: '-5min' or '5 min ago'
        if bool(minus) == bool(ago) or unit not in SINCE_UNITS or int(amount) == 0:
            return None
        return f"-{int(amount)}{SINCE_UNITS[unit]}"

    # strptime alone is too lenient ('2026-1-5' passes), hence the shape check
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}( \d{2}:\d{2}(:\d{2})?)?", value, re.ASCII):
        for fmt in SINCE_ABSOLUTE_FORMATS:
            try:
                datetime.strptime(value, fmt)
                return value
            except ValueError:
                continue
    return None

# Docker's own `--since` forms: a Go duration (h/m/s only) or an RFC 3339 timestamp
DOCKER_SINCE_DURATION_PATTERN = re.compile(r"(?:(\d{1,6})h)?(?:(\d{1,6})m)?(?:(\d{1,6})s)?", re.ASCII)
DOCKER_SINCE_TIMESTAMP_PATTERN = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z?", re.ASCII)
# Go durations have no day/week units, so those are converted to hours
DOCKER_SINCE_UNIT_CONVERSION = {"s": (1, "s"), "min": (1, "m"), "h": (1, "h"), "d": (24, "h"), "w": (168, "h")}
DOCKER_SINCE_ERROR = (
    "Invalid value of since. Use a relative time ('30 min ago', '2 hours ago', '-1d', "
    "or a Go duration like '30m', '1h30m'), or an absolute time in the remote host's "
    "timezone ('YYYY-MM-DD', 'YYYY-MM-DD HH:MM', 'YYYY-MM-DD HH:MM:SS' or "
    "'YYYY-MM-DDTHH:MM:SS'). 'today' and 'yesterday' are not supported for docker."
)

def normalize_since_docker(since: Any) -> Optional[str]:
    """Validates a `since` time spec for `docker logs --since` and returns it in the form
    the docker CLI expects (Go duration or RFC 3339 timestamp), or None if invalid.

    Accepts docker's native forms and the relative/absolute forms of normalize_since,
    so a caller can use the same value as for the journalctl/dmesg tools:
      - Go duration: '30m', '1h30m', '45s'
      - relative:    '30 min ago', '-2h', '1 day ago'  -> '30m', '2h', '24h'
      - absolute:    'YYYY-MM-DD', 'YYYY-MM-DD HH:MM[:SS]', 'YYYY-MM-DDTHH:MM:SS[Z]'
                     -> 'YYYY-MM-DD' or 'YYYY-MM-DDTHH:MM:SS[Z]'
    Keywords ('now', 'today', 'yesterday') have no docker equivalent and are rejected.
    The result contains only [0-9A-Za-z:-] characters, but callers must still shlex.quote it.
    """
    if not isinstance(since, str):
        return None
    value = " ".join(since.strip().split())

    duration = DOCKER_SINCE_DURATION_PATTERN.fullmatch(value.lower())
    if value and duration:
        parts = [(int(amount), unit) for amount, unit in zip(duration.groups(), "hms") if amount is not None]
        if not any(amount for amount, _ in parts):
            return None
        return "".join(f"{amount}{unit}" for amount, unit in parts)

    if DOCKER_SINCE_TIMESTAMP_PATTERN.fullmatch(value.upper()):
        timestamp = value.upper()
        try:
            datetime.strptime(timestamp.rstrip("Z"), "%Y-%m-%dT%H:%M:%S")
        except ValueError:
            return None
        return timestamp

    common = normalize_since(value)
    if common is None or common in SINCE_KEYWORDS:
        return None
    if common.startswith("-"):
        amount, unit = re.fullmatch(r"-(\d+)([a-z]+)", common).groups()
        multiplier, go_unit = DOCKER_SINCE_UNIT_CONVERSION[unit]
        return f"{int(amount) * multiplier}{go_unit}"
    date_part, _, time_part = common.partition(" ")
    if not time_part:
        return date_part
    if len(time_part) == 5:  # HH:MM - docker requires seconds
        time_part += ":00"
    return f"{date_part}T{time_part}"

# Same rule the docker daemon enforces for names; the leading alphanumeric also
# guarantees the value can never be mistaken for a command-line option.
CONTAINER_NAME_PATTERN = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{1,254}")
# Short (12 hex chars, as printed by docker ps) up to full (64 hex chars) container ID
CONTAINER_ID_PATTERN = re.compile(r"[0-9a-f]{12,64}")
CONTAINER_ERROR = (
    "Invalid container. Use a container name (ASCII alphanumeric characters, '_', '.', '-', "
    "starting with an alphanumeric one) or a container ID (12 to 64 lowercase hex characters)."
)

def is_valid_container_name(name: Any) -> bool:
    """Checks that the value is a syntactically valid docker container name."""
    return isinstance(name, str) and CONTAINER_NAME_PATTERN.fullmatch(name) is not None

def is_valid_container_id(container_id: Any) -> bool:
    """Checks that the value is a syntactically valid short or full docker container ID."""
    return isinstance(container_id, str) and CONTAINER_ID_PATTERN.fullmatch(container_id) is not None

def is_valid_container_ref(container: Any) -> bool:
    """Checks that the value is either a valid container name or a valid container ID."""
    return is_valid_container_name(container) or is_valid_container_id(container)

IMAGE_ID_PATTERN = re.compile(r"(?:sha256:)?[0-9a-f]{12,64}")
# [registry[:port]/]path[/path...][:tag][@sha256:digest], e.g. nginx, nginx:1.27,
# registry.k8s.io/pause:3.9, localhost:5000/team/app@sha256:<64 hex>.
# The leading alphanumeric guarantees the value can never be mistaken for an option.
IMAGE_NAME_PATTERN = re.compile(
    r"[a-zA-Z0-9][a-zA-Z0-9._-]*(?::[0-9]{1,5})?"      # registry host[:port] or first path component
    r"(?:/[a-z0-9]+(?:[._-]+[a-z0-9]+)*)*"              # /path components
    r"(?::[a-zA-Z0-9_][a-zA-Z0-9._-]{0,127})?"          # :tag
    r"(?:@sha256:[0-9a-f]{64})?"                        # @digest
)
IMAGE_NAME_MAX_LENGTH = 512
IMAGE_ERROR = (
    "Invalid image. Use an image name like 'nginx', 'nginx:1.27', "
    "'registry.example.com:5000/team/app:tag' or 'repo/app@sha256:<64 hex>', "
    "or an image ID (12 to 64 lowercase hex characters, optionally prefixed with 'sha256:')."
)

def is_valid_image_id(image_id: Any) -> bool:
    """Checks that the value is a syntactically valid short or full image ID."""
    return isinstance(image_id, str) and IMAGE_ID_PATTERN.fullmatch(image_id) is not None

def is_valid_image_name(image: Any) -> bool:
    """Checks that the value is a syntactically valid image name: [registry/]path[:tag][@digest]."""
    return (
        isinstance(image, str)
        and len(image) <= IMAGE_NAME_MAX_LENGTH
        and IMAGE_NAME_PATTERN.fullmatch(image) is not None
    )

def is_valid_image_ref(image: Any) -> bool:
    """Checks that the value is either a valid image name or a valid image ID."""
    return is_valid_image_name(image) or is_valid_image_id(image)

# RFC 1123 DNS label: namespaces and container names inside a pod
DNS_LABEL_PATTERN = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
# RFC 1123 DNS subdomain: names of most kubernetes objects (pods, nodes, deployments, ...)
DNS_SUBDOMAIN_PATTERN = re.compile(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?")
K8S_NAMESPACE_ERROR = (
    "Invalid namespace. Only lowercase ASCII alphanumeric characters and '-' are allowed "
    "(max 63, starting and ending with an alphanumeric one)."
)
K8S_CONTAINER_ERROR = (
    "Invalid container name. Only lowercase ASCII alphanumeric characters and '-' are allowed "
    "(max 63, starting and ending with an alphanumeric one)."
)
K8S_NAME_ERROR = (
    "Invalid resource name. Only lowercase ASCII alphanumeric characters, '-' and '.' are allowed "
    "(max 253, starting and ending with an alphanumeric one)."
)

def is_valid_dns_label(value: Any) -> bool:
    """Checks that the value is an RFC 1123 DNS label (kubernetes namespace or container name)."""
    return isinstance(value, str) and DNS_LABEL_PATTERN.fullmatch(value) is not None

def is_valid_dns_subdomain(value: Any) -> bool:
    """Checks that the value is an RFC 1123 DNS subdomain (kubernetes object name)."""
    return isinstance(value, str) and DNS_SUBDOMAIN_PATTERN.fullmatch(value) is not None

# Closed list on purpose: 'secret' and 'configmap' are excluded, since describing
# a configmap prints its data. Maps every accepted spelling to the canonical type.
K8S_DESCRIBE_RESOURCE_TYPES = {
    "pod": ("pods", "po"),
    "node": ("nodes", "no"),
    "namespace": ("namespaces", "ns"),
    "deployment": ("deployments", "deploy"),
    "statefulset": ("statefulsets", "sts"),
    "daemonset": ("daemonsets", "ds"),
    "replicaset": ("replicasets", "rs"),
    "job": ("jobs",),
    "cronjob": ("cronjobs", "cj"),
    "service": ("services", "svc"),
    "endpoints": ("ep",),
    "ingress": ("ingresses", "ing"),
    "networkpolicy": ("networkpolicies", "netpol"),
    "persistentvolumeclaim": ("persistentvolumeclaims", "pvc"),
    "persistentvolume": ("persistentvolumes", "pv"),
    "storageclass": ("storageclasses", "sc"),
    "horizontalpodautoscaler": ("horizontalpodautoscalers", "hpa"),
    "poddisruptionbudget": ("poddisruptionbudgets", "pdb"),
}
K8S_RESOURCE_TYPE_ALIASES = {
    alias: canonical
    for canonical, aliases in K8S_DESCRIBE_RESOURCE_TYPES.items()
    for alias in (canonical, *aliases)
}
K8S_RESOURCE_TYPE_ERROR = (
    "Invalid resource_type, should be one of: " + ", ".join(K8S_DESCRIBE_RESOURCE_TYPES)
)

def normalize_k8s_resource_type(resource_type: Any) -> Optional[str]:
    """Maps a resource type (canonical, plural or short name, any case) from the closed
    list of describable kubernetes resources to its canonical name, or returns None."""
    if not isinstance(resource_type, str):
        return None
    return K8S_RESOURCE_TYPE_ALIASES.get(resource_type.strip().lower())

K8S_SINCE_ERROR = (
    "Invalid value of since. Use a relative time ('30 min ago', '2 hours ago', '-1d', "
    "or a Go duration like '30m', '1h30m') or an absolute UTC time 'YYYY-MM-DDTHH:MM:SSZ'. "
    "Absolute times without the trailing 'Z', 'today' and 'yesterday' are not supported here."
)

def normalize_since_kubernetes(since: Any) -> Optional[str]:
    """Validates a `since` time spec for kubectl logs / crictl logs and returns either
    a Go duration ('30m') or an RFC 3339 UTC timestamp ('2026-11-10T14:00:00Z'), or None.

    Builds on normalize_since_docker, but both tools insist on an explicit timezone in
    absolute times, so only the 'Z' (UTC) form is accepted and dates without a time are not.
    kubectl takes the two kinds through different flags, see is_go_duration.
    """
    value = normalize_since_docker(since)
    if value is None:
        return None
    if is_go_duration(value) or value.endswith("Z"):
        return value
    return None

def is_go_duration(value: Any) -> bool:
    """Checks that the value is a Go duration made of h/m/s parts, like '30m' or '1h30m'."""
    return isinstance(value, str) and value != "" and DOCKER_SINCE_DURATION_PATTERN.fullmatch(value) is not None

# One DNS label; '_' is allowed for names like _dmarc.example.com. The leading
# alphanumeric/underscore guarantees the value can never be mistaken for an option.
HOSTNAME_LABEL = r"[a-zA-Z0-9_](?:[a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_])?"
HOSTNAME_PATTERN = re.compile(rf"{HOSTNAME_LABEL}(?:\.{HOSTNAME_LABEL})*\.?")
HOSTNAME_MAX_LENGTH = 253
DNS_NAME_ERROR = (
    "Invalid name. Use a hostname (ASCII letters, digits, '-', '_' and '.', e.g. 'example.com'; "
    "internationalized names must be given in punycode) or an IPv4/IPv6 address."
)

def is_valid_hostname(name: Any) -> bool:
    """Checks that the value is a syntactically valid ASCII DNS hostname."""
    return (
        isinstance(name, str)
        and len(name.rstrip(".")) <= HOSTNAME_MAX_LENGTH
        and HOSTNAME_PATTERN.fullmatch(name) is not None
    )

def is_valid_ip_address(address: Any) -> bool:
    """Checks that the value is a valid IPv4 or IPv6 address (no zone ID, no netmask)."""
    # The pattern keeps out zone IDs ('fe80::1%eth0'), which ipaddress would accept
    if not isinstance(address, str) or not re.fullmatch(r"[0-9a-fA-F:.]{2,45}", address):
        return False
    try:
        ipaddress.ip_address(address)
    except ValueError:
        return False
    return True

# Closed list on purpose: no ANY (refused by most servers) and no AXFR/IXFR (zone transfers)
DNS_RECORD_TYPES = ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "PTR", "SRV", "CAA")
DNS_RECORD_TYPE_ERROR = "Invalid record_type, should be one of: " + ", ".join(DNS_RECORD_TYPES)
DNS_SERVER_ERROR = (
    "Invalid server. Use the IPv4/IPv6 address or the hostname of a DNS server, e.g. '8.8.8.8'."
)

def normalize_dns_record_type(record_type: Any) -> Optional[str]:
    """Maps a DNS record type (any case) from the closed list to its canonical upper-case
    form, or returns None."""
    if not isinstance(record_type, str):
        return None
    value = record_type.strip().upper()
    return value if value in DNS_RECORD_TYPES else None

TCP_TARGET_ERROR = (
    "Invalid target_host. Use a hostname (ASCII letters, digits, '-', '_' and '.') "
    "or an IPv4/IPv6 address."
)
TCP_PORT_ERROR = "Invalid value of target_port, should be Integer from 1 to 65535"
# Seconds nc waits for the connection (per address, if the name resolves to several)
TCP_CONNECT_TIMEOUT_S = 3

def is_valid_tcp_port(port: Any) -> bool:
    """Checks that the value is a TCP port number: an integer from 1 to 65535."""
    return isinstance(port, int) and not isinstance(port, bool) and 1 <= port <= 65535

LINES_MAX = 1000
LINES_ERROR = f"Invalid value of lines, should be Integer from 1 to {LINES_MAX}"

def is_valid_lines(lines: Any) -> bool:
    """Checks that the value is a line count: an integer from 1 to LINES_MAX."""
    # bool is a subclass of int, so True/False must be excluded explicitly
    return isinstance(lines, int) and not isinstance(lines, bool) and 1 <= lines <= LINES_MAX

# Largest PID the Linux kernel can be configured to hand out (PID_MAX_LIMIT, 2^22)
PID_MAX = 4194304
PID_ERROR = f"Invalid value of pid, should be Integer from 1 to {PID_MAX}"

def is_valid_pid(pid: Any) -> bool:
    """Checks that the value is a Linux process ID: an integer from 1 to PID_MAX."""
    return isinstance(pid, int) and not isinstance(pid, bool) and 1 <= pid <= PID_MAX

# Closed list on purpose: 'debug' starts an interactive gdb session and 'dump'
# writes the raw core (process memory, may hold secrets) - neither is diagnostic-safe.
COREDUMP_COMMANDS = ("list", "info")
COREDUMP_COMMAND_ERROR = "Invalid command, should be one of: " + ", ".join(COREDUMP_COMMANDS)

def is_valid_coredump_command(command: Any) -> bool:
    """Checks that the value is one of the coredumpctl commands in the closed list."""
    return isinstance(command, str) and command in COREDUMP_COMMANDS

# systemd's own limit on a unit name (UNIT_NAME_MAX is 256 including the terminator)
SYSTEMD_UNIT_NAME_MAX = 255
SYSTEMD_UNIT_NAME_SHOWN_MAX = 60
SYSTEMD_UNIT_NAME_PATTERN = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9.\-_@:]*")
SYSTEMD_UNIT_NAME_RULES = (
    "Allowed: ASCII letters, digits and . - _ @ : , starting with a letter or digit, "
    f"at most {SYSTEMD_UNIT_NAME_MAX} characters (e.g. nginx, sshd.service, user@1000.service)."
)

def systemd_unit_name_error(name: Any) -> Optional[str]:
    """
    Says what is wrong with a systemd unit name, or returns None when it is valid.
    A name may not start with '-' (systemctl would read it as an option, e.g.
    -H user@host), so the units '-.mount' and '-.slice' cannot be asked for.
    """
    if not isinstance(name, str):
        return f"Invalid daemon name: it must be a string, got {type(name).__name__}. {SYSTEMD_UNIT_NAME_RULES}"
    if name == "":
        return f"Invalid daemon name: it is empty. {SYSTEMD_UNIT_NAME_RULES}"
    # the name is echoed back cut short, so a huge input does not make a huge error
    shown = repr(name[:SYSTEMD_UNIT_NAME_SHOWN_MAX]) + ("..." if len(name) > SYSTEMD_UNIT_NAME_SHOWN_MAX else "")
    if len(name) > SYSTEMD_UNIT_NAME_MAX:
        return f"Invalid daemon name {shown}: it is {len(name)} characters long. {SYSTEMD_UNIT_NAME_RULES}"
    if not re.fullmatch(r"[a-zA-Z0-9]", name[0]):
        return f"Invalid daemon name {shown}: it starts with {name[0]!r}. {SYSTEMD_UNIT_NAME_RULES}"
    if not SYSTEMD_UNIT_NAME_PATTERN.fullmatch(name):
        bad = sorted(set(re.sub(r"[a-zA-Z0-9.\-_@:]", "", name)))
        return (f"Invalid daemon name {shown}: it contains {', '.join(repr(c) for c in bad)}. "
                f"{SYSTEMD_UNIT_NAME_RULES}")
    return None

def is_valid_systemd_unit_name(name: Any) -> bool:
    """Checks that the value is a systemd unit name systemctl cannot read as an option."""
    return systemd_unit_name_error(name) is None

# Finds how to become root without a password prompt: nothing when already root, else
# `sudo -n` or `doas -n` (Alpine), whichever the host has. -n makes them fail at once
# instead of waiting for a password. With neither, the command runs as the login user.
AS_ROOT_PREFIX = (
    'AS_ROOT=; if [ "$(id -u)" != 0 ]; then '
    "if command -v sudo >/dev/null 2>&1; then AS_ROOT='sudo -n'; "
    "elif command -v doas >/dev/null 2>&1; then AS_ROOT='doas -n'; fi; fi; "
)

def as_root(cmd: str) -> str:
    """Runs cmd as root on the remote host when the login user is not root, through
    `sudo -n` or `doas -n`. Only for the fixed, read-only commands of the few tools that
    need root (see decision_records/as_root.md); cmd must be a single simple command
    built by the tool, never caller-supplied text.
    """
    return f"{AS_ROOT_PREFIX}$AS_ROOT {cmd}"

# Picks how to call docker: directly when the login user can reach the daemon (root, or a
# member of the docker group - `docker version` asks the daemon, so it proves access),
# otherwise through sudo -n / doas -n. The direct call comes first so that a docker-group
# user without a sudo rule keeps working.
def as_root_or_plain(cmd: str, plain_note: str) -> str:
    """
    Like as_root, but for a command that also works without root, only with less detail:
    if there is no sudo/doas, or it refuses, cmd is run as the login user after a
    plain_note line that says what is missing.
    """
    return (
        f"{AS_ROOT_PREFIX}"
        f"""if [ -n "$AS_ROOT" ] && out=$($AS_ROOT {cmd} 2>/dev/null); then printf '%s\\n' "$out"; """
        f"""else if [ "$(id -u)" != 0 ]; then echo {shlex.quote(plain_note)}; fi; {cmd}; fi"""
    )

DOCKER_PREFIX = (
    "if ! command -v docker >/dev/null 2>&1; then "
    "echo 'docker is not installed on this host' >&2; exit 127; fi; "
    "DOCKER=docker; if ! docker version >/dev/null 2>&1; then "
    f"{AS_ROOT_PREFIX}"
    'DOCKER="$AS_ROOT docker"; fi; '
)

def docker_cmd(args: str) -> str:
    """Builds `docker <args>` for the remote host, run as root through sudo -n / doas -n
    when the login user cannot reach the docker daemon (see decision_records/as_root.md).
    args must be the fixed, read-only arguments built by a tool, never caller-supplied text.
    """
    return f"{DOCKER_PREFIX}$DOCKER {args}"

def busybox_fallback(cmd: str, program: str, fallback_cmd: str, output_filter: Optional[str] = None) -> str:
    """Runs cmd; if it fails AND program is the BusyBox one (Alpine), runs fallback_cmd instead.
    BusyBox programs lack many options of their procps / util-linux namesakes.
    A failure on a non-BusyBox host is passed through unchanged: same output on stderr,
    same exit code. cmd must be a single simple command (no pipes).

    output_filter, if given, is a pipeline the output of a successful cmd is piped through;
    it runs after cmd's exit code is checked, so it cannot mask a failure.
    It is not applied to fallback_cmd.
    """
    filter_part = f" | {output_filter}" if output_filter else ""
    return (
        f"out=$({cmd} 2>&1); rc=$?; "
        f"""if [ "$rc" -eq 0 ]; then printf '%s\\n' "$out"{filter_part}; """
        f"elif {program} --help 2>&1 | grep -q BusyBox; then {fallback_cmd}; "
        """else printf '%s\\n' "$out" >&2; exit "$rc"; fi"""
    )

def tail_keeping_header(cmd: str, lines: int) -> str:
    """Pipes cmd through `tail -n lines`, but always keeps its first line (the column header),
    so `lines` counts data rows. The caller must have validated lines with is_valid_lines.

    bash's read takes exactly one line off the pipe and tail gets the rest;
    pipefail keeps cmd's exit code, which tail would otherwise mask.
    """
    return (
        f"set -o pipefail; {cmd} | "
        f"{{ IFS= read -r header && printf '%s\\n' \"$header\"; tail -n {lines}; }}"
    )

# ---- Redaction of secrets in free text ----
# Trade-off, see decision_records/redact_secrets.md: output that can hold secrets (crontabs,
# command lines, config files) is still returned, but values that LOOK like secrets are
# replaced by REDACTED before the result leaves the server, so they reach neither the model
# nor the MCP client's logs. It is pattern-based: a secret in an unusual form is still
# shown, and a harmless value that looks like one is hidden. Tools that use it say so in
# their docstring, and every result they return carries a "redaction" field.

REDACTED = "<redacted>"
# A value: quoted, or up to the next space, quote or ';' (a shell command separator, and
# the field separator of connection strings: Password=x;Database=app). Never one that is
# already redacted, so that a value matched by two rules is replaced (and counted) once;
# never one that starts with '-', so that `--token --verbose` keeps --verbose.
_SECRET_VALUE = r"""(?!<redacted>)(?!-)(?:"[^"\n]*"|'[^'\n]*'|[^\s'";]+)"""
# no bare "pass": it would also catch bypass, passthrough, ...; db_pass is the common exception
_SECRET_WORDS = r"(?:password|passwd|passphrase|db_pass|secret|token|api[-_]?key|access[-_]?key|private[-_]?key|credentials?)"
# Names that end in _KEY / _PWD / _PAT (STRIPE_KEY, MYSQL_PWD, GITHUB_PAT) hold secrets too,
# except these _KEY names, which are not secrets. PWD without a prefix is the working directory.
_NOT_SECRET_KEYS = r"(?:public|primary|foreign|unique|sort|partition|routing|cache|lookup)_key"
# Tokens recognised by their prefix wherever they appear; the prefix is kept, so the kind
# of token stays visible: Stripe live keys, GitHub tokens, Slack bot tokens, AWS access key IDs
_SECRET_SUFFIX_NAME = rf"(?![A-Za-z0-9_.]*?(?<![A-Za-z0-9]){_NOT_SECRET_KEYS}\b)[A-Za-z0-9_.]*_(?:key|pwd|pat)"
_TOKEN_PREFIXES = r"(?:sk_live_|ghp_|xoxb-|AKIA)"
_TOKEN_BODY = r"(?:(?<=sk_live_)[A-Za-z0-9]{10,}|(?<=ghp_)[A-Za-z0-9]{30,}|(?<=xoxb-)[A-Za-z0-9-]{10,}|(?<=AKIA)[A-Z0-9]{16})"
_TOKEN_PREFIX_RULE = rf"(?P<k>\b{_TOKEN_PREFIXES})(?P<v>{_TOKEN_BODY})\b"
# Each pattern has a group k (kept), a group v (replaced) and, optionally, a group s (kept).
# The order matters: a narrow rule runs before the broad one that would match the same text.
SECRET_PATTERNS = tuple(re.compile(pattern, flags) for pattern, flags in (
    # PEM private keys, whole block
    (r"(?P<k>-----BEGIN [A-Z ]*PRIVATE KEY-----)(?P<v>.*?)(?P<s>-----END [A-Z ]*PRIVATE KEY-----)", re.DOTALL),
    # scheme://user:password@host, and scheme://:password@host (Redis has no user)
    (r"(?P<k>\b[a-z][a-z0-9+.-]*://[^\s/:@'\"]*:)(?P<v>(?!<redacted>)[^\s@/'\"]+)(?=@)", re.IGNORECASE),
    # Authorization: Bearer xyz / Basic xyz / xyz
    (r"(?P<k>\bAuthorization:\s*(?:(?:Bearer|Basic|Token|Digest)\s+)?)(?P<v>(?!<redacted>)[^\s'\"]+)", re.IGNORECASE),
    (r"(?P<k>\bBearer\s+)(?P<v>[A-Za-z0-9._~+/=-]{8,})", 0),
    # --password=x, --password x, --api-key x, --db-password x, --client-secret x, ...
    # (nothing may follow the word: --password-stdin and --password-file take no secret)
    (rf"(?P<k>--[A-Za-z0-9_-]*{_SECRET_WORDS}(?:=|\s+))(?P<v>{_SECRET_VALUE})", re.IGNORECASE),
    # mysql -pSECRET (the password is attached to -p; -p alone prompts, -P is the port)
    (r"(?P<k>\b(?:mysql|mysqldump|mysqladmin|mysqlcheck|mysqlimport|mariadb|mariadb-dump|mariadb-admin)\b"
     r"[^\n|;&]*?\s-p)(?P<v>(?!<redacted>)(?:\"[^\"\n]*\"|'[^'\n]*'|[^\s'\"]+))", 0),
    # sshpass -p SECRET
    (rf"(?P<k>\bsshpass\s+-p\s*)(?P<v>{_SECRET_VALUE})", 0),
    # curl -u user:password / --user user:password
    (r"(?P<k>\s(?:-u|--user)\s*[^\s:'\"]+:)(?P<v>(?!<redacted>)[^\s'\"]+)", 0),
    # STRIPE_KEY=x, MYSQL_PWD=x, GITHUB_PAT=x, but not PRIMARY_KEY=x
    (rf"(?P<k>\b{_SECRET_SUFFIX_NAME}[\"']?\s*[=:]\s*)(?P<v>{_SECRET_VALUE})", re.IGNORECASE),
    # DB_PASSWORD=x, export API_TOKEN=x, password: x, "secret": "x"
    (rf"(?P<k>\b[A-Za-z0-9_.-]*{_SECRET_WORDS}[A-Za-z0-9_.-]*[\"']?\s*[=:]\s*)(?P<v>{_SECRET_VALUE})", re.IGNORECASE),
    # sk_live_..., ghp_..., xoxb-..., AKIA... anywhere, by the token's own prefix. Last, so that
    # a token already replaced as the value of an assignment is not counted twice.
    (_TOKEN_PREFIX_RULE, 0),
))
# Unit files quote a whole assignment: Environment="DB_PASSWORD=a b" MODE=prod. There the
# value runs to the closing quote, spaces included. Only for systemd output: in a shell line
# ("sh -c 'DB_PASS=x ./run'") the same rule would also hide the command after the value.
SYSTEMD_SECRET_PATTERNS = (re.compile(
    rf"(?P<k>(?P<q>[\"'])(?:[A-Za-z0-9_.-]*{_SECRET_WORDS}[A-Za-z0-9_.-]*|{_SECRET_SUFFIX_NAME})=)(?P<v>(?!<redacted>)[^\"'\n]+)(?=(?P=q))",
    re.IGNORECASE),) + SECRET_PATTERNS
# Mount options (fstab, mount.cifs) are comma-separated: a value ends at the next single
# comma, so the options after it stay visible (mount.cifs writes a comma inside a password
# as ",,"). cifs takes the password as password=, password2=, pass= or after a % in
# user=name%password. credentials= is a file path, hidden all the same (the broad rule
# would hide it, and the options after it). See decision_records/redact_mount_options.md.
_MOUNT_OPTION_VALUE = r"(?!<redacted>)(?:[^\s,]|,,)+"
MOUNT_SECRET_PATTERNS = tuple(re.compile(pattern, re.IGNORECASE) for pattern in (
    rf"(?P<k>(?<![^\s,])(?:password2?|passwd|pass|credentials?)=)(?P<v>{_MOUNT_OPTION_VALUE})",
    rf"(?P<k>(?<![^\s,])user(?:name)?=[^\s,%]*%)(?P<v>{_MOUNT_OPTION_VALUE})",
)) + SECRET_PATTERNS
# Lockfiles (get_lockfiles with include_contents) are read by programs, and the general rules
# would corrupt them: secretstorage==3.3.3, tokenizers==0.15.0 and "js-tokens": { look like a
# secret name with a value. So they get only rules for credentials in URLs, where a
# requirements*.txt keeps them (--index-url https://user:token@host, git+https://token@host,
# ...whl?private_token=x), and the token prefixes. A ${VAR} placeholder, filled in by pip from the environment, is not
# a secret and stays visible. See decision_records/redact_lockfiles.md.
_URL_PLACEHOLDER = r"\$\{[A-Za-z0-9_]+\}(?=@)"
LOCKFILE_SECRET_PATTERNS = tuple(re.compile(pattern, re.IGNORECASE) for pattern in (
    # scheme://user:password@host
    rf"(?P<k>\b[a-z][a-z0-9+.-]*://[^\s/:@'\"]*:)(?P<v>(?!<redacted>)(?!{_URL_PLACEHOLDER})[^\s@/'\"]+)(?=@)",
    # http(s)://token@host, git+https://token@host: there a user name alone is a token
    # (in ssh://git@host it is a plain user name, and stays)
    rf"(?P<k>\b(?:[a-z][a-z0-9.-]*\+)?https?://)(?P<v>(?!<redacted>)(?!{_URL_PLACEHOLDER})[^\s/:@'\"]+)(?=@)",
    # a token as a query parameter of a URL: ?private_token=x, &X-Amz-Signature=x, &sig=x (Azure
    # SAS). Only the value; ?branch=, ?rev=, ?tag= and #integrity stay. Lockfiles have ? and &
    # only in URLs, and a package line never has one before a name (tokenizers==0.15.0 stays).
    rf"(?P<k>[?&](?:[A-Za-z0-9_.-]*{_SECRET_WORDS}[A-Za-z0-9_.-]*|[A-Za-z0-9_.-]*signature|sig|auth)=)"
    rf"(?P<v>(?!<redacted>)(?!\$\{{)[^&#\s'\"]+)",
)) + (re.compile(_TOKEN_PREFIX_RULE),)
REDACTION_NOTE = (
    f"Values that look like secrets (passwords, tokens, keys, credentials in URLs) were replaced "
    f"with '{REDACTED}'. Redaction is pattern-based: a secret written in an unusual form may "
    f"still be shown, and a harmless value that looks like a secret may be hidden."
)

def redact_secrets(text: str, patterns: Tuple[re.Pattern, ...] = SECRET_PATTERNS) -> Tuple[str, int]:
    """Replaces values that look like secrets in free text by REDACTED. Returns the text and
    how many values were replaced. See SECRET_PATTERNS for what is caught."""
    count = 0
    for pattern in patterns:
        text, n = pattern.subn(lambda m: m.group("k") + REDACTED + (m.groupdict().get("s") or ""), text)
        count += n
    return text, count

def redact_secrets_in_result(result: Dict[str, Any],
                             patterns: Tuple[re.Pattern, ...] = SECRET_PATTERNS,
                             redactor: Optional[Callable[[str], Tuple[str, int]]] = None) -> Dict[str, Any]:
    """Redacts the stdout and stderr of a run_ssh_command result in place and adds a
    "redaction" field with the number of values replaced and REDACTION_NOTE. A result
    without output (validation or connection error) is returned unchanged. redactor, when
    given, is used instead of redact_secrets with patterns (e.g. redact_k8s_describe)."""
    if redactor is None:
        redactor = lambda text: redact_secrets(text, patterns)
    data = result.get("data")
    if not isinstance(data, dict):
        return result
    replaced = 0
    for stream in ("stdout", "stderr"):
        if isinstance(data.get(stream), str):
            data[stream], n = redactor(data[stream])
            replaced += n
    result["redaction"] = {"replaced": replaced, "note": REDACTION_NOTE}
    return result

# kubectl describe prints the environment of each container as an indented block:
#     Environment:
#       DB_PASSWORD:   s3cret
#       TLS_KEY:       line 1
#                      line 2                 <- a multi-line value goes on, indented deeper
#       API_TOKEN:     <set to the key 'token' in secret 'db'>  Optional: false
#       POD_IP:         (v1:status.podIP)
# Every literal value is replaced, as the crictl inspect tools do: a variable's name does not
# tell whether its value is a secret (MODE=x). References to a secret, a config map or a field
# hold no value and say where it comes from, so they are kept. The rest of the output goes
# through SECRET_PATTERNS (Command, Args). See decision_records/get_kubectl_describe_pod.md.
_K8S_ENV_HEADER = re.compile(r"^(?P<i>[ \t]*)Environment:[ \t]*$")
_K8S_ENV_ENTRY = re.compile(r"^(?P<k>(?P<i>[ \t]+)[A-Za-z_][A-Za-z0-9_.-]*:[ \t]+)(?P<v>\S.*)$")
_K8S_ENV_REFERENCE = re.compile(
    r"^<set to the key '[^']*' (?:in secret|of config map) '[^']*'>(?:\s+Optional: (?:true|false))?$"
    r"|^\([a-z0-9]+:[^)]*\)$"                 # fieldRef: (v1:status.podIP)
    r"|\((?:limits|requests)\.[A-Za-z0-9.-]+\)$")  # resourceFieldRef: node allocatable (limits.cpu)

def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" \t"))

def redact_k8s_describe(text: str) -> Tuple[str, int]:
    """Redacts kubectl describe output: every literal value in an Environment: block (with
    the continuation lines of a multi-line value), then SECRET_PATTERNS on the other lines.
    Returns the text and how many values were replaced."""
    lines, out, other, count, i = text.split("\n"), [], [], 0, 0
    def flush_other():
        nonlocal count
        if other:
            redacted, n = redact_secrets("\n".join(other))
            out.append(redacted)
            count += n
            other.clear()
    while i < len(lines):
        header = _K8S_ENV_HEADER.match(lines[i])
        other.append(lines[i])
        i += 1
        if not header:
            continue
        flush_other()
        entry_indent, hiding = None, False
        while i < len(lines) and lines[i].strip() and _indent(lines[i]) > len(header["i"]):
            line, entry = lines[i], _K8S_ENV_ENTRY.match(lines[i])
            if entry and entry_indent in (None, len(entry["i"])):
                entry_indent = len(entry["i"])
                hiding = entry["v"] != REDACTED and not _K8S_ENV_REFERENCE.search(entry["v"].strip())
                out.append(entry["k"] + REDACTED if hiding else line)
                count += hiding
            elif entry_indent is not None and _indent(line) > entry_indent:
                if not hiding:  # a continuation line: dropped with the value it belongs to
                    out.append(line)
            else:
                break
            i += 1
    flush_other()
    return "\n".join(out), count

## == START OF TOOLS == ##

DISK_FREE_CMD = "df -h"

@mcp.tool()
def get_disk_free(
    host: str,
    user: str,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = TIMEOUT_DEFAULT_S,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Collects disk usage (df -h) from a remote Linux host via SSH.
    """
    return run_ssh_command(host, user, DISK_FREE_CMD, port, password, key_path, timeout, accept_new_hostkey)

INODE_USAGE_CMD = "df -i"

@mcp.tool()
def get_inode_usage(
    host: str,
    user: str,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = TIMEOUT_DEFAULT_S,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Collects inode usage (df -i) from a remote Linux host via SSH.
    """
    return run_ssh_command(host, user, INODE_USAGE_CMD, port, password, key_path, timeout, accept_new_hostkey)

@mcp.tool()
def get_disk_usage(
    host: str,
    user: str,
    abs_path: str = "/",
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = TIMEOUT_DEFAULT_S,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Collects disk usage for a specific abs path from a remote Linux host via SSH.
    Returns the top 20 largest files/folders in the specified directory.
    """
    if not isinstance(abs_path, str):
        return {"ok": False, "error": "Path must be a string"}

    if os.name != 'nt':  # Skip local path validation on Windows (wrong for remote Linux)
        abs_path = os.path.normpath(abs_path)
        if not os.path.isabs(abs_path):
            return {"ok": False, "error": "Path must be absolute"}

    FORBIDDEN_CHARS = r'[|&;<>()$`{}]'
    if re.search(FORBIDDEN_CHARS, abs_path):
        return {"ok": False, "error": "Path contains forbidden characters |&;<>()$`{}"}

    quoted_path = shlex.quote(abs_path)
    cmd = f"find {quoted_path} -mindepth 1 -maxdepth 1 -exec du -sh -- {{}} + 2>/dev/null | sort -rh | head -n 20"
    result = run_ssh_command(
        host, user, cmd, port, password, key_path, timeout, accept_new_hostkey, 
        success_exit_codes=(0, 1) # du may return 1 on partial permission denied
    )
    if result["ok"]:
        result["path"] = abs_path
    return result

@mcp.tool()
def get_list_of_files(
    host: str,
    user: str,
    abs_path: str = "/",
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = TIMEOUT_DEFAULT_S,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Collects list of files for a specific abs path from a remote Linux host via SSH.
    Returns with -lah option
    """
    FORBIDDEN_CHARS = r'[|&;<>()$`{}]'

    if not isinstance(abs_path, str):
        logger.error(f"get_list_of_files tool: Path must be string")
        return {"ok": False, "error": "Path must be a string"}

    if os.name != 'nt':  # Skip local path validation on Windows (wrong for remote Linux)
        abs_path = os.path.normpath(abs_path)
        if not os.path.isabs(abs_path):
            logger.error(f"get_list_of_files tool: Path must be absolute")
            return {"ok": False, "error": "Path must be absolute"}

    if re.search(FORBIDDEN_CHARS, abs_path):
        logger.error(f"get_list_of_files tool: Filter contains forbidden characters |&;<>()$`")
        return {"ok": False, "error": "Path contains forbidden characters |&;<>()$`{}"}

    quoted_path = shlex.quote(abs_path)
    cmd = f"ls {quoted_path} -lah"
    result = run_ssh_command(
        host, user, cmd, port, password, key_path, timeout, accept_new_hostkey, 
        success_exit_codes=(0, 1) # du may return 1 on partial permission denied
    )
    if result["ok"]:
        result["path"] = abs_path
    return result

@mcp.tool()
def get_list_of_files_with_filter(
    host: str,
    user: str,
    abs_path: str = "/",
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    filter: str = "",
    timeout: int = TIMEOUT_DEFAULT_S,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Collects list of files for a specific abs path with filter (grep) applied from a remote Linux host via SSH.
    -lah option is applied.
    """
    FORBIDDEN_CHARS = r'[|&;<>()$`{}]'
    
    if not isinstance(abs_path, str):
        logger.error(f"get_list_of_files_with_filter tool: Path must be string")
        return {"ok": False, "error": "Path must be a string"}
    if os.name != 'nt':  # Skip local path validation on Windows (wrong for remote Linux)
        abs_path = os.path.normpath(abs_path)
        if not os.path.isabs(abs_path):
            logger.error(f"get_list_of_files_with_filter tool: Path must be absolute")
            return {"ok": False, "error": "Path must be absolute"}

    if re.search(FORBIDDEN_CHARS, abs_path):
        logger.error(f"get_list_of_files_with_filter tool:Path contains forbidden characters |&;<>()$`")
        return {"ok": False, "error": "Path contains forbidden characters |&;<>()$`{}"}
    quoted_path = shlex.quote(abs_path)

    if not isinstance(filter, str):
        logger.error(f"get_list_of_files_with_filter tool: Filter must be string")
        return {"ok": False, "error": "Filter must be a string"}
    if re.search(FORBIDDEN_CHARS, filter):
        logger.error(f"get_list_of_files_with_filter tool: Filter contains forbidden characters |&;<>()$`")
        return {"ok": False, "error": "Filter contains forbidden characters |&;<>()$`{}"}
    quoted_filter = shlex.quote(filter)

    # -e: the filter is always the pattern, even when it starts with "-" (otherwise
    # grep reads it as options, e.g. -r, and prints file contents)
    cmd = f"ls {quoted_path} -lah | grep -e {quoted_filter} "
    result = run_ssh_command(
        host, user, cmd, port, password, key_path, timeout, accept_new_hostkey,
        success_exit_codes=(0, 1) # du may return 1 on partial permission denied
    )
    if result["ok"]:
        result["path"] = abs_path
    return result

LOCKFILE_NAMES = (
    "composer.lock",                                                  # PHP
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml",               # Node.js
    "requirements*.txt", "poetry.lock", "uv.lock", "Pipfile.lock",    # Python
    "Gemfile.lock",                                                   # Ruby
    "go.sum",                                                         # Go
    "Cargo.lock",                                                     # Rust
)
LOCKFILE_PRUNED_DIRS = ("node_modules", "vendor", ".git", "venv", ".venv")
LOCKFILE_MAX_FILES_WITH_CONTENTS = 20
# A file is returned whole or not at all: a lockfile cut in the middle cannot be parsed.
LOCKFILE_MAX_BYTES_PER_FILE = 5_000_000
LOCKFILE_MAX_BYTES_TOTAL = 10_000_000

@mcp.tool()
def get_lockfiles(
    host: str,
    user: str,
    abs_paths: List[str],
    include_contents: bool = False,
    max_depth: int = 4,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = TIMEOUT_DEFAULT_S,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Finds dependency lockfiles under the given absolute app paths on a remote Linux host via SSH:
    composer.lock (PHP), package-lock.json, yarn.lock, pnpm-lock.yaml (Node.js),
    requirements*.txt, poetry.lock, uv.lock, Pipfile.lock (Python), Gemfile.lock (Ruby),
    go.sum (Go) and Cargo.lock (Rust).
    Skips node_modules, vendor, .git, venv and .venv directories.
    Lists the files found with size and mtime (ls -l). With include_contents=True prints the files
    instead (the first 20 found), each after a '===== <path> (<size> bytes) =====' line.
    A file is always printed WHOLE or not at all, never cut: a file over 5 MB, or one that would
    take the output over 10 MB in total, gets a '===== <path> (skipped: ...) =====' line instead.
    The output can be several MB - call without include_contents first to see the sizes,
    then narrow abs_paths to the application you need.
    With include_contents=True, credentials in URLs (--index-url https://user:<redacted>@host,
    git+https://<redacted>@host, ?private_token=<redacted>, &sig=<redacted>) and known token prefixes are replaced by '<redacted>', and
    redaction.replaced says how many; the sizes in the '=====' lines are those of the files
    on disk. Only these forms are caught, so that package names and versions stay intact:
    a secret written another way is still shown. ${VAR} placeholders stay visible.
    """
    FORBIDDEN_CHARS = r'[|&;<>()$`{}]'
    MAX_PATHS = 10

    if not isinstance(abs_paths, list) or not abs_paths:
        return {"ok": False, "error": "abs_paths must be a non-empty list of absolute paths"}
    if len(abs_paths) > MAX_PATHS:
        return {"ok": False, "error": f"At most {MAX_PATHS} paths are allowed"}
    if not isinstance(max_depth, int) or isinstance(max_depth, bool) or not (1 <= max_depth <= 10):
        return {"ok": False, "error": "Invalid value of max_depth, should be Integer from 1 to 10"}

    normalized_paths = []
    for abs_path in abs_paths:
        if not isinstance(abs_path, str):
            logger.error(f"get_lockfiles tool: Path must be string")
            return {"ok": False, "error": "Path must be a string"}
        if os.name != 'nt':  # Skip local path validation on Windows (wrong for remote Linux)
            abs_path = os.path.normpath(abs_path)
            if not os.path.isabs(abs_path):
                logger.error(f"get_lockfiles tool: Path must be absolute")
                return {"ok": False, "error": f"Path must be absolute: {abs_path}"}
        if re.search(FORBIDDEN_CHARS, abs_path):
            logger.error(f"get_lockfiles tool: Path contains forbidden characters |&;<>()$`{{}}")
            return {"ok": False, "error": "Path contains forbidden characters |&;<>()$`{}"}
        normalized_paths.append(abs_path)

    quoted_paths = " ".join(shlex.quote(p) for p in normalized_paths)
    find_cmd = (
        f"find {quoted_paths} -maxdepth {max_depth} "
        f"\\( {' -o '.join(f'-name {d}' for d in LOCKFILE_PRUNED_DIRS)} \\) -prune -o "
        f"-type f \\( {' -o '.join(f'-name {shlex.quote(n)}' for n in LOCKFILE_NAMES)} \\)"
    )
    if include_contents:
        cmd = (
            f"{find_cmd} -print 2>/dev/null | head -n {LOCKFILE_MAX_FILES_WITH_CONTENTS} | "
            "{ total=0; while IFS= read -r f; do "
            'if [ ! -r "$f" ]; then echo "===== $f (skipped: not readable) ====="; continue; fi; '
            'size=$(( $(wc -c < "$f") )); '
            f'if [ "$size" -gt {LOCKFILE_MAX_BYTES_PER_FILE} ]; then '
            f'echo "===== $f (skipped: $size bytes, over the {LOCKFILE_MAX_BYTES_PER_FILE} byte per-file limit) ====="; '
            f'elif [ $((total + size)) -gt {LOCKFILE_MAX_BYTES_TOTAL} ]; then '
            f'echo "===== $f (skipped: $size bytes, would exceed the {LOCKFILE_MAX_BYTES_TOTAL} byte total limit) ====="; '
            'else total=$((total + size)); echo "===== $f ($size bytes) ====="; cat "$f"; echo; fi; '
            "done; }"
        )
    else:
        # busybox find has no -printf, so ls -l for size and mtime
        cmd = f"{find_cmd} -exec ls -l {{}} + 2>/dev/null"
    result = run_ssh_command(
        host, user, cmd, port, password, key_path, timeout, accept_new_hostkey,
        success_exit_codes=(0, 1) # find returns 1 on partial permission denied
    )
    if include_contents:
        result = redact_secrets_in_result(result, LOCKFILE_SECRET_PATTERNS)
    if result["ok"]:
        result["paths"] = normalized_paths
    return result

@mcp.tool()
def get_is_installed(
    host: str,
    user: str,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    binary: str = "ls",
    timeout: int = TIMEOUT_DEFAULT_S,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Checks whether a binary/command is installed and callable on a remote Linux host via SSH.
    """
    FORBIDDEN_CHARS = r'[|&;<>()$`{}]'
    
    if not isinstance(binary, str):
        logger.error(f"get_is_installed tool: Binary name must be string")
        return {"ok": False, "error": "Binary name must be a string"}
    if re.search(FORBIDDEN_CHARS, binary):
        logger.error(f"get_is_installed tool: Binary name contains forbidden characters |&;<>()$`")
        return {"ok": False, "error": "Binary name contains forbidden characters |&;<>()$`{}"}
    quoted_binary = shlex.quote(binary)

    cmd = f"if command -v {quoted_binary} >/dev/null 2>&1; then echo 'installed'; else echo 'not installed'; fi"
    logger.info(cmd)
    return run_ssh_command(
        host, user, cmd, port, password, key_path, timeout, accept_new_hostkey
    )

# The source package columns are there because Debian/Ubuntu security data is keyed by
# source package (openssh, not openssh-server).
DPKG_FORMAT = (
    r"${Package}\t${Version}\t${Architecture}\t${db:Status-Abbrev}\t${source:Package}\t${source:Version}\n"
)
# A bare `dpkg-query -W` also lists removed packages whose config files are left behind
# (state 'rc'), looking just like installed ones. The second character of the status
# abbreviation is the package state: keep only 'i' (installed), so 'ii' and 'hi' (held) stay,
# 'rc' (config-files), 'iH' (half-installed) and 'iU' (unpacked) go.
DPKG_INSTALLED_FILTER = r"""awk -F'\t' 'substr($4, 2, 1) == "i"'"""
DPKG_LIST_INSTALLED = f"dpkg-query -W -f='{DPKG_FORMAT}' | {DPKG_INSTALLED_FILTER}"
DPKG_HEADER = "# dpkg, tab-separated: package version architecture status source_package source_version"

# `apk info -v` prints only name-version. The installed database also has the origin (the
# source package Alpine security data is keyed by: libcrypto3 -> openssl), one record per
# package, records separated by an empty line, each line 'X:value' (P name, V version,
# A architecture, o origin). The file lists in it (F:, R:, Z: lines) are skipped.
APK_DB_PATH = "/lib/apk/db/installed"
APK_DB_TO_TSV = (
    """awk '/^P:/ {p = substr($0, 3)} /^V:/ {v = substr($0, 3)} /^A:/ {a = substr($0, 3)} """
    """/^o:/ {o = substr($0, 3)} """
    """/^$/ {if (p != "") print p "\\t" v "\\t" a "\\t" o; p = v = a = o = ""} """
    """END {if (p != "") print p "\\t" v "\\t" a "\\t" o}'"""
)
APK_HEADER = "# apk, tab-separated: package version architecture origin"

# `rpm -qa` prints name-version-release.arch, which cannot be split reliably and has neither
# the epoch nor the source RPM. Version comparison is wrong without the epoch (1:1.0 is newer
# than 2.0), and the source RPM links a binary package to its advisories
# (openssh-server -> openssh). A package without an epoch gets 0, not rpm's '(none)'.
RPM_FORMAT = r"%{NAME}\t%|EPOCH?{%{EPOCH}}:{0}|\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{SOURCERPM}\n"
# Imported GPG keys are listed as gpg-pubkey pseudo-packages (rpm before 6.0); they are not software.
RPM_PACKAGES_FILTER = r"""awk -F'\t' '$1 != "gpg-pubkey"'"""
RPM_LIST_INSTALLED = f"rpm -qa --qf '{RPM_FORMAT}' | {RPM_PACKAGES_FILTER}"
RPM_HEADER = "# rpm, tab-separated: package epoch version release architecture source_rpm"

@mcp.tool()
def get_installed_packages(
    host: str,
    user: str,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = TIMEOUT_DEFAULT_S,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Lists installed packages with versions on a remote Linux host via SSH, using the first
    available package manager. The FIRST output line starts with '#' and names the package
    manager and the columns; the rest is one package per line:
    dpkg (Debian/Ubuntu), tab-separated: package, version, architecture, status ('ii' installed,
      'hi' installed and held), source_package, source_version. Security advisories for
      Debian/Ubuntu are keyed by SOURCE package (openssh, not openssh-server).
      Removed packages whose config files are left behind (state 'rc') are not listed.
    rpm (RHEL/Fedora/SUSE), tab-separated: package, epoch (0 if the package has none), version,
      release, architecture, source_rpm (file name of the source RPM, e.g.
      openssh-8.7p1-38.el9.src.rpm for openssh-server). Compare versions as epoch:version-release.
      Imported GPG keys (gpg-pubkey) are not listed.
    apk (Alpine), tab-separated: package, version, architecture, origin. Security advisories for
      Alpine are keyed by ORIGIN (openssl, not libcrypto3); it has the same version as the package.
    """
    cmd = (
        # pipefail keeps the exit code of dpkg-query and rpm, which awk would otherwise mask
        "set -o pipefail; if command -v dpkg-query >/dev/null 2>&1; then "
        f"echo {shlex.quote(DPKG_HEADER)}; {DPKG_LIST_INSTALLED}; "
        f"elif command -v rpm >/dev/null 2>&1; then echo {shlex.quote(RPM_HEADER)}; {RPM_LIST_INSTALLED}; "
        f"elif [ -r {APK_DB_PATH} ]; then echo {shlex.quote(APK_HEADER)}; {APK_DB_TO_TSV} {APK_DB_PATH}; "
        "elif command -v apk >/dev/null 2>&1; then echo '# apk: name-version'; apk info -v; "
        "else echo 'No supported package manager found (dpkg, rpm, apk)' >&2; exit 127; fi"
    )
    return run_ssh_command(host, user, cmd, port, password, key_path, timeout, accept_new_hostkey)

def dmesg_cmd(safe_since: Optional[str] = None) -> str:
    """Builds the get_dmesg command (as root). safe_since must come from normalize_since."""
    cmd = "dmesg"
    if safe_since is not None:
        cmd += f" --since {shlex.quote(safe_since)}"
    return as_root(cmd)

@mcp.tool()
def get_dmesg(
    host: str,
    user: str,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = TIMEOUT_DEFAULT_S,
    accept_new_hostkey: bool = False,
    since: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Collects dmesg log from a remote Linux host via SSH.
    Reading the kernel log usually requires root: when the login user is not root,
    the command is run through passwordless sudo or doas (sudo -n / doas -n).
    Optional since limits it to recent messages: '30 min ago', '2 hours ago', 'today',
    'yesterday' or 'YYYY-MM-DD HH:MM:SS'. It requires util-linux 2.37+ on the remote host;
    on older hosts dmesg fails with an unrecognized option error - then call without since.
    """
    safe_since = None
    if since is not None:
        safe_since = normalize_since(since)
        if safe_since is None:
            return {"ok": False, "error": SINCE_ERROR}
    cmd = dmesg_cmd(safe_since)
    return run_ssh_command(host, user, cmd, port, password, key_path, timeout, accept_new_hostkey)

UPTIME_CMD = "uptime"

@mcp.tool()
def get_uptime(
    host: str,
    user: str,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = TIMEOUT_DEFAULT_S,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Collects uptime from a remote Linux host via SSH
    """
    return run_ssh_command(host, user, UPTIME_CMD, port, password, key_path, timeout, accept_new_hostkey)

@mcp.tool()
def get_current_datetime(
    host: str,
    user: str,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = TIMEOUT_DEFAULT_S,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Collects current datetime from a remote Linux host via SSH
    """
    return run_ssh_command(host, user, "date", port, password, key_path, timeout, accept_new_hostkey)

# uname -n is POSIX and is there even when the hostname program is not (minimal images).
# The FQDN lookup may ask DNS, so it gets its own short timeout and is optional.
HOSTNAME_CMD = (
    "name=$(uname -n 2>/dev/null); "
    '[ -n "$name" ] || name=$(cat /proc/sys/kernel/hostname 2>/dev/null); '
    '[ -n "$name" ] || name=$(hostname 2>/dev/null); '
    """if [ -z "$name" ]; then echo 'could not read the hostname: uname -n, """
    "/proc/sys/kernel/hostname and hostname all failed' >&2; exit 1; fi; "
    """printf 'hostname: %s\\n' "$name"; """
    "fqdn=$(timeout 3 hostname -f 2>/dev/null); "
    """if [ -n "$fqdn" ]; then printf 'fqdn: %s\\n' "$fqdn"; fi"""
)

@mcp.tool()
def get_hostname(
    host: str,
    user: str,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = TIMEOUT_DEFAULT_S,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Collects the hostname of a remote Linux host via SSH, as the host itself reports it.
    Output: "hostname: <name>" (the kernel hostname, uname -n), then "fqdn: <name>"
    (hostname -f) when the host can resolve its fully qualified name; that line is
    absent otherwise.
    """
    return run_ssh_command(host, user, HOSTNAME_CMD, port, password, key_path, timeout, accept_new_hostkey)

OS_RELEASE_CMD = "cat /etc/os-release"

@mcp.tool()
def get_distroname_version(
    host: str,
    user: str,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = TIMEOUT_DEFAULT_S,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Collects distr details from os-release from a remote Linux host via SSH
    """
    return run_ssh_command(host, user, OS_RELEASE_CMD, port, password, key_path, timeout, accept_new_hostkey)

KERNEL_VERSION_CMD = "uname -srvm"

@mcp.tool()
def get_kernel_version(
    host: str,
    user: str,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = TIMEOUT_DEFAULT_S,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Collects kernel name, release, build version and architecture (uname -srvm) from a remote Linux host via SSH
    """
    return run_ssh_command(host, user, KERNEL_VERSION_CMD, port, password, key_path, timeout, accept_new_hostkey)

# One line "package: <name> <version>" with the distro package version of the C library.
# Prints nothing (and still succeeds) when the package manager or the package is missing.
LIBC_PACKAGE_GLIBC_CMD = (
    "if pkg=$(dpkg-query -W -f='package: ${binary:Package} ${Version}\\n' libc6 2>/dev/null) "
    """&& [ -n "$pkg" ]; then printf '%s\\n' "$pkg"; """
    "elif pkg=$(rpm -q --qf 'package: %{NAME} %{VERSION}-%{RELEASE}\\n' glibc 2>/dev/null); "
    """then printf '%s\\n' "$pkg"; fi"""
)
LIBC_PACKAGE_MUSL_CMD = (
    "if pkg=$(apk info -e -v musl 2>/dev/null) "
    """&& [ -n "$pkg" ]; then printf '%s\\n' "$pkg" | sed 's/^musl-/package: musl /'; fi"""
)

# musl's ldd prints its version to stderr and exits 1, hence 2>&1 and head
LIBC_VERSION_CMD = (
    "if ls /lib/ld-musl-* >/dev/null 2>&1; then ls /lib/ld-musl-*; ldd --version 2>&1 | head -n 2; "
    f"{LIBC_PACKAGE_MUSL_CMD}; "
    "else ldd --version 2>&1 | head -n 1; "
    f"{LIBC_PACKAGE_GLIBC_CMD}; fi"
)

@mcp.tool()
def get_libc_version(
    host: str,
    user: str,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = TIMEOUT_DEFAULT_S,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Collects C library implementation and version (glibc or musl) from a remote Linux host via SSH.
    Uses ldd --version; musl is detected by the presence of /lib/ld-musl-* loader.
    The last line, "package: <name> <version>", is the distro package version
    (e.g. 2.39-0ubuntu8.9, 2.34-289.el9, 1.2.6-r3) that security data is keyed by;
    it is taken from dpkg, rpm or apk and is absent on other distros.
    """
    return run_ssh_command(host, user, LIBC_VERSION_CMD, port, password, key_path, timeout, accept_new_hostkey)

@mcp.tool()
def get_sshd_effective_config(
    host: str,
    user: str,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = TIMEOUT_DEFAULT_S,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Collects the effective sshd configuration (sshd -T) from a remote Linux host via SSH.
    Shows the final values after defaults, includes and Match blocks are applied.
    Requires root, since sshd -T reads the host keys: when the login user is not root,
    the command is run through passwordless sudo or doas (sudo -n / doas -n).
    """
    # sshd lives in /usr/sbin, which is often not in PATH for non-root users
    cmd = 'SSHD=$(command -v sshd || echo /usr/sbin/sshd); ' + as_root('"$SSHD" -T')
    return run_ssh_command(host, user, cmd, port, password, key_path, timeout, accept_new_hostkey)

@mcp.tool()
def get_php_info(
    host: str,
    user: str,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = TIMEOUT_DEFAULT_S,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Collects PHP details from a remote Linux host via SSH: CLI version and SAPI,
    installed CGI (php-cgi) and FPM (php-fpm) binaries with their versions/SAPIs,
    whether php-fpm or php-cgi processes are currently running, and, if Apache
    is installed, whether mod_php is enabled in its config and loaded.
    """
    # Distros name binaries differently (php-cgi8.2, php-fpm8.2, php-fpm82), hence the globs.
    # php-cgi -v reports "(cgi-fcgi)", php-fpm -v reports "(fpm-fcgi)".
    list_bins = (
        'found=0; for b in {globs}; do [ -x "$b" ] && '
        '{{ echo "$b: $("$b" -v 2>/dev/null | head -n 1)"; found=1; }}; done; '
        '[ "$found" = 1 ] || echo "none"'
    )
    cmd = "; ".join([
        "echo '== CLI =='",
        "if command -v php >/dev/null 2>&1; then php -v 2>/dev/null | head -n 1; "
        "php -r 'echo \"SAPI: \", PHP_SAPI, PHP_EOL;'; else echo 'not installed'; fi",
        "echo '== CGI binaries =='",
        list_bins.format(globs="/usr/bin/php-cgi* /usr/local/bin/php-cgi*"),
        "echo '== FPM binaries =='",
        list_bins.format(globs="/usr/sbin/php-fpm* /usr/local/sbin/php-fpm*"),
        "echo '== Running processes =='",
        # pgrep matches the process name, not args, so it can't match this bash -c itself
        "pgrep -a '^php[0-9.]*-(fpm|cgi)' || echo 'no php-fpm or php-cgi processes'",
        "echo '== Apache mod_php =='",
        "A=$(command -v apache2 || command -v httpd || ls /usr/sbin/apache2 /usr/sbin/httpd 2>/dev/null | head -n 1)",
        "if [ -z \"$A\" ]; then echo 'apache not installed'; else "
        "echo \"$A: $(\"$A\" -v 2>/dev/null | head -n 1)\"; "
        # Only enabled config: Debian mods-enabled, RHEL conf.modules.d + httpd.conf, Alpine httpd.conf + conf.d.
        # Explicit globs rather than grep -r, which skips Debian's mods-enabled symlinks.
        # grep exits 2 when any listed path is missing (always true across distros), so test output instead
        "echo 'Enabled LoadModule directives:'; "
        "M=$(grep -hsiE '^[[:space:]]*LoadModule[[:space:]]+php[0-9_]*_module' "
        "/etc/apache2/mods-enabled/*.load /etc/apache2/httpd.conf /etc/apache2/conf.d/*.conf "
        "/etc/httpd/conf/httpd.conf /etc/httpd/conf.modules.d/*.conf); "
        "if [ -n \"$M\" ]; then echo \"$M\"; else echo '  none (mod_php not enabled)'; fi; "
        # apachectl -M reports what is really loaded, but often needs root to read the config
        "echo 'Loaded modules (apachectl -M):'; "
        "(apachectl -M || apache2ctl -M) 2>/dev/null | grep -i 'php' "
        "|| echo '  no php module reported (or apachectl -M needs root)'; fi",
    ])
    return run_ssh_command(host, user, cmd, port, password, key_path, timeout, accept_new_hostkey)

@mcp.tool()
def get_systemd_list_all(
    host: str,
    user: str,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = TIMEOUT_DEFAULT_S,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Lists all systemd units. USE THIS TOOL to check for running, stopped, or FAILED daemon/service/unit.
    """
    cmd = "systemctl list-units --all --no-pager"
    return run_ssh_command(host, user, cmd, port, password, key_path, timeout, accept_new_hostkey)

SYSTEMD_FAILED_CMD = "systemctl list-units --state=failed --no-pager"

@mcp.tool()
def get_systemd_list_failed(
    host: str,
    user: str,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = TIMEOUT_DEFAULT_S,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Lists failed systemd units. USE THIS TOOL to check for FAILED daemons/services/units.
    """
    cmd = SYSTEMD_FAILED_CMD
    return run_ssh_command(host, user, cmd, port, password, key_path, timeout, accept_new_hostkey)


@mcp.tool()
def get_systemd_list_timers(
    host: str,
    user: str,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = TIMEOUT_DEFAULT_S,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Lists all systemd timers. USE THIS TOOL to check for timers.
    """
    cmd = "systemctl list-timers --no-pager"
    return run_ssh_command(host, user, cmd, port, password, key_path, timeout, accept_new_hostkey)

@mcp.tool()
def get_systemd_status(
    daemon: str,
    host: str,
    user: str,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = TIMEOUT_DEFAULT_S,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Gets the detailed status, logs, and error messages for a SPECIFIC systemd daemon/service/unit.
    daemon is a unit name such as nginx, sshd.service or user@1000.service: ASCII letters,
    digits and . - _ @ : only, starting with a letter or digit, at most 255 characters.
    Process command lines and log lines in the output can hold secrets.
    Values that look like secrets (passwords, tokens, keys, credentials in URLs) are replaced
    by '<redacted>' before the output is returned; the "redaction" field of the result says
    how many. It is pattern-based: a secret in an unusual form may still be shown, and a
    harmless value that looks like one may be hidden.
    """
    error = systemd_unit_name_error(daemon)
    if error:
        logger.error(f"get_systemd_status tool: {error}")
        return {"ok": False, "error": error}
    # --: whatever follows is a unit name, never a systemctl option
    cmd = f"systemctl status -- {shlex.quote(daemon)}"
    result = run_ssh_command(host, user, cmd, port, password, key_path, timeout, accept_new_hostkey)
    return redact_secrets_in_result(result)

def systemd_unit_definition_cmd(daemon: str) -> str:
    """Builds the get_systemd_unit_definition command; daemon must already be validated."""
    # --: whatever follows is a unit name, never a systemctl option
    return f"systemctl cat --no-pager -- {shlex.quote(daemon)}"

@mcp.tool()
def get_systemd_unit_definition(
    daemon: str,
    host: str,
    user: str,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = TIMEOUT_DEFAULT_S,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Gets the definition of a SPECIFIC systemd daemon/service/unit as systemd reads it
    (systemctl cat): the unit file and every drop-in override, each after a '# /path' line.
    USE THIS TOOL to see how a unit is run: ExecStart=, User=, WorkingDirectory=, Restart=,
    StandardOutput= / StandardError= (where the program's output goes when it is not in the
    journal), Environment= and EnvironmentFile= (only its path: the file's contents are not
    read). A setting that is absent has its systemd default (StandardOutput=journal, Restart=no).
    daemon is a unit name such as nginx, sshd.service or user@1000.service: ASCII letters,
    digits and . - _ @ : only, starting with a letter or digit, at most 255 characters.
    Values that look like secrets (passwords, tokens, keys, credentials in URLs) are replaced
    by '<redacted>' before the output is returned; the "redaction" field of the result says
    how many. It is pattern-based: a secret in an unusual form may still be shown, and a
    harmless value that looks like one may be hidden.
    """
    error = systemd_unit_name_error(daemon)
    if error:
        logger.error(f"get_systemd_unit_definition tool: {error}")
        return {"ok": False, "error": error}
    cmd = systemd_unit_definition_cmd(daemon)
    result = run_ssh_command(host, user, cmd, port, password, key_path, timeout, accept_new_hostkey)
    return redact_secrets_in_result(result, SYSTEMD_SECRET_PATTERNS)

# BusyBox ps (Alpine) has neither `aux --sort` nor %cpu/%mem columns, so each tool tries
# procps first and falls back to a BusyBox command when ps rejects the options.
# The ps output is captured, not piped, so that a failing ps is noticed.
# Rows are cut with awk, which reads its whole input: head would close the pipe early
# and, with pipefail on, turn a long process list into exit code 141 (SIGPIPE).
BUSYBOX_TOP_CPU_HEADER = "# BusyBox: top -b -n 1, sorted by CPU usage at this moment"
# the first 3 lines of BusyBox top are the Mem/CPU/Load summary
PS_TOP_CPU_CMD = (
    "set -o pipefail; "
    """if out=$(ps aux --sort=-%cpu 2>/dev/null); then printf '%s\\n' "$out" | awk 'NR <= 10'; """
    f"else echo {shlex.quote(BUSYBOX_TOP_CPU_HEADER)}; top -b -n 1 | awk 'NR > 3 && NR <= 13'; fi"
)
BUSYBOX_TOP_MEM_HEADER = "# BusyBox: ps -o pid,user,rss,vsz,args, sorted by RSS"
# BusyBox prints big sizes with a suffix (12m, 1.5g), so RSS is turned into a number to sort on
BUSYBOX_RSS_SORT = (
    """awk '{v = $3 + 0; if ($3 ~ /m$/) v *= 1024; else if ($3 ~ /g$/) v *= 1048576; print v "\\t" $0}' """
    "| sort -n -r | awk 'NR <= 9' | cut -f 2-"
)
PS_TOP_MEM_CMD = (
    "set -o pipefail; "
    """if out=$(ps aux --sort=-%mem 2>/dev/null); then printf '%s\\n' "$out" | awk 'NR <= 10'; """
    f"else echo {shlex.quote(BUSYBOX_TOP_MEM_HEADER)}; ps -o pid,user,rss,vsz,args | "
    f"""{{ IFS= read -r header && printf '%s\\n' "$header"; {BUSYBOX_RSS_SORT}; }}; fi"""
)

@mcp.tool()
def get_ps_aux_top_cpu_consumers(
    host: str,
    user: str,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = TIMEOUT_DEFAULT_S,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Lists top 10 cpu consumers, CPU desc (ps aux --sort=-%cpu).
    On BusyBox hosts (Alpine), where ps cannot sort, the output comes from `top -b -n 1`
    instead: its first line starts with '# BusyBox', the columns differ, and %CPU is the
    usage at this moment, not the average over the process lifetime that ps reports.
    Process command lines can hold secrets (--password=..., URLs with credentials).
    Values that look like secrets (passwords, tokens, keys, credentials in URLs) are replaced
    by '<redacted>' before the output is returned; the "redaction" field of the result says
    how many. It is pattern-based: a secret in an unusual form may still be shown, and a
    harmless value that looks like one may be hidden.
    """
    cmd = PS_TOP_CPU_CMD
    result = run_ssh_command(host, user, cmd, port, password, key_path, timeout, accept_new_hostkey)
    return redact_secrets_in_result(result)

@mcp.tool()
def get_ps_aux_top_mem_consumers(
    host: str,
    user: str,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = TIMEOUT_DEFAULT_S,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Lists top 10 mem consumers, MEM desc (ps aux --sort=-%mem).
    On BusyBox hosts (Alpine), where ps cannot sort and has no %MEM, the output is
    `ps -o pid,user,rss,vsz,args` sorted by RSS instead: its first line starts with
    '# BusyBox' and sizes are in KB unless they carry an m or g suffix.
    Process command lines can hold secrets (--password=..., URLs with credentials).
    Values that look like secrets (passwords, tokens, keys, credentials in URLs) are replaced
    by '<redacted>' before the output is returned; the "redaction" field of the result says
    how many. It is pattern-based: a secret in an unusual form may still be shown, and a
    harmless value that looks like one may be hidden.
    """
    cmd = PS_TOP_MEM_CMD
    result = run_ssh_command(host, user, cmd, port, password, key_path, timeout, accept_new_hostkey)
    return redact_secrets_in_result(result)

FREE_MEMORY_CMD = "free -h && echo && cat /proc/meminfo"

@mcp.tool()
def get_free_memory(
    host: str,
    user: str,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = TIMEOUT_DEFAULT_S,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Returns free memory, swap (total/free), page cache, HugePages and so on
    """
    cmd = FREE_MEMORY_CMD
    return run_ssh_command(host, user, cmd, port, password, key_path, timeout, accept_new_hostkey)

@mcp.tool()
def get_mounts(
    host: str,
    user: str,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = TIMEOUT_DEFAULT_S,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Lists mounted filesystems with their mount point, source device, filesystem type and
    mount options (findmnt, as a tree; /proc/mounts if findmnt is not installed).
    USE THIS TOOL to find a filesystem that was remounted read-only after an error ('ro' in
    the options), to check options like noexec/nosuid, and to see network (nfs, cifs),
    overlay and tmpfs mounts. For free space use get_disk_free instead.
    """
    cmd = "if command -v findmnt >/dev/null 2>&1; then findmnt; else cat /proc/mounts; fi"
    return run_ssh_command(host, user, cmd, port, password, key_path, timeout, accept_new_hostkey)

@mcp.tool()
def get_fstab(
    host: str,
    user: str,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = TIMEOUT_DEFAULT_S,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Returns /etc/fstab of a remote Linux host via SSH as written, comments included: the
    filesystems and swap configured to be mounted at boot, with their sources (UUID=, LABEL=
    or a device), mount points, types and options (noauto, nofail, ro, ...).
    What is mounted now is get_mounts; to find fstab entries that are not mounted, mounted
    read-only by mistake or would fail on the next boot, use get_mount_problems.
    Mount options can hold secrets (cifs password=, user=name%password).
    Values that look like secrets (passwords, tokens, keys, credentials in URLs) are replaced
    by '<redacted>' before the output is returned; the "redaction" field of the result says
    how many. It is pattern-based: a secret in an unusual form may still be shown, and a
    harmless value that looks like one may be hidden.
    """
    cmd = "cat /etc/fstab"
    result = run_ssh_command(host, user, cmd, port, password, key_path, timeout, accept_new_hostkey)
    return redact_secrets_in_result(result, MOUNT_SECRET_PATTERNS)

MOUNT_PROBLEMS_VERIFY_PLAIN_NOTE = (
    "# not run as root (no sudo -n / doas -n access): on-disk filesystem types were not "
    "checked, so 'cannot detect on-disk filesystem type' warnings can be ignored"
)
# Part 1: every fstab entry is looked up in /proc/mounts (by mount point, so UUID= and
# LABEL= need no resolving) or, for swap, in /proc/swaps. Mount points are compared as
# written: both files escape spaces as \040. Part 2: findmnt --verify, where it exists.
# Problems are reported in the output and the command exits 0: a host with problems is
# a correct answer, not a failed call.
# Plain sh (BusyBox ash too). The placeholders are replaced by mount_problems_cmd.
MOUNT_PROBLEMS_SCRIPT = r"""fstab=@FSTAB@
if [ ! -e "$fstab" ]; then echo "# $fstab does not exist: nothing is configured to be mounted at boot"; exit 0; fi
entries=$(awk '!/^[ \t]*(#|$)/ { print $1 "\t" $2 "\t" $3 "\t" $4 }' "$fstab") || exit
mounts=$(cat @MOUNTS@) || exit
swaps=$(awk 'NR > 1 { print $1 }' @SWAPS@ 2>/dev/null)
tab=$(printf '\t')
checked=0; skipped=0; problems=0
problem() { problems=$((problems + 1)); echo "$1"; }
echo "# fstab entries compared with what is mounted now (/proc/mounts, /proc/swaps)"
while IFS="$tab" read -r src target type opts; do
    [ -n "$src" ] || continue
    entry="$src $target $type $opts"
    case ",$opts," in *,noauto,*) skipped=$((skipped + 1)); continue ;; esac
    [ "$type" = ignore ] && { skipped=$((skipped + 1)); continue; }
    case ",$opts," in *,nofail,*) nofail=" (nofail: the boot went on without it)" ;; *) nofail= ;; esac
    if [ "$type" = swap ]; then
        checked=$((checked + 1))
        spec=$(printf '%s' "$src" | tr -d '"')
        case "$spec" in
            UUID=*) dev=@DEV_DISK@/by-uuid/${spec#UUID=} ;;
            LABEL=*) dev=@DEV_DISK@/by-label/${spec#LABEL=} ;;
            PARTUUID=*) dev=@DEV_DISK@/by-partuuid/${spec#PARTUUID=} ;;
            PARTLABEL=*) dev=@DEV_DISK@/by-partlabel/${spec#PARTLABEL=} ;;
            *) dev=$spec ;;
        esac
        real=$(readlink -f "$dev" 2>/dev/null)
        if [ -z "$real" ] || [ ! -e "$real" ]; then
            problem "SWAP NOT FOUND$nofail: $entry -- $spec is not an existing device or file"
            continue
        fi
        active=
        for s in $swaps; do [ "$(readlink -f "$s" 2>/dev/null)" = "$real" ] && active=1; done
        [ -n "$active" ] || problem "SWAP NOT ACTIVE$nofail: $entry"
        continue
    fi
    case "$target" in /*) ;; *) skipped=$((skipped + 1)); continue ;; esac
    checked=$((checked + 1))
    # the last match is the mount on top, the one in use
    mounted=$(printf '%s\n' "$mounts" | T="$target" awk '
        function norm(p) { if (p != "/") sub(/\/+$/, "", p); return p }
        BEGIN { t = norm(ENVIRON["T"]) }
        norm($2) == t { line = $0 } END { print line }')
    if [ -z "$mounted" ]; then problem "NOT MOUNTED$nofail: $entry"; continue; fi
    case ",$opts," in *,ro,*) continue ;; esac
    mounted_opts=$(printf '%s\n' "$mounted" | awk '{ print $4 }')
    case ",$mounted_opts," in
        *,ro,*) problem "READ-ONLY: $entry -- configured read-write but mounted read-only, usually remounted after I/O errors (errors=remount-ro): $mounted" ;;
    esac
done <<EOF
$entries
EOF
summary="$checked fstab entries checked"
[ "$skipped" -gt 0 ] && summary="$summary; $skipped skipped: noauto, type ignore or no mount point"
if [ "$problems" -eq 0 ]; then echo "no problems found ($summary)"; else echo "$problems problem(s) ($summary)"; fi
echo
if command -v findmnt >/dev/null 2>&1 && findmnt --help 2>&1 | grep -q -- --verify; then
    echo "# findmnt --verify: would every fstab entry mount on the next boot? ([E] error, [W] warning)"
    @AS_ROOT_PREFIX@
    verified=
    if [ -n "$AS_ROOT" ]; then
        out=$($AS_ROOT findmnt --verify --tab-file "$fstab" 2>&1)
        # a refusal of sudo/doas, not findmnt's answer (findmnt exits 1 for problems it finds)
        case "$out" in sudo:*|doas:*) ;; *) verified=1 ;; esac
    fi
    if [ -z "$verified" ]; then
        [ "$(id -u)" = 0 ] || echo @PLAIN_NOTE@
        out=$(findmnt --verify --tab-file "$fstab" 2>&1)
    fi
    printf '%s\n' "$out"
else
    echo "# findmnt --verify is not available on this host (it needs util-linux 2.29+): fstab sources, mount points and filesystem types were not checked"
fi"""

def mount_problems_cmd(
    fstab: str = "/etc/fstab",
    mounts: str = "/proc/mounts",
    swaps: str = "/proc/swaps",
    dev_disk: str = "/dev/disk",
) -> str:
    """Builds the get_mount_problems command. The paths are there for the tests."""
    replacements = {
        "@FSTAB@": shlex.quote(fstab),
        "@MOUNTS@": shlex.quote(mounts),
        "@SWAPS@": shlex.quote(swaps),
        "@DEV_DISK@": shlex.quote(dev_disk),
        "@AS_ROOT_PREFIX@": AS_ROOT_PREFIX,
        "@PLAIN_NOTE@": shlex.quote(MOUNT_PROBLEMS_VERIFY_PLAIN_NOTE),
    }
    cmd = MOUNT_PROBLEMS_SCRIPT
    for placeholder, value in replacements.items():
        cmd = cmd.replace(placeholder, value)
    return cmd

@mcp.tool()
def get_mount_problems(
    host: str,
    user: str,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = TIMEOUT_DEFAULT_S,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Finds filesystem mount problems on a remote Linux host via SSH, by checking /etc/fstab
    against what is mounted now. USE THIS TOOL when a filesystem or disk is missing, the host
    did not come back after a reboot, or writes fail with "Read-only file system".
    Part 1 prints one line per problem, then a summary ('no problems found (N fstab entries
    checked)' when all is well):
      NOT MOUNTED       - configured in fstab but not mounted now;
      READ-ONLY         - configured read-write but mounted read-only: the kernel usually
                          remounts a filesystem read-only after I/O errors;
      SWAP NOT ACTIVE / SWAP NOT FOUND - a configured swap is off, or its device is gone.
    noauto entries are skipped. "(nofail ...)" means the boot did not wait for it.
    Part 2 is findmnt --verify: would each entry still mount on the NEXT boot (the source
    device exists, the mount point exists, the type matches the disk)? An entry can be
    mounted now and still fail then, e.g. after fstab was edited or a disk was replaced.
    It runs through sudo -n / doas -n when the login user is not root (only root can read
    the on-disk filesystem type); if that is not allowed, it runs as the login user after a
    "# not run as root" line. Where findmnt is missing or too old (e.g. Alpine) part 2 says so.
    To see the whole fstab use get_fstab; for everything mounted now use get_mounts.
    Mount options in the output can hold secrets (cifs password=, user=name%password).
    Values that look like secrets (passwords, tokens, keys, credentials in URLs) are replaced
    by '<redacted>' before the output is returned; the "redaction" field of the result says
    how many. It is pattern-based: a secret in an unusual form may still be shown, and a
    harmless value that looks like one may be hidden.
    """
    cmd = mount_problems_cmd()
    result = run_ssh_command(host, user, cmd, port, password, key_path, timeout, accept_new_hostkey)
    return redact_secrets_in_result(result, MOUNT_SECRET_PATTERNS)

PRESSURE_CMD = (
    'for r in cpu io memory; do echo "== $r =="; '
    "cat /proc/pressure/$r 2>/dev/null || echo 'PSI not supported'; done"
)

@mcp.tool()
def get_pressure(
    host: str,
    user: str,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = TIMEOUT_DEFAULT_S,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Returns Linux pressure stall information (PSI) for CPU, I/O and memory in one call.
    USE THIS TOOL to tell which resource the host is short of: unlike load average, it shows
    how much time tasks actually spent waiting for each resource.
    'some' = share of time at least one task was stalled, 'full' = all non-idle tasks were stalled
    at once; avg10/avg60/avg300 are percentages over the last 10, 60 and 300 seconds,
    total is the cumulative stall time in microseconds.
    Prints 'PSI not supported' for a resource if the kernel is older than 4.20 or PSI is disabled.
    """
    cmd = PRESSURE_CMD
    return run_ssh_command(host, user, cmd, port, password, key_path, timeout, accept_new_hostkey)

def vmstat_cmd(samples: int = 5) -> str:
    """vmstat, `samples` reports 1 second apart; the first is the average since boot."""
    return f"vmstat 1 {samples}"

@mcp.tool()
def get_vmstat(
    host: str,
    user: str,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = TIMEOUT_DEFAULT_S,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Samples system activity for 4 seconds with vmstat (5 reports, 1 second apart): run queue and
    blocked processes (r, b), memory, swap-in/out (si, so), block I/O (bi, bo), interrupts and
    context switches (in, cs) and the CPU split (us, sy, id, wa, st).
    USE THIS TOOL to see what the host is doing right now: swapping, I/O wait, CPU saturation.
    The FIRST report line is the average since boot - judge the current state by the other four.
    """
    cmd = vmstat_cmd()
    return run_ssh_command(host, user, cmd, port, password, key_path, timeout, accept_new_hostkey)

# ---- get_iostat / get_mpstat: sysstat, or the same numbers computed from /proc ----

SAMPLES_MAX = 30
INTERVAL_MAX = 10
SAMPLES_ERROR = f"Invalid value of samples, should be Integer from 1 to {SAMPLES_MAX}"
INTERVAL_ERROR = f"Invalid value of interval, should be Integer from 1 to {INTERVAL_MAX} (seconds)"
# time left for connecting and printing once the sampling is over
SAMPLING_TIMEOUT_MARGIN_S = 5

def sampling_error(samples: Any, interval: Any, timeout: Any) -> Optional[str]:
    """Says what is wrong with samples / interval, or returns None when they are valid
    and the sampling (samples * interval seconds) fits in the timeout."""
    for value, error in ((samples, SAMPLES_ERROR), (interval, INTERVAL_ERROR)):
        if not isinstance(value, int) or isinstance(value, bool):
            return error
    if not 1 <= samples <= SAMPLES_MAX:
        return SAMPLES_ERROR
    if not 1 <= interval <= INTERVAL_MAX:
        return INTERVAL_ERROR
    needed = samples * interval + SAMPLING_TIMEOUT_MARGIN_S
    if isinstance(timeout, int) and timeout < needed:
        return (f"samples={samples} x interval={interval}s takes {samples * interval}s: "
                f"set timeout to at least {needed}, or ask for fewer samples")
    return None

# Where sysstat is missing, the tools read the kernel counters themselves: one snapshot,
# then one more after each interval. Every snapshot starts with an "@" line, then the
# uptime (to know how long the interval really was), then the files the tool needs.
# The snapshots are kept in a variable and handed to awk at the end in one go.
def proc_sampling_cmd(read_counters: str, samples: int, interval: int, proc_dir: str) -> str:
    snap = f"echo @; cat {shlex.quote(proc_dir + '/uptime')}; {read_counters}"
    return (
        f"snaps=$({snap}) || exit; i=0; "
        f'while [ "$i" -lt {samples} ]; do sleep {interval}; '
        f'snaps="$snaps\n$({snap})" || exit; i=$((i + 1)); done; '
    )

# /proc/stat cpu fields: $2 user, $3 nice, $4 system, $5 idle, $6 iowait, $7 irq,
# $8 softirq, $9 steal, $10 guest, $11 guest_nice. guest is already counted in user and
# guest_nice in nice, so the total is $2..$9, and user / nice are shown without them,
# as sysstat does. A counter that went backwards (idle can, on some kernels) counts as 0.
PROC_CPU_AWK_FUNCTIONS = r"""
function delta(a, b, name, i,   x) { x = v[b, name, i] - v[a, name, i]; return x > 0 ? x : 0 }
function cpu_pct(a, b, name,   i, tot) {
    tot = 0
    for (i = 2; i <= 9; i++) { p[i] = delta(a, b, name, i); tot += p[i] }
    p[10] = delta(a, b, name, 10); p[11] = delta(a, b, name, 11)
    p[2] = p[2] > p[10] ? p[2] - p[10] : 0
    p[3] = p[3] > p[11] ? p[3] - p[11] : 0
    for (i = 2; i <= 11; i++) p[i] = tot > 0 ? 100 * p[i] / tot : 0
    return tot
}
"""

IOSTAT_SYSSTAT_FILTER = (
    # loop and ram devices are noise; repeated blank lines are squeezed into one
    "awk '/^(loop|ram)[0-9]/ { next } /^$/ { if (blank++) next; print; next } { blank = 0; print }'"
)
IOSTAT_PROC_AWK = PROC_CPU_AWK_FUNCTIONS + r"""
BEGIN { n = split(disks, list, " "); for (i = 1; i <= n; i++) if (list[i] !~ /^(loop|ram)[0-9]/) disk[list[i]] = 1 }
$1 == "@" { k++; want_uptime = 1; next }
want_uptime { up[k] = $1; want_uptime = 0; next }
$1 == "cpu" { for (i = 2; i <= 11; i++) v[k, "all", i] = $i + 0; next }
($3 in disk) {
    if (k == 1) order[++nd] = $3
    for (i = 4; i <= 14; i++) d[k, $3, i] = $i + 0
}
function dd(a, b, name, i,   x) { x = d[b, name, i] - d[a, name, i]; return x > 0 ? x : 0 }
END {
    for (s = 2; s <= k; s++) {
        dt = up[s] - up[s - 1]; if (dt <= 0) dt = 0.01
        cpu_pct(s - 1, s, "all")
        print "avg-cpu:  %user   %nice %system %iowait  %steal   %idle"
        printf "         %7.2f %7.2f %7.2f %7.2f %7.2f %7.2f\n\n", p[2], p[3], p[4] + p[7] + p[8], p[6], p[9], p[5]
        print "Device            r/s     rMB/s r_await     w/s     wMB/s w_await  aqu-sz   %util"
        for (j = 1; j <= nd; j++) {
            name = order[j]
            r = dd(s - 1, s, name, 4); w = dd(s - 1, s, name, 8)
            util = 100 * dd(s - 1, s, name, 13) / (dt * 1000); if (util > 100) util = 100
            printf "%-12s %8.2f %9.2f %7.2f %7.2f %9.2f %7.2f %7.2f %7.2f\n", name,
                r / dt, dd(s - 1, s, name, 6) * 512 / 1048576 / dt, r ? dd(s - 1, s, name, 7) / r : 0,
                w / dt, dd(s - 1, s, name, 10) * 512 / 1048576 / dt, w ? dd(s - 1, s, name, 11) / w : 0,
                dd(s - 1, s, name, 14) / (dt * 1000), util
        }
        print ""
    }
}
"""

def iostat_cmd(samples: int, interval: int, proc_dir: str = "/proc", sys_block_dir: str = "/sys/block") -> str:
    """Builds the get_iostat command: sysstat iostat -x, or the same main columns computed
    from /proc/stat and /proc/diskstats (BusyBox iostat has no await or %util).
    proc_dir and sys_block_dir are there for the tests."""
    # the total cpu line is enough here: per-CPU lines are get_mpstat's
    read_counters = (
        f"grep '^cpu ' {shlex.quote(proc_dir + '/stat')} && cat {shlex.quote(proc_dir + '/diskstats')}"
    )
    proc_header = (
        "# sysstat is not installed (BusyBox iostat, if any, has no await or %util): "
        f"computed from /proc/stat and /proc/diskstats, {samples} report(s) {interval}s apart"
    )
    return (
        "export LC_ALL=C S_TIME_FORMAT=ISO; "
        "if iostat -V 2>&1 | grep -q sysstat; then "
        f"""out=$(iostat -x -m -y {interval} {samples}) || exit; printf '%s\\n' "$out" | {IOSTAT_SYSSTAT_FILTER}; """
        f"else echo {shlex.quote(proc_header)}; echo; "
        f"{proc_sampling_cmd(read_counters, samples, interval, proc_dir)}"
        f"""printf '%s\\n' "$snaps" | awk -v disks="$(ls {shlex.quote(sys_block_dir)} | tr '\\n' ' ')" """
        f"{shlex.quote(IOSTAT_PROC_AWK)}; fi"
    )

@mcp.tool()
def get_iostat(
    host: str,
    user: str,
    samples: int = 3,
    interval: int = 1,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = TIMEOUT_DEFAULT_S,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Measures disk I/O and CPU usage with iostat -x -m: `samples` reports, each covering
    `interval` seconds (the since-boot report is skipped, so every number is current).
    Per device: reads and writes per second (r/s, w/s), MB/s, average wait per request in ms
    (r_await, w_await), queue length (aqu-sz) and %util (time the device was busy).
    USE THIS TOOL when the host is slow and vmstat or get_pressure shows I/O wait, to find
    which disk is saturated (%util near 100, high await). loop and ram devices are left out.
    The call takes samples x interval seconds; timeout must be at least that plus 5.
    Where sysstat is not installed (e.g. Alpine), the output starts with a
    '# sysstat is not installed' line and the same main columns are computed from
    /proc/stat and /proc/diskstats (whole disks only, no partitions).
    """
    error = sampling_error(samples, interval, timeout)
    if error:
        return {"ok": False, "error": error}
    cmd = iostat_cmd(samples, interval)
    return run_ssh_command(host, user, cmd, port, password, key_path, timeout, accept_new_hostkey)

MPSTAT_SYSSTAT_FILTER = (
    # keeps the banner, one header, the 'all' row of each sample and the whole Average block
    "awk 'NR == 1 { print; next } "
    '$1 == "Average:" { if (!avg++) print ""; print; next } '
    '$2 == "CPU" { if (!hdr++) { print ""; print } next } '
    "$2 == \"all\" { print }'"
)
MPSTAT_PROC_AWK = PROC_CPU_AWK_FUNCTIONS + r"""
$1 == "@" { k++; want_uptime = 1; next }
want_uptime { want_uptime = 0; next }
$1 ~ /^cpu/ {
    name = $1 == "cpu" ? "all" : substr($1, 4)
    if (k == 1) order[++n] = name
    for (i = 2; i <= 11; i++) v[k, name, i] = $i + 0
}
function row(label, name, a, b) {
    if (!cpu_pct(a, b, name)) return
    printf "%-8s %5s %7.2f %7.2f %7.2f %7.2f %7.2f %7.2f %7.2f %7.2f %7.2f %7.2f\n", label, name,
        p[2], p[3], p[4], p[6], p[7], p[8], p[9], p[10], p[11], p[5]
}
END {
    header = "%-8s %5s    %%usr   %%nice    %%sys %%iowait    %%irq   %%soft  %%steal  %%guest  %%gnice   %%idle\n"
    printf header, "Sample", "CPU"
    for (s = 2; s <= k; s++) row(s - 1, "all", s - 1, s)
    print ""
    printf header, "Average:", "CPU"
    for (j = 1; j <= n; j++) row("Average:", order[j], 1, k)
}
"""

def mpstat_cmd(samples: int, interval: int, proc_dir: str = "/proc") -> str:
    """Builds the get_mpstat command: sysstat mpstat -P ALL, or the same columns computed
    from /proc/stat. proc_dir is there for the tests."""
    read_counters = f"grep '^cpu' {shlex.quote(proc_dir + '/stat')}"
    proc_header = (
        "# sysstat is not installed: computed from /proc/stat, "
        f"{samples} sample(s) {interval}s apart"
    )
    return (
        "export LC_ALL=C S_TIME_FORMAT=ISO; "
        "if mpstat -V 2>&1 | grep -q sysstat; then "
        f"""out=$(mpstat -P ALL {interval} {samples}) || exit; printf '%s\\n' "$out" | {MPSTAT_SYSSTAT_FILTER}; """
        f"else echo {shlex.quote(proc_header)}; "
        f"{proc_sampling_cmd(read_counters, samples, interval, proc_dir)}"
        f"""printf '%s\\n' "$snaps" | awk {shlex.quote(MPSTAT_PROC_AWK)}; fi"""
    )

@mcp.tool()
def get_mpstat(
    host: str,
    user: str,
    samples: int = 3,
    interval: int = 1,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = TIMEOUT_DEFAULT_S,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Measures CPU usage PER CORE with mpstat -P ALL: `samples` samples, each covering
    `interval` seconds. Prints the all-CPU row of each sample, then an Average block with one
    row per CPU: %usr, %nice, %sys, %iowait, %irq, %soft, %steal, %guest, %gnice, %idle.
    USE THIS TOOL when total CPU looks fine but the host is slow: a single core at 100%
    (a single-threaded bottleneck, or interrupts all landing on one core) hides in the
    totals of top and vmstat. High %steal means the hypervisor gives the VM's CPU time to
    other VMs - it cannot be fixed from inside the VM.
    The call takes samples x interval seconds; timeout must be at least that plus 5.
    Where sysstat is not installed (e.g. Alpine), the output starts with a
    '# sysstat is not installed' line and the same columns are computed from /proc/stat
    (samples are numbered instead of timed).
    """
    error = sampling_error(samples, interval, timeout)
    if error:
        return {"ok": False, "error": error}
    cmd = mpstat_cmd(samples, interval)
    return run_ssh_command(host, user, cmd, port, password, key_path, timeout, accept_new_hostkey)

BUSYBOX_TOP_HEADER = "# BusyBox: top -b -n 1"
# captured, not piped, so that a failing top is noticed; with the header line it is 30 lines
BUSYBOX_TOP_CMD = (
    "out=$(top -b -n 1) || exit $?; "
    f"""echo {shlex.quote(BUSYBOX_TOP_HEADER)}; printf '%s\\n' "$out" | awk 'NR <= 29'"""
)
# every sample of procps top starts with a "top - ..." line; keep the second sample only
TOP_SECOND_SAMPLE_FILTER = "awk '/^top -/{n++} n==2' | head -n 30"

@mcp.tool()
def get_top(
    host: str,
    user: str,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = TIMEOUT_DEFAULT_S,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Collects top's snapshot from a remote Linux host via SSH (top -b -n 2 -d 1 -c -w 512).
    Takes two samples 1 second apart and returns the second one, so CPU usage is the current one
    (the first sample of top shows averages since boot). The output is cut to the first 30 lines:
    the summary and the top CPU consumers.
    On BusyBox hosts (Alpine), where top has no -c / -w, the output is plain `top -b -n 1`,
    cut to 30 lines too: its first line starts with '# BusyBox' and the columns differ.
    Process command lines can hold secrets (--password=..., URLs with credentials).
    Values that look like secrets (passwords, tokens, keys, credentials in URLs) are replaced
    by '<redacted>' before the output is returned; the "redaction" field of the result says
    how many. It is pattern-based: a secret in an unusual form may still be shown, and a
    harmless value that looks like one may be hidden.
    """
    cmd = busybox_fallback(
        "top -b -n 2 -d 1 -c -w 512", "top", BUSYBOX_TOP_CMD,
        output_filter=TOP_SECOND_SAMPLE_FILTER,
    )
    result = run_ssh_command(host, user, cmd, port, password, key_path, timeout, accept_new_hostkey)
    return redact_secrets_in_result(result)

CPU_INFO_NO_LSCPU_HEADER = "# lscpu is not installed: summary of /proc/cpuinfo"
# The /proc/cpuinfo lines that describe the CPU rather than one core: x86 names first,
# then the ARM ones (ARM has no "model name"). Each distinct line is printed once.
CPU_INFO_FIELDS = (
    "vendor_id", "model name", "cpu family", "model", "stepping", "microcode", "cache size",
    "physical id", "siblings", "cpu cores", "address sizes",
    "Hardware", "CPU implementer", "CPU architecture", "CPU variant", "CPU part", "CPU revision", "Model",
)
# x86 calls them flags, ARM Features
CPU_INFO_FLAG_FIELDS = ("flags", "Features")
# lscpu 2.38+ no longer prints the current frequency, so it is always taken from
# /proc/cpuinfo, as one line however many CPUs there are. Hosts whose /proc/cpuinfo has
# no "cpu MHz" (most ARM) get no line.
CPU_MHZ_SUMMARY = (
    "awk -F: '/^cpu MHz/ { v = $2 + 0; n++; s += v; if (n == 1 || v < min) min = v; if (v > max) max = v } "
    'END { if (n) printf "CPU MHz now (/proc/cpuinfo): min %.0f, average %.0f, max %.0f over %d CPUs\\n", '
    "min, s / n, max, n }'"
)
CPUINFO_PATH = "/proc/cpuinfo"

def cpu_info_cmd(include_flags: bool, cpuinfo_path: str = CPUINFO_PATH) -> str:
    """Builds the get_cpu_info command: lscpu, or a /proc/cpuinfo summary where lscpu is
    missing (Alpine: it is in util-linux, which BusyBox systems usually lack).
    cpuinfo_path is there for the tests."""
    cpuinfo = shlex.quote(cpuinfo_path)
    fields = CPU_INFO_FIELDS + (CPU_INFO_FLAG_FIELDS if include_flags else ())
    cpuinfo_summary = (
        f"awk -v fields={shlex.quote('|'.join(fields))} "
        "'BEGIN { n = split(fields, f, \"|\"); for (i = 1; i <= n; i++) want[f[i]] = 1 } "
        "{ k = $0; sub(/[ \\t]*:.*/, \"\", k) } (k in want) && !seen[$0]++' "
        f"{cpuinfo}"
    )
    lscpu_print = """printf '%s\\n' "$out\"""" if include_flags else """printf '%s\\n' "$out" | grep -v '^Flags:'"""
    return (
        # C locale: lscpu translates its labels
        "LC_ALL=C; export LC_ALL; "
        f"if command -v lscpu >/dev/null 2>&1; then out=$(lscpu) || exit; {lscpu_print}; "
        f"else echo {shlex.quote(CPU_INFO_NO_LSCPU_HEADER)}; "
        """echo "Architecture: $(uname -m)"; echo "CPU(s): $(grep -c '^processor' """ f"{cpuinfo})\"; "
        f"{cpuinfo_summary} || exit; fi; "
        f"{CPU_MHZ_SUMMARY} {cpuinfo}"
    )

@mcp.tool()
def get_cpu_info(
    host: str,
    user: str,
    include_flags: bool = False,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = TIMEOUT_DEFAULT_S,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Describes the CPUs of a remote Linux host via SSH (lscpu): architecture, model name,
    number of CPUs, sockets, cores and threads per core, caches, NUMA nodes, hypervisor
    and CPU vulnerability mitigations. The last line gives the current frequency
    ('CPU MHz now (/proc/cpuinfo): min, average, max over N CPUs'); it is missing on
    hosts that do not report it (most ARM).
    The CPU flags (avx2, aes, ...) are left out unless include_flags=True: the line is long.
    Where lscpu is not installed (e.g. Alpine), the output starts with a
    '# lscpu is not installed' line and lists the distinct model lines of /proc/cpuinfo
    (model name, cache size, cpu cores, ...) instead, with the field names of /proc/cpuinfo.
    """
    if not isinstance(include_flags, bool):
        return {"ok": False, "error": "Invalid value of include_flags, should be Boolean"}
    cmd = cpu_info_cmd(include_flags)
    return run_ssh_command(host, user, cmd, port, password, key_path, timeout, accept_new_hostkey)

LSBLK_NO_UTIL_LINUX_HEADER = (
    "# lsblk (util-linux) is not installed: block devices from /sys/block, "
    "mount points from /proc/mounts and /proc/swaps; device-mapper devices by their dm name, "
    "not nested under the disks they are built on"
)
LSBLK_NO_DEVICES = "no block devices in /sys/block"
# Formats the rows the sysfs walk prints (type name label maj:min rm sectors ro) as lsblk
# does: sizes of 512-byte sectors in K/M/G/T, partitions under their disk, every mount point
# (comma-separated) or [SWAP]. Devices of size 0 (empty loop devices) are left out, as lsblk does.
LSBLK_SYSFS_AWK = r"""
# BusyBox awk: no `in` here, it creates the entry it tests
function add(dev, m) { mp[dev] = (mp[dev] == "") ? m : mp[dev] "," m }
function human(sectors,    v, i, u, s) {
    v = sectors * 512; split("B K M G T P", u, " "); i = 1
    while (v >= 1024 && i < 6) { v /= 1024; i++ }
    s = sprintf("%.1f", v); sub(/\.0$/, "", s)
    return s u[i]
}
BEGIN {
    while ((getline line < mounts) > 0) { split(line, f, " "); add(f[1], f[2]) }
    while ((getline line < swaps) > 0) { split(line, f, " "); if (f[1] != "Filename") add(f[1], "[SWAP]") }
    printf "%-14s %7s %2s %6s %2s %4s %s\n", "NAME", "MAJ:MIN", "RM", "SIZE", "RO", "TYPE", "MOUNTPOINTS"
}
$6 == 0 { next }
{
    n++
    m = mp["/dev/" $2]
    if (m == "" && $1 == "dm") m = mp["/dev/mapper/" $3]
    name = ($1 == "part") ? "`-" $3 : $3
    printf "%-14s %7s %2s %6s %2s %4s %s\n", name, $4, $5, human($6), $7, $1, m
}
END { if (!n) print none }
"""

def lsblk_cmd(sys_block_dir: str = "/sys/block", proc_dir: str = "/proc") -> str:
    """Builds the get_lsblk command: lsblk from util-linux, or the same main columns read
    from /sys/block where lsblk is missing (Alpine: BusyBox has no lsblk).
    A failing lsblk is passed through. sys_block_dir and proc_dir are there for the tests."""
    sysfs_rows = (
        f"for d in {shlex.quote(sys_block_dir)}/*; do n=${{d##*/}}; "
        # ram disks are left out by lsblk too
        'case $n in ram*) continue;; esac; [ -r "$d/size" ] || continue; '
        "t=disk; label=$n; case $n in loop*) t=loop;; esac; "
        '[ -r "$d/dm/name" ] && read -r label < "$d/dm/name" && t=dm; '
        'read -r dev < "$d/dev"; read -r rm < "$d/removable"; read -r size < "$d/size"; read -r ro < "$d/ro"; '
        'echo "$t $n $label $dev $rm $size $ro"; '
        'for p in "$d/$n"*; do [ -r "$p/partition" ] || continue; '
        'read -r dev < "$p/dev"; read -r size < "$p/size"; read -r pro < "$p/ro"; '
        'echo "part ${p##*/} ${p##*/} $dev $rm $size $pro"; done; '
        "done"
    )
    awk_vars = (
        f"-v mounts={shlex.quote(proc_dir + '/mounts')} -v swaps={shlex.quote(proc_dir + '/swaps')} "
        f"-v none={shlex.quote(LSBLK_NO_DEVICES)}"
    )
    return (
        # lsblk keeps the host's locale: in the C locale it draws its tree in ASCII
        "if command -v lsblk >/dev/null 2>&1; then lsblk; "
        f"else echo {shlex.quote(LSBLK_NO_UTIL_LINUX_HEADER)}; "
        # C locale: awk's %.1f could otherwise print a decimal comma
        f"{{ {sysfs_rows}; }} | LC_ALL=C awk {awk_vars} {shlex.quote(LSBLK_SYSFS_AWK)}; fi"
    )

@mcp.tool()
def get_lsblk(
    host: str,
    user: str,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = TIMEOUT_DEFAULT_S,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Lists the block devices of a remote Linux host via SSH (lsblk): disks, their partitions,
    loop and device-mapper (LVM, LUKS) devices, with MAJ:MIN, removable (RM), size,
    read-only (RO), type and mount points ([SWAP] for swap).
    Where lsblk is not installed (e.g. Alpine), the output starts with a
    '# lsblk (util-linux) is not installed' line and lists the same columns read from
    /sys/block, /proc/mounts and /proc/swaps; device-mapper devices are listed by their
    dm name and not nested under the disks they are built on.
    """
    cmd = lsblk_cmd()
    return run_ssh_command(host, user, cmd, port, password, key_path, timeout, accept_new_hostkey)

LSPCI_NO_PCIUTILS_HEADER = (
    "# lspci (pciutils) is not installed: devices from /sys/bus/pci/devices, "
    "class and [vendor:device] IDs only, no vendor or device names"
)
LSPCI_NO_DEVICES = "no PCI devices (this host has no PCI bus, e.g. a VM with virtio-mmio devices)"
PCI_SYSFS_DIR = "/sys/bus/pci/devices"
# The base class of a PCI device (first byte of its class code), named as lspci names it
PCI_BASE_CLASSES = {
    "00": "Unclassified device", "01": "Mass storage controller", "02": "Network controller",
    "03": "Display controller", "04": "Multimedia controller", "05": "Memory controller",
    "06": "Bridge", "07": "Communication controller", "08": "Generic system peripheral",
    "09": "Input device controller", "0a": "Docking station", "0b": "Processor",
    "0c": "Serial bus controller", "0d": "Wireless controller", "0e": "Intelligent controller",
    "0f": "Satellite communications controller", "10": "Encryption controller",
    "11": "Signal processing controller", "12": "Processing accelerators",
    "13": "Non-Essential Instrumentation", "40": "Coprocessor", "ff": "Unassigned class",
}

def lspci_cmd(sysfs_dir: str = PCI_SYSFS_DIR) -> str:
    """Builds the get_lspci command: `lspci -nnk` from pciutils, or one line per device read
    from sysfs where pciutils is missing (Alpine and minimal images; the BusyBox lspci, where
    there is one, lacks -nn and is not used). A failing pciutils lspci is passed through.
    sysfs_dir is there for the tests."""
    class_case = " ".join(
        f"{code}) name={shlex.quote(name)};;" for code, name in PCI_BASE_CLASSES.items()
    )
    sysfs_list = (
        "found=; "
        f"for d in {shlex.quote(sysfs_dir)}/*; do "
        '[ -r "$d/class" ] || continue; found=1; '
        'read -r cls < "$d/class"; read -r ven < "$d/vendor"; read -r dev < "$d/device"; '
        "sub=; "
        'if [ -r "$d/subsystem_vendor" ] && [ -r "$d/subsystem_device" ]; then '
        'read -r sv < "$d/subsystem_vendor"; read -r sd < "$d/subsystem_device"; '
        'sub=" (subsystem [${sv#0x}:${sd#0x}])"; fi; '
        'drv=none; [ -L "$d/driver" ] && drv=$(basename "$(readlink "$d/driver")"); '
        "cls=${cls#0x}; "
        f"case ${{cls%????}} in {class_case} *) name='Unknown class';; esac; "
        'echo "${d##*/} $name [${cls%??}]: [${ven#0x}:${dev#0x}]$sub, driver: $drv"; '
        "done; "
        f'[ -n "$found" ] || echo {shlex.quote(LSPCI_NO_DEVICES)}'
    )
    return (
        # C locale: lspci translates nothing today, but keeps the output the same everywhere
        "LC_ALL=C; export LC_ALL; "
        "if command -v lspci >/dev/null 2>&1 && ! lspci --help 2>&1 | grep -q BusyBox; then lspci -nnk; "
        f"else echo {shlex.quote(LSPCI_NO_PCIUTILS_HEADER)}; {sysfs_list}; fi"
    )

@mcp.tool()
def get_lspci(
    host: str,
    user: str,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = TIMEOUT_DEFAULT_S,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Lists the PCI devices of a remote Linux host via SSH (lspci -nnk): network, storage and
    display controllers, bridges, GPUs and accelerators, each with its class, its
    [vendor:device] IDs and the kernel driver in use (and the kernel modules that could drive it).
    A device with no 'Kernel driver in use' line has no driver bound.
    Where pciutils is not installed (e.g. Alpine), the output starts with a
    '# lspci (pciutils) is not installed' line and lists one line per device from
    /sys/bus/pci/devices: slot, class [code], [vendor:device] IDs, subsystem IDs and driver
    ('none' if no driver is bound), without vendor or device names.
    A host with no PCI bus (some VMs) gets a 'no PCI devices' line.
    """
    cmd = lspci_cmd()
    return run_ssh_command(host, user, cmd, port, password, key_path, timeout, accept_new_hostkey)

LSUSB_NO_USBUTILS_HEADER = (
    "# lsusb (usbutils) is not installed: devices from /sys/bus/usb/devices, "
    "names as the devices report them, drivers of their interfaces"
)
LSUSB_NO_DEVICES = "no USB devices (this host has no USB controller, or none is visible)"
USB_SYSFS_DIR = "/sys/bus/usb/devices"

def lsusb_cmd(sysfs_dir: str = USB_SYSFS_DIR) -> str:
    """Builds the get_lsusb command: `lsusb` then `lsusb -t` from usbutils, or one line per
    device read from sysfs where usbutils is missing (Alpine and minimal images; the BusyBox
    lsusb, where there is one, has no names, speeds or drivers and is not used).
    A failing usbutils lsusb is passed through. Serial numbers are never read.
    sysfs_dir is there for the tests."""
    sysfs_list = (
        "found=; "
        f"for d in {shlex.quote(sysfs_dir)}/*; do "
        # interfaces (1-1:1.0) are listed here too; only devices have idVendor
        '[ -r "$d/idVendor" ] || continue; found=1; '
        'read -r bus < "$d/busnum"; read -r num < "$d/devnum"; '
        'read -r ven < "$d/idVendor"; read -r prod < "$d/idProduct"; '
        "name=; "
        'for f in manufacturer product; do [ -r "$d/$f" ] && read -r v < "$d/$f" && name="$name $v"; done; '
        'speed=; [ -r "$d/speed" ] && read -r speed < "$d/speed"; '
        "drivers=; "
        'for i in "$d"/*:*; do [ -L "$i/driver" ] || continue; x=$(basename "$(readlink "$i/driver")"); '
        'case " $drivers " in *" $x "*) ;; *) drivers="${drivers:+$drivers }$x";; esac; done; '
        """printf 'Bus %03d Device %03d: ID %s:%s%s, speed %s Mbit/s, drivers: %s\\n' """
        '"$bus" "$num" "$ven" "$prod" "$name" "${speed:-?}" "${drivers:-none}"; '
        "done; "
        f'[ -n "$found" ] || echo {shlex.quote(LSUSB_NO_DEVICES)}'
    )
    return (
        "LC_ALL=C; export LC_ALL; "
        "if command -v lsusb >/dev/null 2>&1 && ! lsusb --help 2>&1 | grep -q BusyBox; then "
        "lsusb || exit; echo; lsusb -t; "
        f"else echo {shlex.quote(LSUSB_NO_USBUTILS_HEADER)}; {sysfs_list}; fi"
    )

@mcp.tool()
def get_lsusb(
    host: str,
    user: str,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = TIMEOUT_DEFAULT_S,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Lists the USB devices of a remote Linux host via SSH: `lsusb` (bus, device number,
    [vendor:product] ID and name of each device, root hubs included), then `lsusb -t`
    (the device tree: which port each device is on, its class, the driver bound to each
    interface, e.g. usbhid, usb-storage, uas, and the speed).
    Where usbutils is not installed (e.g. Alpine), the output starts with a
    '# lsusb (usbutils) is not installed' line and lists one line per device from
    /sys/bus/usb/devices: bus, device number, ID, the manufacturer and product names the
    device reports, its speed and the drivers of its interfaces ('none' if none is bound).
    Serial numbers are not shown. A host with no USB controller gets a 'no USB devices' line.
    """
    cmd = lsusb_cmd()
    return run_ssh_command(host, user, cmd, port, password, key_path, timeout, accept_new_hostkey)

@mcp.tool()
def get_docker_ps_all(
    host: str,
    user: str,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = TIMEOUT_DEFAULT_S,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Collects docker ps --all output from a remote Linux host via SSH
    When the login user cannot reach the docker daemon (not root, not in the docker group),
    the command is run through passwordless sudo or doas (sudo -n / doas -n).
    """
    cmd = docker_cmd("ps --all")
    return run_ssh_command(host, user, cmd, port, password, key_path, timeout, accept_new_hostkey)

@mcp.tool()
def get_docker_images(
    host: str,
    user: str,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = TIMEOUT_DEFAULT_S,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Collects docker images --digests output (repository, tag, digest, image ID, age, size) from a remote Linux host via SSH
    When the login user cannot reach the docker daemon (not root, not in the docker group),
    the command is run through passwordless sudo or doas (sudo -n / doas -n).
    """
    # No -a: it only adds untagged intermediate build layers, which are noise for diagnostics
    cmd = docker_cmd("images --digests")
    return run_ssh_command(host, user, cmd, port, password, key_path, timeout, accept_new_hostkey)

@mcp.tool()
def get_docker_logs(
    container: str,
    host: str,
    user: str,
    lines: int = 200,
    since: Optional[str] = None,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = TIMEOUT_DEFAULT_S,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Gets the last `lines` log lines (stdout and stderr merged) of a SPECIFIC docker container,
    given by name or ID, from a remote Linux host via SSH. Works for stopped containers too.
    Use get_docker_ps_all first to find container names.
    Optional since limits them to a time window: '30 min ago', '2 hours ago', '30m', '1h30m'
    or 'YYYY-MM-DD HH:MM:SS' ('today' and 'yesterday' are not supported here).
    When the login user cannot reach the docker daemon (not root, not in the docker group),
    the command is run through passwordless sudo or doas (sudo -n / doas -n).
    Log lines can hold secrets.
    Values that look like secrets (passwords, tokens, keys, credentials in URLs) are replaced
    by '<redacted>' before the output is returned; the "redaction" field of the result says
    how many. It is pattern-based: a secret in an unusual form may still be shown, and a
    harmless value that looks like one may be hidden.
    """
    if not is_valid_container_ref(container):
        return {"ok": False, "error": CONTAINER_ERROR}
    if not is_valid_lines(lines):
        return {"ok": False, "error": LINES_ERROR}

    cmd = docker_cmd(f"logs --tail {lines}")
    if since is not None:
        safe_since = normalize_since_docker(since)
        if safe_since is None:
            return {"ok": False, "error": DOCKER_SINCE_ERROR}
        cmd += f" --since {shlex.quote(safe_since)}"
    # docker replays the container's stderr on stderr; merge to keep the lines in order
    cmd += f" {shlex.quote(container)} 2>&1"
    result = run_ssh_command(host, user, cmd, port, password, key_path, timeout, accept_new_hostkey)
    return redact_secrets_in_result(result)

@mcp.tool()
def get_docker_stats(
    host: str,
    user: str,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = TIMEOUT_DEFAULT_S,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Collects a one-shot docker stats snapshot from a remote Linux host via SSH:
    CPU %, memory usage/limit, network and block I/O, PIDs for every RUNNING container.
    When the login user cannot reach the docker daemon (not root, not in the docker group),
    the command is run through passwordless sudo or doas (sudo -n / doas -n).
    """
    cmd = docker_cmd("stats --no-stream")
    return run_ssh_command(host, user, cmd, port, password, key_path, timeout, accept_new_hostkey)

# Curated on purpose: a full `docker inspect` dumps .Config.Env, where secrets usually live.
DOCKER_INSPECT_FORMAT = """Name: {{.Name}}
Id: {{.Id}}
Image: {{.Config.Image}} ({{.Image}})
Created: {{.Created}}
Entrypoint: {{json .Config.Entrypoint}}
Cmd: {{json .Config.Cmd}}
State: {{json .State}}
RestartCount: {{.RestartCount}}
RestartPolicy: {{json .HostConfig.RestartPolicy}}
MemoryLimitBytes: {{.HostConfig.Memory}}
NanoCpus: {{.HostConfig.NanoCpus}}
Privileged: {{.HostConfig.Privileged}}
NetworkMode: {{.HostConfig.NetworkMode}}
Networks: {{range $name, $net := .NetworkSettings.Networks}}{{$name}}={{$net.IPAddress}} {{end}}
Ports: {{json .NetworkSettings.Ports}}
Mounts: {{json .Mounts}}
LogDriver: {{.HostConfig.LogConfig.Type}}"""

@mcp.tool()
def get_docker_inspect(
    container: str,
    host: str,
    user: str,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = TIMEOUT_DEFAULT_S,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Inspects a SPECIFIC docker container, given by name or ID, on a remote Linux host via SSH.
    Returns a curated subset of docker inspect: image, entrypoint/cmd, state (status, exit code,
    OOMKilled, start/finish time, health check log), restart count and policy, memory/CPU limits,
    networks, ports, mounts and log driver. Environment variables are NOT returned.
    When the login user cannot reach the docker daemon (not root, not in the docker group),
    the command is run through passwordless sudo or doas (sudo -n / doas -n).
    The entrypoint/cmd can hold secrets.
    Values that look like secrets (passwords, tokens, keys, credentials in URLs) are replaced
    by '<redacted>' before the output is returned; the "redaction" field of the result says
    how many. It is pattern-based: a secret in an unusual form may still be shown, and a
    harmless value that looks like one may be hidden.
    """
    if not is_valid_container_ref(container):
        return {"ok": False, "error": CONTAINER_ERROR}

    cmd = docker_cmd(
        f"inspect --type container --format {shlex.quote(DOCKER_INSPECT_FORMAT)} "
        f"{shlex.quote(container)}"
    )
    result = run_ssh_command(host, user, cmd, port, password, key_path, timeout, accept_new_hostkey)
    return redact_secrets_in_result(result)

# ---- Kubernetes: kubectl (cluster level) ----

@mcp.tool()
def get_kubectl_logs(
    pod: str,
    host: str,
    user: str,
    namespace: str = "default",
    container: Optional[str] = None,
    previous: bool = False,
    lines: int = 200,
    since: Optional[str] = None,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = TIMEOUT_DEFAULT_S,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Gets the last `lines` log lines of a SPECIFIC kubernetes pod (kubectl logs) by running
    kubectl on a remote Linux host via SSH. kubectl must be configured for the SSH user there.
    container selects a container in a multi-container pod.
    previous=True returns logs of the previous, crashed instance - use it for CrashLoopBackOff.
    Optional since limits them to a time window: '30 min ago', '2 hours ago', '30m', '1h30m'
    or an absolute UTC time 'YYYY-MM-DDTHH:MM:SSZ'.
    Log lines can hold secrets.
    Values that look like secrets (passwords, tokens, keys, credentials in URLs) are replaced
    by '<redacted>' before the output is returned; the "redaction" field of the result says
    how many. It is pattern-based: a secret in an unusual form may still be shown, and a
    harmless value that looks like one may be hidden.
    """
    if not is_valid_dns_subdomain(pod):
        return {"ok": False, "error": K8S_NAME_ERROR}
    if not is_valid_dns_label(namespace):
        return {"ok": False, "error": K8S_NAMESPACE_ERROR}
    if container is not None and not is_valid_dns_label(container):
        return {"ok": False, "error": K8S_CONTAINER_ERROR}
    if not isinstance(previous, bool):
        return {"ok": False, "error": "Invalid value of previous, should be Boolean"}
    if not is_valid_lines(lines):
        return {"ok": False, "error": LINES_ERROR}

    cmd = f"kubectl logs --tail={lines} --namespace={shlex.quote(namespace)}"
    if container is not None:
        cmd += f" --container={shlex.quote(container)}"
    if previous:
        cmd += " --previous"
    if since is not None:
        safe_since = normalize_since_kubernetes(since)
        if safe_since is None:
            return {"ok": False, "error": K8S_SINCE_ERROR}
        # kubectl takes durations and timestamps through different flags
        flag = "--since" if is_go_duration(safe_since) else "--since-time"
        cmd += f" {flag}={shlex.quote(safe_since)}"
    cmd += f" {shlex.quote(pod)}"
    return redact_secrets_in_result(
        run_ssh_command(host, user, cmd, port, password, key_path, timeout, accept_new_hostkey))

@mcp.tool()
def get_kubectl_describe(
    resource_type: str,
    name: str,
    host: str,
    user: str,
    namespace: str = "default",
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = TIMEOUT_DEFAULT_S,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Describes a SPECIFIC kubernetes resource (kubectl describe) by running kubectl on a remote
    Linux host via SSH: status, conditions, containers and its recent events.
    kubectl must be configured for the SSH user there.
    resource_type is one of: pod, node, namespace, deployment, statefulset, daemonset, replicaset,
    job, cronjob, service, endpoints, ingress, networkpolicy, persistentvolumeclaim, persistentvolume,
    storageclass, horizontalpodautoscaler, poddisruptionbudget (plural and short names like
    'po', 'deploy', 'svc' work too). Secrets and configmaps are NOT available.
    namespace is ignored for cluster-scoped resources (node, namespace, persistentvolume, storageclass).
    Every literal environment value (Environment: blocks of pods and pod templates) is
    replaced by '<redacted>', the variable names are kept; references to a secret, config map
    or field are shown as they are, since they hold no value. In the rest of the output (Command,
    Args) values that look like secrets are replaced the same way; that part is pattern-based:
    a secret in an unusual form may still be shown, and a harmless value may be hidden.
    The "redaction" field of the result says how many values were replaced.
    """
    safe_type = normalize_k8s_resource_type(resource_type)
    if safe_type is None:
        return {"ok": False, "error": K8S_RESOURCE_TYPE_ERROR}
    if not is_valid_dns_subdomain(name):
        return {"ok": False, "error": K8S_NAME_ERROR}
    if not is_valid_dns_label(namespace):
        return {"ok": False, "error": K8S_NAMESPACE_ERROR}

    cmd = f"kubectl describe {safe_type} {shlex.quote(name)} --namespace={shlex.quote(namespace)}"
    result = run_ssh_command(host, user, cmd, port, password, key_path, timeout, accept_new_hostkey)
    return redact_secrets_in_result(result, redactor=redact_k8s_describe)

@mcp.tool()
def get_kubectl_events(
    host: str,
    user: str,
    namespace: Optional[str] = None,
    warnings_only: bool = False,
    lines: int = 200,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = TIMEOUT_DEFAULT_S,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Gets the most recent `lines` kubernetes events (kubectl get events), oldest first, below the
    column header, by running
    kubectl on a remote Linux host via SSH. kubectl must be configured for the SSH user there.
    USE THIS TOOL FIRST when you don't know what is wrong in a cluster.
    Events of ALL namespaces are returned unless namespace is given.
    warnings_only=True keeps only events of type Warning (FailedScheduling, BackOff, Unhealthy...).
    Event messages can hold secrets (the output of a failed probe, an image URL).
    Values that look like secrets (passwords, tokens, keys, credentials in URLs) are replaced
    by '<redacted>' before the output is returned; the "redaction" field of the result says
    how many. It is pattern-based: a secret in an unusual form may still be shown, and a
    harmless value that looks like one may be hidden.
    """
    if namespace is not None and not is_valid_dns_label(namespace):
        return {"ok": False, "error": K8S_NAMESPACE_ERROR}
    if not isinstance(warnings_only, bool):
        return {"ok": False, "error": "Invalid value of warnings_only, should be Boolean"}
    if not is_valid_lines(lines):
        return {"ok": False, "error": LINES_ERROR}

    cmd = "kubectl get events --sort-by=.lastTimestamp"
    cmd += " --all-namespaces" if namespace is None else f" --namespace={shlex.quote(namespace)}"
    if warnings_only:
        cmd += " --field-selector=type=Warning"
    cmd = tail_keeping_header(cmd, lines)
    return redact_secrets_in_result(
        run_ssh_command(host, user, cmd, port, password, key_path, timeout, accept_new_hostkey))

# ---- Kubernetes: crictl (node level) ----

@mcp.tool()
def get_crictl_ps(
    host: str,
    user: str,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = TIMEOUT_DEFAULT_S,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Collects crictl ps --all output (all CRI containers on a kubernetes node, including exited ones:
    container ID, image, state, name, attempt, pod) from a remote Linux host via SSH.
    Usually requires root.
    """
    cmd = "crictl ps --all"
    return run_ssh_command(host, user, cmd, port, password, key_path, timeout, accept_new_hostkey)

@mcp.tool()
def get_crictl_images(
    host: str,
    user: str,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = TIMEOUT_DEFAULT_S,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Collects crictl images output (image, tag, image ID, size of images present in the CRI runtime
    of a kubernetes node) from a remote Linux host via SSH. Usually requires root.
    """
    cmd = "crictl images"
    return run_ssh_command(host, user, cmd, port, password, key_path, timeout, accept_new_hostkey)

@mcp.tool()
def get_crictl_imagefsinfo(
    host: str,
    user: str,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = TIMEOUT_DEFAULT_S,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Collects crictl imagefsinfo output (mountpoint, used bytes and inodes of the CRI image
    filesystem of a kubernetes node) from a remote Linux host via SSH.
    USE THIS TOOL to investigate image garbage collection and DiskPressure. Usually requires root.
    """
    cmd = "crictl imagefsinfo"
    return run_ssh_command(host, user, cmd, port, password, key_path, timeout, accept_new_hostkey)

@mcp.tool()
def get_crictl_logs(
    container_id: str,
    host: str,
    user: str,
    lines: int = 200,
    since: Optional[str] = None,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = TIMEOUT_DEFAULT_S,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Gets the last `lines` log lines (stdout and stderr merged) of a SPECIFIC CRI container on a
    kubernetes node from a remote Linux host via SSH. Works when the API server is down.
    Use get_crictl_ps first to find the container ID. Usually requires root.
    Optional since limits them to a time window: '30 min ago', '2 hours ago', '30m', '1h30m'
    or an absolute UTC time 'YYYY-MM-DDTHH:MM:SSZ'.
    Log lines can hold secrets.
    Values that look like secrets (passwords, tokens, keys, credentials in URLs) are replaced
    by '<redacted>' before the output is returned; the "redaction" field of the result says
    how many. It is pattern-based: a secret in an unusual form may still be shown, and a
    harmless value that looks like one may be hidden.
    """
    if not is_valid_container_id(container_id):
        return {"ok": False, "error": "Invalid container_id, should be 12 to 64 lowercase hex characters"}
    if not is_valid_lines(lines):
        return {"ok": False, "error": LINES_ERROR}

    cmd = f"crictl logs --tail={lines}"
    if since is not None:
        safe_since = normalize_since_kubernetes(since)
        if safe_since is None:
            return {"ok": False, "error": K8S_SINCE_ERROR}
        cmd += f" --since={shlex.quote(safe_since)}"
    # crictl replays the container's stderr on stderr; merge to keep the lines in order
    cmd += f" {shlex.quote(container_id)} 2>&1"
    return redact_secrets_in_result(
        run_ssh_command(host, user, cmd, port, password, key_path, timeout, accept_new_hostkey))

def redact_env_values(obj: Any) -> Any:
    """Returns a copy of parsed JSON with the values of every 'env' / 'envs' entry replaced
    by '<redacted>'. Variable names are kept: ['A=1'] -> ['A=<redacted>'],
    [{'key': 'A', 'value': '1'}] -> [{'key': 'A', 'value': '<redacted>'}]."""
    def redact_entry(entry: Any) -> Any:
        if isinstance(entry, str):
            return f"{entry.partition('=')[0]}={REDACTED}"
        if isinstance(entry, dict):
            return {k: (v if k in ("key", "name") else REDACTED) for k, v in entry.items()}
        return REDACTED

    if isinstance(obj, dict):
        redacted = {}
        for key, value in obj.items():
            if isinstance(key, str) and key.lower() in ("env", "envs"):
                redacted[key] = [redact_entry(e) for e in value] if isinstance(value, list) else REDACTED
            else:
                redacted[key] = redact_env_values(value)
        return redacted
    if isinstance(obj, list):
        return [redact_env_values(item) for item in obj]
    return obj

def _redact_env_in_json_stdout(result: Dict[str, Any]) -> Dict[str, Any]:
    """Redacts env values in the JSON stdout of a run_ssh_command result.
    Output that cannot be parsed is dropped rather than returned unredacted."""
    data = result.get("data")
    if not data or not data.get("stdout"):
        return result
    try:
        parsed = json.loads(data["stdout"])
    except ValueError:
        data["stdout"] = ""
        result["ok"] = False
        result["error"] = "Output was not valid JSON; it was dropped, since env values could not be redacted."
        return result
    data["stdout"] = json.dumps(redact_env_values(parsed), indent=1)
    return result

@mcp.tool()
def get_crictl_inspect(
    container_id: str,
    host: str,
    user: str,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = TIMEOUT_DEFAULT_S,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Inspects a SPECIFIC CRI container (crictl inspect, JSON) on a kubernetes node from a remote
    Linux host via SSH: state, exit code and reason, timestamps, image, mounts, log path, pid
    and the runtime spec. Use get_crictl_ps first to find the container ID. Usually requires root.
    Values of environment variables are replaced by '<redacted>'; their names are kept.
    """
    if not is_valid_container_id(container_id):
        return {"ok": False, "error": "Invalid container_id, should be 12 to 64 lowercase hex characters"}

    cmd = f"crictl inspect --output json {shlex.quote(container_id)}"
    result = run_ssh_command(host, user, cmd, port, password, key_path, timeout, accept_new_hostkey)
    return _redact_env_in_json_stdout(result)

@mcp.tool()
def get_crictl_inspect_image(
    image: str,
    host: str,
    user: str,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = TIMEOUT_DEFAULT_S,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Inspects a SPECIFIC image (crictl inspecti, JSON) in the CRI runtime of a kubernetes node
    from a remote Linux host via SSH: repo tags and digests, size, user, entrypoint/cmd, layers.
    image is an image name ('registry.k8s.io/pause:3.9') or an image ID from get_crictl_images.
    Usually requires root.
    Values of environment variables are replaced by '<redacted>'; their names are kept.
    """
    if not is_valid_image_ref(image):
        return {"ok": False, "error": IMAGE_ERROR}

    cmd = f"crictl inspecti --output json {shlex.quote(image)}"
    result = run_ssh_command(host, user, cmd, port, password, key_path, timeout, accept_new_hostkey)
    return _redact_env_in_json_stdout(result)

# Process names of the cron daemons: Vixie/Debian cron, cronie and BusyBox (crond), fcron, dcron
CRON_DAEMON_NAMES = ("cron", "crond", "fcron", "dcron")

def cron_daemon_check_cmd(proc_dir: str = "/proc") -> str:
    """Builds a command that prints one line saying whether a cron daemon is running, found
    by its process name in /proc/<pid>/comm (no ps needed, so BusyBox works too):
      # cron daemon: running: cron (pid 612)
      # cron daemon: NOT RUNNING (...): scheduled jobs are not executed
      # cron daemon: cannot tell: ...   - a non-root user on a /proc mounted with hidepid
    It always exits 0. proc_dir is there for the tests."""
    names = "|".join(CRON_DAEMON_NAMES)
    proc = shlex.quote(proc_dir)
    hidepid_check = (
        "awk '$2 == \"/proc\" && $4 ~ /(^|,)hidepid=([12]|invisible|noaccess)(,|$)/ { f = 1 } "
        f"END {{ exit !f }}' {shlex.quote(proc_dir + '/mounts')}"
    )
    return (
        f"cron_found=; for d in {proc}/[0-9]*; do "
        # read, not cat: no process per /proc entry. A process can end between the glob and the read.
        '{ read -r c < "$d/comm"; } 2>/dev/null || continue; '
        f'case "$c" in {names}) cron_found="$cron_found $c (pid ${{d##*/}})," ;; esac; done; '
        'if [ -n "$cron_found" ]; then echo "# cron daemon: running:${cron_found%,}"; '
        f'elif [ "$(id -u)" != 0 ] && {hidepid_check}; then '
        "echo '# cron daemon: cannot tell: /proc is mounted with hidepid, so the processes of other users are hidden'; "
        f"else echo '# cron daemon: NOT RUNNING (no {', '.join(CRON_DAEMON_NAMES)} process): "
        "scheduled jobs are not executed'; fi"
    )

CRONTAB_LIST_CMD = (
    "if ! command -v crontab >/dev/null 2>&1; then echo 'crontab is not installed on this host' >&2; exit 127; fi; "
    'out=$(crontab -l 2>&1); rc=$?; '
    """if [ "$rc" -eq 0 ]; then if [ -n "$out" ]; then printf '%s\\n' "$out"; """
    """else echo "# the crontab of the login user ($(id -un)) is empty"; fi; """
    # No crontab is an answer, not a failure: "no crontab for <user>" (Vixie cron, cronie),
    # "can't open '<user>': No such file or directory" (BusyBox). Anything else still fails.
    """else case "$out" in *"no crontab for "*|*"can't open"*"No such file"*) """
    """echo "# no crontab for the login user ($(id -un))" ;; """
    """*) printf '%s\\n' "$out" >&2; exit "$rc" ;; esac; fi"""
)

def crontab_tasks_cmd(proc_dir: str = "/proc") -> str:
    """Builds the get_crontab_tasks command. proc_dir is there for the tests."""
    return f"{cron_daemon_check_cmd(proc_dir)}; {CRONTAB_LIST_CMD}"

@mcp.tool()
def get_crontab_tasks(
    host: str,
    user: str,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = TIMEOUT_DEFAULT_S,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Collects the crontab of the LOGIN USER (crontab -l) from a remote Linux host via SSH.
    For the cron jobs of all users and of the system (/etc/crontab, /etc/cron.d) use
    get_cron_jobs.
    The first line says whether a cron daemon is running ('# cron daemon: running: cron
    (pid 612)'): if it is NOT RUNNING, no cron job on the host is executed.
    A user without a crontab gets '# no crontab for the login user (<user>)', not an error.
    Values that look like secrets (passwords, tokens, keys, credentials in URLs) are replaced
    by '<redacted>' before the output is returned; the "redaction" field of the result says
    how many. It is pattern-based: a secret in an unusual form may still be shown, and a
    harmless value that looks like one may be hidden.
    """
    cmd = crontab_tasks_cmd()
    result = run_ssh_command(host, user, cmd, port, password, key_path, timeout, accept_new_hostkey)
    return redact_secrets_in_result(result)

CRON_JOBS_MAX_LINES_PER_FILE = 200
CRON_JOBS_PLAIN_NOTE = (
    "# not run as root (no sudo -n / doas -n access): only the cron files the login user "
    "can read are shown; user crontabs usually need root"
)
# Run as one `sh -c` (through sudo -n / doas -n when possible): user crontabs are readable
# by root only, and their directory often cannot even be listed by others. Comments and
# blank lines are left out; environment lines (MAILTO, PATH, ...) stay, they explain
# failing jobs. run-parts directories are listed by script name only.
# Debian: /var/spool/cron/crontabs/<user>; RHEL (cronie): /var/spool/cron/<user>;
# Alpine (BusyBox): /etc/crontabs/<user>, with /var/spool/cron/crontabs a symlink to it -
# a directory is read once however it is reached. The script always exits 0.
# @ROOT@ is a path prefix, empty except in the tests.
CRON_JOBS_SCRIPT = r"""print_file() {
    if [ ! -r "$1" ]; then echo "# $1 is not readable by $(id -un)"; return; fi
    awk -v max=@MAX@ '/^[ \t]*(#|$)/ { next } { n++; if (n <= max) print }
        END { if (n > max) printf "# ... %d more lines not shown\n", n - max; if (!n) print "# (only comments or empty lines)" }' "$1"
}
found=0
for f in @ROOT@/etc/crontab @ROOT@/etc/anacrontab @ROOT@/etc/cron.d/*; do
    [ -f "$f" ] || continue
    found=$((found + 1)); echo "# $f"; print_file "$f"
done
seen=
for dir in @ROOT@/var/spool/cron/crontabs @ROOT@/var/spool/cron @ROOT@/etc/crontabs; do
    [ -d "$dir" ] || continue
    real=$(readlink -f "$dir")
    case " $seen " in *" $real "*) continue ;; esac
    seen="$seen $real"
    for f in "$dir"/*; do
        [ -f "$f" ] || continue
        found=$((found + 1)); echo "# user crontab: ${f##*/} ($f)"; print_file "$f"
    done
done
header=
for d in @ROOT@/etc/cron.hourly @ROOT@/etc/cron.daily @ROOT@/etc/cron.weekly @ROOT@/etc/cron.monthly @ROOT@/etc/cron.yearly @ROOT@/etc/periodic/*; do
    [ -d "$d" ] || continue
    if [ -z "$header" ]; then header=1; echo "# run-parts directories (script names only)"; fi
    names=$(ls -A "$d" 2>/dev/null | grep -v '^\.placeholder$' | tr '\n' ' ')
    names=${names% }
    echo "$d: ${names:-(empty)}"
done
[ "$found" -gt 0 ] || echo "# no crontab files found"
"""

def cron_jobs_cmd(root: str = "", proc_dir: str = "/proc") -> str:
    """Builds the get_cron_jobs command. root and proc_dir are there for the tests."""
    script = (CRON_JOBS_SCRIPT
              .replace("@ROOT@", shlex.quote(root) if root else "")
              .replace("@MAX@", str(CRON_JOBS_MAX_LINES_PER_FILE)))
    return (
        f"{cron_daemon_check_cmd(proc_dir)}; "
        f"{as_root_or_plain(f'sh -c {shlex.quote(script)}', CRON_JOBS_PLAIN_NOTE)}"
    )

@mcp.tool()
def get_cron_jobs(
    host: str,
    user: str,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = TIMEOUT_DEFAULT_S,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Lists ALL cron jobs of a remote Linux host via SSH: /etc/crontab, /etc/anacrontab,
    /etc/cron.d/*, the crontab of every user (/var/spool/cron/crontabs, /var/spool/cron or
    /etc/crontabs, depending on the distribution) and the scripts in the run-parts
    directories (/etc/cron.daily, ..., /etc/periodic/* on Alpine; names only).
    USE THIS TOOL to find what runs on a schedule, e.g. a job that fills the disk, loads the
    CPU at night or should run but does not. For the login user's crontab alone use
    get_crontab_tasks; systemd timers are get_systemd_list_timers.
    The first line says whether a cron daemon is running: if it is NOT RUNNING, none of the
    jobs listed is executed. Each file starts with a '# <path>' or '# user crontab: <user>'
    line; comments and blank lines are left out, at most 200 lines per file.
    User crontabs are readable by root only, so the listing runs through sudo -n / doas -n
    when the login user is not root; if that is not allowed, it runs as the login user after
    a '# not run as root' line and shows only what that user can read.
    Values that look like secrets (passwords, tokens, keys, credentials in URLs) are replaced
    by '<redacted>' before the output is returned; the "redaction" field of the result says
    how many. It is pattern-based: a secret in an unusual form may still be shown, and a
    harmless value that looks like one may be hidden.
    """
    cmd = cron_jobs_cmd()
    result = run_ssh_command(host, user, cmd, port, password, key_path, timeout, accept_new_hostkey)
    return redact_secrets_in_result(result)

LISTENING_SOCKETS_PLAIN_NOTE = (
    "# not run as root (no sudo -n / doas -n access): "
    "process names are shown only for the login user's own sockets"
)
LISTENING_SOCKETS_CMD = (
    "if command -v ss >/dev/null 2>&1; then "
    f"{as_root_or_plain('ss -tulpn', LISTENING_SOCKETS_PLAIN_NOTE)}; "
    "elif command -v netstat >/dev/null 2>&1; then "
    "echo '# ss is not installed: netstat -tulnp'; "
    f"{as_root_or_plain('netstat -tulnp', LISTENING_SOCKETS_PLAIN_NOTE)}; "
    "else echo 'neither ss nor netstat is installed on this host' >&2; exit 127; fi"
)

@mcp.tool()
def get_listening_sockets(
    host: str,
    user: str,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = TIMEOUT_DEFAULT_S,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Collects ss -tulpn output (open ports and sockets) from a remote Linux host via SSH.
    If ss is not installed (e.g. Alpine), falls back to netstat -tulnp; the output then
    starts with a "# ss is not installed: netstat -tulnp" line and has netstat's columns.
    If the login user is not root, runs through sudo -n / doas -n to get the process
    names of all sockets; if that is not allowed, runs as the login user and says so in
    a "# not run as root" line (process names are then shown only for its own sockets).
    """
    cmd = LISTENING_SOCKETS_CMD
    return run_ssh_command(host, user, cmd, port, password, key_path, timeout, accept_new_hostkey)

# Step 1, the only part that needs root: for every process whose /proc entry can be read,
# a "P <pid> <name> <executable>" line and an "F <file>" line per file it has mapped as
# executable code (its shared libraries). Kernel threads have no executable and are skipped,
# as is a process that exits half-way. A file replaced by an upgrade is shown without the
# kernel's " (deleted)" mark: the process still runs the old code, under the same path.
PROCESS_FILES_PROC_SCRIPT = r"""for d in /proc/[0-9]*; do
exe=$(readlink "$d/exe" 2>/dev/null) && [ -n "$exe" ] || continue
read -r comm 2>/dev/null < "$d/comm" || continue
files=$(awk '$2 ~ /x/ && index($0, "/") { p = substr($0, index($0, "/")); sub(/ \(deleted\)$/, "", p); if (!seen[p]++) print "F\t" p }' "$d/maps" 2>/dev/null) || continue
printf 'P\t%s\t%s\t%s\n' "${d#/proc/}" "$comm" "${exe% (deleted)}"
[ -z "$files" ] || printf '%s\n' "$files"
done"""
PROCESS_FILES_PLAIN_NOTE = (
    "# not run as root (no sudo -n / doas -n access): "
    "only the login user's own processes are listed"
)
# Step 2: every distinct file of step 1, in both spellings of a merged /usr (the kernel
# says /usr/lib/x where the package database may say /lib/x, or the other way round).
PROCESS_FILES_PATHS = (
    r"""awk -F'\t' '{ p = ($1 == "P") ? $4 : $2 } p == "" || seen[p]++ { next } { print p } """
    r"""p ~ /^\/usr\/(s?bin|lib[^\/]*)\// { print substr(p, 5) } """
    r"""p ~ /^\/(s?bin|lib[^\/]*)\// { print "/usr" p }'"""
)
# Keeps the "package<TAB>file" lines (after the "#" line) whose file is in the list before it.
PROCESS_FILES_OWNED = r"""awk -F'\t' '!listed { if ($0 == "#") listed = 1; else want[$0]; next } $2 in want'"""
# apk has no fast "who owns these files": the installed database lists them per package
# (P: package, F: directory, R: file name).
APK_DB_FILES = (
    """awk '/^P:/ { p = substr($0, 3) } /^F:/ { d = substr($0, 3) } """
    f"""/^R:/ {{ print p "\\t/" d "/" substr($0, 3) }}' {APK_DB_PATH}"""
)
PROCESS_FILES_CMD = (
    f"PROC={shlex.quote(PROCESS_FILES_PROC_SCRIPT)}; "
    f"""out=$({as_root_or_plain('sh -c "$PROC"', PROCESS_FILES_PLAIN_NOTE)}) || exit; """
    """printf '%s\\n' "$out"; """
    f"""paths=$(printf '%s\\n' "$out" | {PROCESS_FILES_PATHS}); """
    # dpkg-query -S exits 1 when one of the files has no owner; the others are still printed
    "if command -v dpkg-query >/dev/null 2>&1; then echo '# owners: dpkg-query -S'; "
    """printf '%s\\n' "$paths" | xargs -d '\\n' dpkg-query -S 2>/dev/null; true; """
    "elif command -v rpm >/dev/null 2>&1; then echo '# owners: package, file'; "
    """{ printf '%s\\n#\\n' "$paths"; rpm -qa --qf '[%{=NAME}\\t%{FILENAMES}\\n]'; } | """
    f"{PROCESS_FILES_OWNED}; "
    f"elif [ -r {APK_DB_PATH} ]; then echo '# owners: package, file'; "
    f"""{{ printf '%s\\n#\\n' "$paths"; {APK_DB_FILES}; }} | {PROCESS_FILES_OWNED}; """
    "else echo '# owners: unknown (no dpkg, rpm or apk package database)'; fi"
)

@mcp.tool()
def get_process_files(
    host: str,
    user: str,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = TIMEOUT_DEFAULT_S,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Shows which packages' code every running process executes on a remote Linux host via
    SSH: its executable, the shared libraries it has loaded, and the package that owns each
    of those files. USE THIS TOOL to find which services really use a library (e.g. is the
    vulnerable libssl loaded by anything that listens on the network?) and which processes
    still run a binary or library that was replaced by an upgrade and need a restart.
    Combine the pids with get_listening_sockets.
    The output has two parts, tab-separated:
    1. Per process a line "P <pid> <name> <executable>", followed by one line "F <file>"
       for every file it has mapped as executable code (read from /proc/<pid>/maps).
    2. After a line starting with "# owners": the package of each of those files.
       rpm and apk: "<package> <file>". dpkg: "<package>[:arch][, <package>...]: <file>",
       as printed by dpkg-query -S. A file missing here belongs to no package. With a merged
       /usr a file may be listed as /lib/... or /bin/... where part 1 says /usr/lib/... or
       /usr/bin/..., or the other way round.
    If the login user is not root, part 1 runs through sudo -n / doas -n to see all
    processes; if that is not allowed, it runs as the login user and says so in a
    "# not run as root" first line (only that user's own processes are then listed).
    """
    cmd = PROCESS_FILES_CMD
    return run_ssh_command(host, user, cmd, port, password, key_path, timeout, accept_new_hostkey)

# A process name is matched against /proc/<pid>/comm: what ps shows as COMM, at most 15
# characters (the kernel cuts longer names: systemd-journald is "systemd-journal"). The kernel
# allows nearly any byte there; this is the set real names use, so that a name never brings
# shell or regex syntax (it is compared as a string on the host, not passed to pgrep).
PROCESS_NAME_MAX = 15
PROCESS_NAME_CHARS = r"A-Za-z0-9._@:+/()\-"
PROCESS_NAME_PATTERN = re.compile(rf"[{PROCESS_NAME_CHARS}]([{PROCESS_NAME_CHARS} ]*[{PROCESS_NAME_CHARS}])?")
PROCESS_NAME_RULES = (
    f"A process name is its COMM, as ps shows it: at most {PROCESS_NAME_MAX} characters "
    "(longer names are cut by the kernel, e.g. 'systemd-journal' for systemd-journald), "
    "ASCII letters, digits and . _ - : / @ + ( ), spaces only inside (e.g. nginx, php-fpm8.2, "
    "kube-apiserver, (sd-pam))."
)

def process_name_error(name: Any) -> Optional[str]:
    """Says what is wrong with a process name, or returns None when it is valid."""
    if not isinstance(name, str):
        return f"Invalid name: it must be a string, got {type(name).__name__}. {PROCESS_NAME_RULES}"
    if name == "":
        return f"Invalid name: it is empty. {PROCESS_NAME_RULES}"
    shown = repr(name[:40]) + ("..." if len(name) > 40 else "")
    if len(name) > PROCESS_NAME_MAX:
        return f"Invalid name {shown}: it is {len(name)} characters long. {PROCESS_NAME_RULES}"
    if not PROCESS_NAME_PATTERN.fullmatch(name):
        bad = sorted(set(re.sub(rf"[{PROCESS_NAME_CHARS} ]", "", name)))
        what = f"it contains {', '.join(repr(c) for c in bad)}" if bad else "it starts or ends with a space"
        return f"Invalid name {shown}: {what}. {PROCESS_NAME_RULES}"
    return None

# At most this many processes are described when name matches several (php-fpm workers).
PROCESS_INFO_MAX_PROCESSES = 5
# The exit code of PROCESS_INFO_SCRIPT for "no such process" and "the PID has another name",
# with the reason on stdout: unlike a sudo refusal, it must not trigger the plain re-run.
PROCESS_INFO_NOT_FOUND = 3
# /proc/<pid>/status fields worth showing; the rest (signal masks, NUMA lists) is noise
PROCESS_INFO_STATUS_FIELDS = (
    "Name", "State", "Tgid", "PPid", "Uid", "Gid", "Threads", "VmPeak", "VmSize", "VmHWM",
    "VmRSS", "RssAnon", "RssFile", "RssShmem", "VmSwap", "voluntary_ctxt_switches",
    "nonvoluntary_ctxt_switches", "CapEff", "NoNewPrivs", "Seccomp", "Cpus_allowed_list",
)
# $1 = pid or '', $2 = name or '': validated by the tool, passed as arguments, never as code.
# Not /proc/<pid>/environ (where secrets are), and of /proc/<pid>/fd only the count.
PROCESS_INFO_SCRIPT = r"""pid=$1; name=$2; max=@MAX@; notfound=@NOTFOUND@
me=$(id -un)
if [ "$(id -u)" = 0 ]; then seen=; else seen=" for $me (not root: other users' processes are hidden if /proc is mounted with hidepid)"; fi
if [ -n "$pid" ]; then
    if ! { IFS= read -r comm < "/proc/$pid/comm"; } 2>/dev/null; then echo "no process with PID $pid$seen"; exit "$notfound"; fi
    if [ -n "$name" ] && [ "$comm" != "$name" ]; then
        echo "PID $pid is '$comm', not '$name': the process may have exited and its PID been given to another one"
        exit "$notfound"
    fi
    pids=$pid
else
    pids=$(for d in /proc/[0-9]*; do { IFS= read -r c < "$d/comm"; } 2>/dev/null || continue; [ "$c" = "$name" ] && echo "${d#/proc/}"; done | sort -n)
    [ -n "$pids" ] || { echo "no process named '$name'$seen"; exit "$notfound"; }
    n=$(printf '%s\n' "$pids" | wc -l | tr -d ' ')
    if [ "$n" -gt "$max" ]; then
        echo "# $n processes are named '$name': the $max with the lowest PIDs are shown"
        pids=$(printf '%s\n' "$pids" | head -n "$max")
    fi
fi
for p in $pids; do
    d=/proc/$p
    { IFS= read -r comm < "$d/comm"; } 2>/dev/null || { echo "=== PID $p: exited"; continue; }
    echo "=== PID $p ($comm)"
    echo "# ps"
    if ps -V 2>&1 | grep -q procps; then
        ps -ww -p "$p" -o pid,ppid,user,stat,ni,etimes,lstart,%cpu,%mem,rss,vsz,nlwp,wchan:32,args
    else
        echo "# BusyBox ps: no %CPU, %MEM, threads or wait channel; ELAPSED is the time since it started"
        ps -o pid,ppid,user,stat,nice,etime,time,rss,vsz,args | awk -v p="$p" 'NR == 1 || $1 == p'
    fi
    echo "# $d/status"
    grep -E '^(@FIELDS@):' "$d/status" 2>/dev/null
    echo "# $d/cgroup (the systemd unit or container the process belongs to)"
    cat "$d/cgroup" 2>/dev/null
    echo "# open file descriptors ($d/fd), to compare with Max open files in limits"
    if fds=$(ls -A "$d/fd" 2>/dev/null); then echo "open: $(printf '%s\n' "$fds" | grep -c .)"; else echo "open: not readable by $me"; fi
    echo "# $d/limits"
    cat "$d/limits" 2>/dev/null || echo "not readable by $me"
    echo "# $d/oom_score, oom_score_adj"
    echo "oom_score: $(cat "$d/oom_score" 2>/dev/null)"
    echo "oom_score_adj: $(cat "$d/oom_score_adj" 2>/dev/null)"
    echo "# $d/io (bytes the process made the disk read and write)"
    cat "$d/io" 2>/dev/null || echo "not readable by $me"
done""".replace("@MAX@", str(PROCESS_INFO_MAX_PROCESSES)).replace(
    "@NOTFOUND@", str(PROCESS_INFO_NOT_FOUND)).replace("@FIELDS@", "|".join(PROCESS_INFO_STATUS_FIELDS))
PROCESS_INFO_PLAIN_NOTE = (
    "# not run as root (no sudo -n / doas -n access): open files and I/O of other users' "
    "processes are not readable"
)

def process_info_cmd(pid: Optional[int], name: Optional[str]) -> str:
    """The command of get_process_info. pid and name must have been validated (is_valid_pid,
    process_name_error); they reach the script as its arguments $1 and $2."""
    script = f'sh -c "$S" sh {shlex.quote("" if pid is None else str(pid))} {shlex.quote(name or "")}'
    return (
        f"S={shlex.quote(PROCESS_INFO_SCRIPT)}; {AS_ROOT_PREFIX}"
        # through sudo/doas first; "not found" (exit 3) is an answer, a refusal is not
        f'if [ -n "$AS_ROOT" ]; then out=$($AS_ROOT {script} 2>/dev/null); rc=$?; '
        f'if [ "$rc" -eq 0 ] || [ "$rc" -eq {PROCESS_INFO_NOT_FOUND} ]; then '
        """printf '%s\\n' "$out"; exit "$rc"; fi; fi; """
        f"""if [ "$(id -u)" != 0 ]; then echo {shlex.quote(PROCESS_INFO_PLAIN_NOTE)}; fi; {script}"""
    )

@mcp.tool()
def get_process_info(
    host: str,
    user: str,
    pid: Optional[int] = None,
    name: Optional[str] = None,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = TIMEOUT_DEFAULT_S,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Details of ONE process on a remote Linux host via SSH, given by pid or by name. Use
    get_ps_aux_top_cpu_consumers, get_ps_aux_top_mem_consumers or get_top first to find it.
    Give pid, or name, or both: with both, the process is described only if that PID still
    has that name (a PID from an earlier call may have been given to another process after
    a restart). name is matched exactly against the process name (COMM in ps, at most 15
    characters, e.g. nginx, php-fpm8.2); when several processes have it, the 5 with the
    lowest PIDs are described.
    Per process, in sections starting with '#':
    - ps: PID, PPID, user, state (D = waiting on I/O, Z = zombie), nice, elapsed seconds and
      start time, %CPU, %MEM, RSS, VSZ, threads, wait channel, command line. On BusyBox
      (Alpine) fewer columns.
    - /proc/<pid>/status: state, parent, uids, threads, memory now and at its peak (VmHWM),
      swap used (VmSwap), context switches (many non-voluntary ones: CPU contention),
      capabilities, NoNewPrivs, seccomp.
    - /proc/<pid>/cgroup: the systemd unit or container the process belongs to.
    - open file descriptors (the count) and /proc/<pid>/limits: compare with Max open files.
    - /proc/<pid>/oom_score and oom_score_adj: who the OOM killer picks first.
    - /proc/<pid>/io: bytes read and written (root, or the process owner).
    The environment of the process is not shown. If the login user is not root, the tool
    runs through sudo -n / doas -n; if that is not allowed, it runs as the login user after
    a '# not run as root' line, and open files and I/O of other users' processes are then
    not readable.
    Process command lines can hold secrets (--password=..., URLs with credentials).
    Values that look like secrets (passwords, tokens, keys, credentials in URLs) are replaced
    by '<redacted>' before the output is returned; the "redaction" field of the result says
    how many. It is pattern-based: a secret in an unusual form may still be shown, and a
    harmless value that looks like one may be hidden.
    """
    if pid is None and name is None:
        return {"ok": False, "error": "Give pid, or name, or both"}
    if pid is not None and not is_valid_pid(pid):
        return {"ok": False, "error": PID_ERROR}
    if name is not None:
        error = process_name_error(name)
        if error:
            return {"ok": False, "error": error}
    cmd = process_info_cmd(pid, name)
    result = run_ssh_command(host, user, cmd, port, password, key_path, timeout, accept_new_hostkey)
    data = result.get("data")
    if isinstance(data, dict) and data.get("exit_code") == PROCESS_INFO_NOT_FOUND and "error" not in result:
        # the script's reason: "no process with PID 123", "PID 123 is 'bash', not 'nginx': ..."
        lines = (data.get("stdout") or "").strip().splitlines()
        result["error"] = lines[-1] if lines else "Process not found"
    return redact_secrets_in_result(result)

@mcp.tool()
def get_ip_addr(
    host: str,
    user: str,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = TIMEOUT_DEFAULT_S,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Collects ip addr show output (network interfaces, their state, MAC, IPv4 and IPv6 addresses)
    from a remote Linux host via SSH
    """
    cmd = "ip addr show"
    return run_ssh_command(host, user, cmd, port, password, key_path, timeout, accept_new_hostkey)

@mcp.tool()
def get_ip_route(
    host: str,
    user: str,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = TIMEOUT_DEFAULT_S,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Collects the IPv4 and IPv6 routing tables (ip route show, ip -6 route show: default gateway,
    per-interface routes) from a remote Linux host via SSH
    """
    # ip route show prints IPv4 only, hence the second call for IPv6
    cmd = "echo '== IPv4 =='; ip route show; echo '== IPv6 =='; ip -6 route show"
    return run_ssh_command(host, user, cmd, port, password, key_path, timeout, accept_new_hostkey)

@mcp.tool()
def get_dns_lookup(
    name: str,
    host: str,
    user: str,
    use_dig: bool = False,
    record_type: str = "A",
    server: Optional[str] = None,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = TIMEOUT_DEFAULT_S,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Resolves a hostname (or reverse-resolves an IP address) ON a remote Linux host via SSH,
    and prints its /etc/resolv.conf. USE THIS TOOL to check what a name resolves to from that host.
    By default uses getent, which resolves exactly like applications on the host do
    (/etc/hosts, nsswitch.conf, then DNS). A name that does not resolve gives exit code 2.
    use_dig=True queries the DNS servers directly with dig (bypassing /etc/hosts) and returns the
    full answer: status (NOERROR, NXDOMAIN, SERVFAIL), CNAME chain, TTLs, the server that answered
    and query time. It fails with exit code 127 if dig is not installed - then use use_dig=False.
    The next two parameters require use_dig=True:
    record_type is one of A (default), AAAA, CNAME, MX, NS, TXT, SOA, PTR, SRV, CAA.
    server (IP address or hostname, e.g. '8.8.8.8') asks that DNS server instead of the ones in
    /etc/resolv.conf - compare both answers to tell a broken resolver from a broken record.
    """
    is_ip = is_valid_ip_address(name)
    if not is_ip and not is_valid_hostname(name):
        return {"ok": False, "error": DNS_NAME_ERROR}
    if not isinstance(use_dig, bool):
        return {"ok": False, "error": "Invalid value of use_dig, should be Boolean"}
    safe_type = normalize_dns_record_type(record_type)
    if safe_type is None:
        return {"ok": False, "error": DNS_RECORD_TYPE_ERROR}
    if server is not None and not (is_valid_ip_address(server) or is_valid_hostname(server)):
        return {"ok": False, "error": DNS_SERVER_ERROR}
    if not use_dig and (safe_type != "A" or server is not None):
        return {"ok": False, "error": "record_type and server require use_dig=True"}
    if is_ip and safe_type not in ("A", "PTR"):
        return {"ok": False, "error": "An IP address can only be reverse-resolved: use record_type 'PTR' or omit it"}

    safe_name = shlex.quote(name)
    if use_dig:
        # No +short: it hides the status, so NXDOMAIN, SERVFAIL and an empty answer look the same.
        # +time/+tries keep the worst case (3 nameservers) well under the command timeout.
        lookup = "dig +time=2 +tries=2"
        if server is not None:
            lookup += f" @{shlex.quote(server)}"
        # -x builds the in-addr.arpa / ip6.arpa name and asks for its PTR record
        lookup += f" -x {safe_name}" if is_ip else f" {safe_name} {safe_type}"
        lookup_cmd = (
            "if ! command -v dig >/dev/null 2>&1; then "
            "echo 'dig is not installed on this host, call again with use_dig=False' >&2; exit 127; fi; "
            f"{lookup}"
        )
    else:
        # ahosts follows the same path as getaddrinfo (IPv4 and IPv6); hosts does the reverse lookup
        lookup = f"getent {'hosts' if is_ip else 'ahosts'} {safe_name}"
        lookup_cmd = (
            f'{lookup}; rc=$?; [ "$rc" -eq 0 ] || echo "not resolved (getent exit code $rc)"; exit "$rc"'
        )
    cmd = (
        "echo '== /etc/resolv.conf =='; cat /etc/resolv.conf; "
        f"echo; echo {shlex.quote(f'== {lookup} ==')}; {lookup_cmd}"
    )
    return run_ssh_command(host, user, cmd, port, password, key_path, timeout, accept_new_hostkey)

@mcp.tool()
def check_tcp_connect(
    target_host: str,
    target_port: int,
    host: str,
    user: str,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = TIMEOUT_DEFAULT_S,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Checks FROM a remote Linux host (reached via SSH) whether a TCP connection to
    target_host:target_port can be opened (nc -vz). USE THIS TOOL to tell whether a service
    (database, API, another server) is reachable from that host.
    target_host is a hostname or an IPv4/IPv6 address, target_port is 1-65535. Do not confuse them
    with host/port, which are the SSH connection to the machine the check runs on.
    Only the connection is opened and closed, no data is sent. One port per call.
    ok=True means the port accepted the connection. Otherwise nc's message tells why:
    'Connection refused' - the target is reachable but nothing listens on the port;
    'timed out' - no answer in 3 seconds, usually a firewall or a routing problem;
    a name resolution error - check the name with get_dns_lookup.
    Fails with exit code 127 if nc is not installed on the host.
    """
    if not (is_valid_ip_address(target_host) or is_valid_hostname(target_host)):
        return {"ok": False, "error": TCP_TARGET_ERROR}
    if not is_valid_tcp_port(target_port):
        return {"ok": False, "error": TCP_PORT_ERROR}

    # -z: connect and close without sending data; -v: print the outcome (it goes to stderr);
    # -w: give up after N seconds instead of waiting for the kernel's connect timeout
    cmd = (
        "if ! command -v nc >/dev/null 2>&1; then "
        "echo 'nc is not installed on this host' >&2; exit 127; fi; "
        f"nc -vz -w {TCP_CONNECT_TIMEOUT_S} {shlex.quote(target_host)} {target_port}"
    )
    return run_ssh_command(host, user, cmd, port, password, key_path, timeout, accept_new_hostkey)

@mcp.tool()
def get_service_logs_from_journalctl(
    service: str,
    host: str,
    user: str,
    lines: int = 200,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = TIMEOUT_DEFAULT_S,
    accept_new_hostkey: bool = False,
    since: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Gets recent journald logs for a specific systemd service.
    Optional since limits them to a time window: '30 min ago', '2 hours ago', 'today',
    'yesterday' or 'YYYY-MM-DD HH:MM:SS' (the last `lines` entries within it are returned).
    Log lines can hold secrets.
    Values that look like secrets (passwords, tokens, keys, credentials in URLs) are replaced
    by '<redacted>' before the output is returned; the "redaction" field of the result says
    how many. It is pattern-based: a secret in an unusual form may still be shown, and a
    harmless value that looks like one may be hidden.
    """
    VALID_SERVICE_PATTERN = re.compile(r"^[a-zA-Z0-9.\-_@:]+$")
    if not VALID_SERVICE_PATTERN.match(service):
        return {"ok": False, 
                "error": f"Invalid service name: '{service}'. Only ASCII alphanumeric characters, '.', '-', '_', '@', and ':' are allowed."}

    if not is_valid_lines(lines):
        return {"ok": False, "error": LINES_ERROR}
    
    lines = max(1, min(lines, 1000))
    safe_service = shlex.quote(service)
    cmd = f"journalctl -xeu {safe_service} -n {lines} --no-pager"
    if since is not None:
        safe_since = normalize_since(since)
        if safe_since is None:
            return {"ok": False, "error": SINCE_ERROR}
        cmd += f" --since {shlex.quote(safe_since)}"
    result = run_ssh_command(host, user, cmd, port, password, key_path, timeout, accept_new_hostkey)
    return redact_secrets_in_result(result)

def journal_errors_cmd(lines: int, current_boot_only: bool = False, safe_since: Optional[str] = None) -> str:
    """Builds the get_journal_errors command. The arguments must already be validated:
    lines with is_valid_lines, safe_since by normalize_since."""
    cmd = f"journalctl -p warning -n {lines} --no-pager"
    if current_boot_only:
        cmd += " -b"
    if safe_since is not None:
        cmd += f" --since {shlex.quote(safe_since)}"
    return cmd

@mcp.tool()
def get_journal_errors(
    host: str,
    user: str,
    lines: int = 200,
    current_boot_only: bool = False,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = TIMEOUT_DEFAULT_S,
    accept_new_hostkey: bool = False,
    since: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Gets recent journald entries of priority warning and above (warning, err, crit, alert, emerg)
    from ALL units and the kernel. USE THIS TOOL FIRST when you don't know which service is at fault.
    With current_boot_only=True only entries since the last boot are returned.
    Optional since limits them to a time window: '30 min ago', '2 hours ago', 'today',
    'yesterday' or 'YYYY-MM-DD HH:MM:SS' (the last `lines` entries within it are returned).
    Log lines can hold secrets.
    Values that look like secrets (passwords, tokens, keys, credentials in URLs) are replaced
    by '<redacted>' before the output is returned; the "redaction" field of the result says
    how many. It is pattern-based: a secret in an unusual form may still be shown, and a
    harmless value that looks like one may be hidden.
    """
    if not is_valid_lines(lines):
        return {"ok": False, "error": LINES_ERROR}
    if not isinstance(current_boot_only, bool):
        return {"ok": False, "error": "Invalid value of current_boot_only, should be Boolean"}

    safe_since = None
    if since is not None:
        safe_since = normalize_since(since)
        if safe_since is None:
            return {"ok": False, "error": SINCE_ERROR}
    cmd = journal_errors_cmd(lines, current_boot_only, safe_since)
    result = run_ssh_command(host, user, cmd, port, password, key_path, timeout, accept_new_hostkey)
    return redact_secrets_in_result(result)

JOURNAL_DISK_USAGE_PLAIN_NOTE = (
    "# not run as root (no sudo -n / doas -n access): "
    "only the journal files the login user can read are counted"
)
# Checked first, with a clear message: Alpine and other hosts without systemd have no journald
JOURNAL_DISK_USAGE_CMD = (
    "if ! command -v journalctl >/dev/null 2>&1; then "
    "echo 'journalctl is not installed on this host' >&2; exit 127; fi; "
    f"{as_root_or_plain('journalctl --disk-usage', JOURNAL_DISK_USAGE_PLAIN_NOTE)}"
)

@mcp.tool()
def get_journalctl_disk_usage(
    host: str,
    user: str,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = TIMEOUT_DEFAULT_S,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Shows how much disk space the systemd journal takes (journalctl --disk-usage): the sum
    of all active and archived journal files. USE THIS TOOL when /var/log is large or the
    disk is full on a systemd host.
    If the login user is not root, runs through sudo -n / doas -n so that every journal is
    counted; if that is not allowed, runs as the login user and says so in a
    "# not run as root" line (the total then covers only the journals it can read).
    """
    cmd = JOURNAL_DISK_USAGE_CMD
    return run_ssh_command(host, user, cmd, port, password, key_path, timeout, accept_new_hostkey)

BUSYBOX_LAST_HEADER ="# BusyBox: last (short times without the year)"
BUSYBOX_LAST_SINCE_ERROR = "last on this host is the BusyBox one and cannot filter by time; call without since"

def _run_login_history(
    binary: str,
    host: str,
    user: str,
    lines: int,
    since: Optional[str],
    port: int,
    password: Optional[str],
    key_path: Optional[str],
    timeout: int,
    accept_new_hostkey: bool,
) -> Dict[str, Any]:
    """Shared body of get_last_logins (last) and get_failed_logins (lastb)."""
    if not is_valid_lines(lines):
        return {"ok": False, "error": LINES_ERROR}

    # -F prints full login/logout times including the year
    cmd = f"{binary} -F -n {lines}"
    if since is not None:
        safe_since = normalize_since(since)
        if safe_since is None:
            return {"ok": False, "error": SINCE_ERROR}
        cmd += f" --since {shlex.quote(safe_since)}"
    if binary == "lastb":
        # btmp is readable by root only
        cmd = as_root(cmd)
    elif since is not None:
        # BusyBox last takes no options at all, so it cannot filter by time
        cmd = busybox_fallback(cmd, binary, f"echo {shlex.quote(BUSYBOX_LAST_SINCE_ERROR)} >&2; exit 2")
    else:
        # plain `last` is newest first too; awk keeps the header row plus `lines` rows
        cmd = busybox_fallback(
            cmd, binary, f"echo {shlex.quote(BUSYBOX_LAST_HEADER)}; set -o pipefail; last | awk 'NR <= {lines + 1}'"
        )
    # Checked first, with a clear message: through sudo a missing program otherwise
    # shows up as the misleading "sudo: a password is required".
    cmd = (
        f"if ! command -v {binary} >/dev/null 2>&1; then "
        f"echo '{binary} is not installed on this host' >&2; exit 127; fi; {cmd}"
    )
    return run_ssh_command(host, user, cmd, port, password, key_path, timeout, accept_new_hostkey)

@mcp.tool()
def get_last_logins(
    host: str,
    user: str,
    lines: int = 50,
    since: Optional[str] = None,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = TIMEOUT_DEFAULT_S,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Lists recent SUCCESSFUL logins (last, from wtmp) to a remote Linux host via SSH, newest first:
    user, terminal, source address, login/logout time. Also shows reboots.
    For failed login attempts use get_failed_logins.
    On BusyBox hosts (Alpine), where last takes no options, the output is plain `last`
    cut to `lines` rows: its first line starts with '# BusyBox', times have no year,
    and since is not supported (the tool fails with a message saying so).
    Optional since limits them to a time window: '30 min ago', '2 hours ago', 'today',
    'yesterday' or 'YYYY-MM-DD HH:MM:SS'.
    """
    return _run_login_history(
        "last", host, user, lines, since, port, password, key_path, timeout, accept_new_hostkey
    )

@mcp.tool()
def get_failed_logins(
    host: str,
    user: str,
    lines: int = 50,
    since: Optional[str] = None,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = TIMEOUT_DEFAULT_S,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Lists recent FAILED login attempts (lastb, from btmp) on a remote Linux host via SSH, newest first:
    attempted user, terminal, source address, time. USE THIS TOOL to check for brute-force attempts.
    Requires root, since btmp is not world-readable: when the login user is not root,
    the command is run through passwordless sudo or doas (sudo -n / doas -n).
    Optional since limits them to a time window: '30 min ago', '2 hours ago', 'today',
    'yesterday' or 'YYYY-MM-DD HH:MM:SS'.
    """
    return _run_login_history(
        "lastb", host, user, lines, since, port, password, key_path, timeout, accept_new_hostkey
    )

@mcp.tool()
def get_coredumps(
    host: str,
    user: str,
    command: str = "list",
    pid: Optional[int] = None,
    lines: int = 50,
    since: Optional[str] = None,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = TIMEOUT_DEFAULT_S,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Inspects crashes (core dumps) recorded by systemd-coredump on a remote Linux host via SSH.
    command='list' lists the last `lines` core dumps (time, PID, signal, executable), below the column header.
    When there are no core dumps, coredumpctl exits with code 1 and ok is False - that is not a failure.
    command='info' shows details of a core dump (signal, command line, stack trace if available):
    of the given pid, or of the most recent one when pid is omitted.
    Optional since limits them to a time window: '30 min ago', '2 hours ago', 'today',
    'yesterday' or 'YYYY-MM-DD HH:MM:SS'.
    Seeing other users' core dumps usually requires root.
    """
    if not is_valid_coredump_command(command):
        return {"ok": False, "error": COREDUMP_COMMAND_ERROR}
    if pid is not None and not is_valid_pid(pid):
        return {"ok": False, "error": PID_ERROR}
    if not is_valid_lines(lines):
        return {"ok": False, "error": LINES_ERROR}

    cmd = f"coredumpctl {command} --no-pager"
    if since is not None:
        safe_since = normalize_since(since)
        if safe_since is None:
            return {"ok": False, "error": SINCE_ERROR}
        cmd += f" --since {shlex.quote(safe_since)}"
    if pid is not None:
        cmd += f" {pid}"
    elif command == "info":
        cmd += " -1"
    if command == "list":
        # coredumpctl lists oldest first, so the tail keeps the most recent ones
        cmd = tail_keeping_header(cmd, lines)
    return run_ssh_command(host, user, cmd, port, password, key_path, timeout, accept_new_hostkey)

# ---- Host overview ----
# Many facts in one tool call: every section is exactly what one existing tool sends (the
# same builder), run one after another over the pooled SSH connection, each in its own
# channel through run_ssh_command, as that tool would. Facts only: no thresholds, no
# findings, no ranking; interpreting them is the caller's job.
# See decision_records/get_host_overview.md.
HOST_OVERVIEW_SECTIONS = (
    # (section, the tool it comes from, the command that tool sends)
    ("hostname", "get_hostname", HOSTNAME_CMD),
    ("os_release", "get_distroname_version", OS_RELEASE_CMD),
    ("kernel", "get_kernel_version", KERNEL_VERSION_CMD),
    ("libc", "get_libc_version", LIBC_VERSION_CMD),
    ("uptime", "get_uptime", UPTIME_CMD),
    ("cpu", "get_cpu_info", cpu_info_cmd(False)),
    ("memory", "get_free_memory", FREE_MEMORY_CMD),
    ("pressure", "get_pressure", PRESSURE_CMD),
    ("disk_free", "get_disk_free", DISK_FREE_CMD),
    ("inode_usage", "get_inode_usage", INODE_USAGE_CMD),
    ("mount_problems", "get_mount_problems", mount_problems_cmd()),
    ("failed_units", "get_systemd_list_failed", SYSTEMD_FAILED_CMD),
    ("top_cpu_processes", "get_ps_aux_top_cpu_consumers", PS_TOP_CPU_CMD),
    ("top_memory_processes", "get_ps_aux_top_mem_consumers", PS_TOP_MEM_CMD),
    ("listening_sockets", "get_listening_sockets", LISTENING_SOCKETS_CMD),
    ("journal_errors", "get_journal_errors", journal_errors_cmd(200)),
)
# the sections whose source tool redacts its output, with that tool's patterns
HOST_OVERVIEW_REDACTED_TOOLS = {
    "get_mount_problems": MOUNT_SECRET_PATTERNS,
    "get_ps_aux_top_cpu_consumers": SECRET_PATTERNS,
    "get_ps_aux_top_mem_consumers": SECRET_PATTERNS,
    "get_journal_errors": SECRET_PATTERNS,
}
def tool_default_timeout(tool: str) -> int:
    """The default `timeout` of a tool, so that a section is run as that tool would run it."""
    return inspect.signature(globals()[tool]).parameters["timeout"].default
HOST_OVERVIEW_TIMEOUT_ERROR = TIMEOUT_ERROR + " per section"

@mcp.tool()
def get_host_overview(
    host: str,
    user: str,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: Optional[int] = None,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Collects a broad first look at a remote Linux host in one tool call: a good first call
    on an unfamiliar host, before the narrower tools. Facts only: no thresholds, no
    findings, no judgement of what is normal; interpreting them is left to the caller.
    Each section is exactly the result of the tool named in its source_tool, with that
    tool's defaults (its timeout included), so that tool's description applies to it:
    hostname (get_hostname), os_release (get_distroname_version), kernel (get_kernel_version),
    libc (get_libc_version), uptime (get_uptime), cpu (get_cpu_info), memory (get_free_memory),
    pressure (get_pressure), disk_free (get_disk_free), inode_usage (get_inode_usage),
    mount_problems (get_mount_problems), failed_units (get_systemd_list_failed),
    top_cpu_processes (get_ps_aux_top_cpu_consumers), top_memory_processes
    (get_ps_aux_top_mem_consumers), listening_sockets (get_listening_sockets),
    journal_errors (get_journal_errors, last 200 warnings and errors).
    Parts that need root (findmnt --verify in mount_problems, process names in
    listening_sockets) use sudo -n / doas -n and fall back as those tools do.
    data.sections maps each section, in this order, to {source_tool, ok, exit_code, stdout,
    stderr, seconds} plus timed_out and error when that tool's result has them. seconds is
    the time of the section's SSH call as seen from this server.
    mount_problems, top_cpu_processes, top_memory_processes and journal_errors are redacted
    as their tools are: values that look like secrets (passwords, tokens, keys, credentials
    in URLs) are replaced by '<redacted>' and redaction_replaced says how many; the
    pattern-based caveats are in data.redaction_note.
    A section that does not apply to the host fails on its own (e.g. failed_units and
    journal_errors without systemd: exit code 127) and the others still run; ok is True
    when the host was reachable for every section, whatever the sections returned.
    timeout (seconds, 1-360), when given, is the limit for EACH section instead of its
    tool's default (60 s). The sections run one after another over one SSH
    connection: usually a few seconds in all.
    The output is not shortened: about 10-20 KB on a typical server.
    """
    if timeout is not None and not is_valid_timeout(timeout):
        return {"ok": False, "error": HOST_OVERVIEW_TIMEOUT_ERROR}
    collected_at = datetime.now(timezone.utc).isoformat()
    sections: Dict[str, Any] = {}
    for name, tool, cmd in HOST_OVERVIEW_SECTIONS:
        started = time.monotonic()
        section_timeout = tool_default_timeout(tool) if timeout is None else timeout
        result = run_ssh_command(host, user, cmd, port, password, key_path, section_timeout, accept_new_hostkey)
        if tool in HOST_OVERVIEW_REDACTED_TOOLS:
            result = redact_secrets_in_result(result, HOST_OVERVIEW_REDACTED_TOOLS[tool])
        data = result.get("data")
        if not isinstance(data, dict):
            # could not connect or authenticate: every other section would fail the same way
            if not sections:
                return result
            return {"ok": False, "host": host, "collected_at_utc": collected_at,
                    "error": f"Section {name} could not be collected, so the overview stopped there: {result.get('error')}",
                    "data": {"sections": sections}}
        section = {
            "source_tool": tool,
            "ok": result["ok"],
            "exit_code": data["exit_code"],
            "stdout": data["stdout"],
            "stderr": data["stderr"],
            "seconds": round(time.monotonic() - started, 2),
        }
        if data.get("timed_out"):
            section["timed_out"] = True
        if result.get("error"):
            section["error"] = result["error"]
        if "redaction" in result:
            section["redaction_replaced"] = result["redaction"]["replaced"]
        sections[name] = section
    return {"ok": True, "host": host, "collected_at_utc": collected_at,
            "data": {"sections": sections, "redaction_note": REDACTION_NOTE}}
## == END OF TOOLS == ##


def main():
    global ssh_key_passphrase_method

    # 1. Set up command line arguments
    parser = argparse.ArgumentParser(description="Safe SSH MCP Server")
    parser.add_argument("--transport", choices=["stdio", "sse", "streamable-http"], 
                        help="Override transport type (defaults to config file)")
    parser.add_argument("--host", help="Override host binding")
    parser.add_argument("--port", type=int, help="Override port")
    args = parser.parse_args()
    logger.debug("Parsed start arguments")
    # 2. Load config file
    cfg = load_config()
    logger.debug("Loaded config")
    ssh_key_passphrase_method = cfg.get(
        "ssh_key_passphrase_method", SSH_KEY_PASSPHRASE_METHOD_ENV_VAR
    ).strip().upper()
    if ssh_key_passphrase_method not in SSH_KEY_PASSPHRASE_METHODS:
        parser.error(
            "Invalid ssh_key_passphrase_method. "
            f"Choose one of: {', '.join(sorted(SSH_KEY_PASSPHRASE_METHODS))}."
        )
    # 3. CLI arguments take priority over config file
    transport_type = args.transport or cfg.get("transport", "stdio")
    host = args.host or cfg.get("host", "127.0.0.1")
    port = args.port or int(cfg.get("port", 4747))

    # 4. Boot the server
    if transport_type in ("sse", "streamable-http"):
        # SSE Mode: Print safely to stderr, then start the web server
        print(f"Starting MCP server [{transport_type}] on http://{host}:{port}", file=sys.stderr)
        mcp.run(transport=transport_type, host=host, port=port)
    else:
        # STDIO Mode: Run silently for Cline/Desktop clients
        mcp.run(transport="stdio")

if __name__ == "__main__":
    main()
