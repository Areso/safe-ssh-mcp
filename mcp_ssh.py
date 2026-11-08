#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import socket
import configparser
import json
import os
from datetime import datetime, timezone
from typing import Optional, Dict, Any, ContextManager, List
from contextlib import contextmanager
import signal
import threading
import time
import argparse
import sys
import re
import shlex
import logging

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

def setup_logger(
    path: str = "safe-ssh-mcp.log",
    level: int = logging.DEBUG,
) -> logging.Logger:
    """Configure a JSON file logger. Path/level are configurable via env vars.

    By default this uses a dependency-free stdlib logger. Set
    SAFE_SSH_MCP_DEV_LOGGER=1 (with the `dev` extra installed) to opt into the
    richer git-aware `json-dev-logger` instead."""
    dev_logger = _setup_dev_logger()
    if dev_logger is not None:
        dev_logger.propagate = False
        return dev_logger

    path = os.environ.get("SAFE_SSH_MCP_LOG_FILE", path)
    env_level = os.environ.get("SAFE_SSH_MCP_LOG_LEVEL")
    if env_level:
        level = getattr(logging, env_level.upper(), level)

    logger_c = logging.getLogger("safe-ssh-mcp")
    if not logger_c.handlers:
        file_handler = logging.FileHandler(path, mode="a")
        file_handler.setFormatter(JSONFormatter())
        logger_c.addHandler(file_handler)
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
    timeout: int = 10,
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
    timeout: int = 10,
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

def _run_cmd(client: paramiko.SSHClient, cmd: str, timeout_s: int = 20) -> Dict[str, Any]:
    channel_timeout_s = 5 
    timeout_cmd = f"timeout {timeout_s}s bash -c {shlex.quote(cmd)}"
    stdin, stdout, stderr = client.exec_command(timeout_cmd, timeout=timeout_s+channel_timeout_s)
    return {
        "command": cmd,
        "exit_code": stdout.channel.recv_exit_status(),
        "stdout": stdout.read().decode(errors="replace").strip(),
        "stderr": stderr.read().decode(errors="replace").strip(),
    }

# ---- MCP Tool Boilerplate Helper ----

def run_ssh_command(
    host: str,
    user: str,
    cmd_str: str,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout_s: int = 20,
    accept_new_hostkey: bool = False,
    success_exit_codes: tuple = (0,)
) -> Dict[str, Any]:
    """Helper to run an SSH command and capture generalized return payload/errors."""
    collected_at = datetime.now(timezone.utc).isoformat()
    
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
        return {
            "ok": result["exit_code"] in success_exit_codes,
            "host": host,
            "collected_at_utc": collected_at,
            "data": result,
        }
        
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

## == START OF TOOLS == ##

@mcp.tool()
def get_disk_free(
    host: str,
    user: str,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = 10,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Collects disk usage (df -h) from a remote Linux host via SSH.
    """
    return run_ssh_command(host, user, "df -h", port, password, key_path, timeout, accept_new_hostkey)

@mcp.tool()
def get_inode_usage(
    host: str,
    user: str,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = 10,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Collects inode usage (df -i) from a remote Linux host via SSH.
    """
    return run_ssh_command(host, user, "df -i", port, password, key_path, timeout, accept_new_hostkey)

@mcp.tool()
def get_disk_usage(
    host: str,
    user: str,
    abs_path: str = "/",
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = 20,
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
    timeout: int = 20,
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
    timeout: int = 20,
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

    cmd = f"ls {quoted_path} -lah | grep {quoted_filter} "
    result = run_ssh_command(
        host, user, cmd, port, password, key_path, timeout, accept_new_hostkey,
        success_exit_codes=(0, 1) # du may return 1 on partial permission denied
    )
    if result["ok"]:
        result["path"] = abs_path
    return result

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
    timeout: int = 30,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Finds dependency lockfiles (composer.lock, package-lock.json, requirements*.txt)
    under the given absolute app paths on a remote Linux host via SSH.
    Skips node_modules, vendor, .git, venv and .venv directories.
    Lists the files found (ls -l); with include_contents=True also prints each file,
    capped at the first 100 KB per file and 20 files.
    """
    FORBIDDEN_CHARS = r'[|&;<>()$`{}]'
    MAX_PATHS = 10
    MAX_FILES_WITH_CONTENTS = 20
    MAX_BYTES_PER_FILE = 100_000

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
        r"\( -name node_modules -o -name vendor -o -name .git -o -name venv -o -name .venv \) -prune -o "
        r"-type f \( -name composer.lock -o -name package-lock.json -o -name 'requirements*.txt' \)"
    )
    if include_contents:
        cmd = (
            f"{find_cmd} -print 2>/dev/null | head -n {MAX_FILES_WITH_CONTENTS} | "
            f'while IFS= read -r f; do echo "===== $f ====="; head -c {MAX_BYTES_PER_FILE} "$f"; echo; done'
        )
    else:
        # busybox find has no -printf, so ls -l for size and mtime
        cmd = f"{find_cmd} -exec ls -l {{}} + 2>/dev/null"
    result = run_ssh_command(
        host, user, cmd, port, password, key_path, timeout, accept_new_hostkey,
        success_exit_codes=(0, 1) # find returns 1 on partial permission denied
    )
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
    timeout: int = 20,
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

@mcp.tool()
def get_installed_packages(
    host: str,
    user: str,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = 20,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Lists installed packages with versions on a remote Linux host via SSH.
    Uses the first available package manager: dpkg-query -W (Debian/Ubuntu),
    rpm -qa (RHEL/Fedora/SUSE) or apk info -v (Alpine).
    """
    cmd = (
        "if command -v dpkg-query >/dev/null 2>&1; then dpkg-query -W; "
        "elif command -v rpm >/dev/null 2>&1; then rpm -qa; "
        "elif command -v apk >/dev/null 2>&1; then apk info -v; "
        "else echo 'No supported package manager found (dpkg, rpm, apk)' >&2; exit 127; fi"
    )
    return run_ssh_command(host, user, cmd, port, password, key_path, timeout, accept_new_hostkey)

@mcp.tool()
def get_dmesg(
    host: str,
    user: str,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = 20,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Collects dmesg log from a remote Linux host via SSH
    """
    return run_ssh_command(host, user, "dmesg", port, password, key_path, timeout, accept_new_hostkey)

@mcp.tool()
def get_uptime(
    host: str,
    user: str,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = 20,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Collects uptime from a remote Linux host via SSH
    """
    return run_ssh_command(host, user, "uptime", port, password, key_path, timeout, accept_new_hostkey)

@mcp.tool()
def get_current_datetime(
    host: str,
    user: str,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = 20,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Collects current datetime from a remote Linux host via SSH
    """
    return run_ssh_command(host, user, "date", port, password, key_path, timeout, accept_new_hostkey)

@mcp.tool()
def get_distroname_version(
    host: str,
    user: str,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = 20,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Collects distr details from os-release from a remote Linux host via SSH
    """
    return run_ssh_command(host, user, "cat /etc/os-release", port, password, key_path, timeout, accept_new_hostkey)

@mcp.tool()
def get_kernel_version(
    host: str,
    user: str,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = 20,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Collects kernel name, release, build version and architecture (uname -srvm) from a remote Linux host via SSH
    """
    return run_ssh_command(host, user, "uname -srvm", port, password, key_path, timeout, accept_new_hostkey)

@mcp.tool()
def get_libc_version(
    host: str,
    user: str,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = 20,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Collects C library implementation and version (glibc or musl) from a remote Linux host via SSH.
    Uses ldd --version; musl is detected by the presence of /lib/ld-musl-* loader.
    """
    # musl's ldd prints its version to stderr and exits 1, hence 2>&1 and head
    cmd = (
        "if ls /lib/ld-musl-* >/dev/null 2>&1; then ls /lib/ld-musl-*; ldd --version 2>&1 | head -n 2; "
        "else ldd --version 2>&1 | head -n 1; fi"
    )
    return run_ssh_command(host, user, cmd, port, password, key_path, timeout, accept_new_hostkey)

@mcp.tool()
def get_sshd_effective_config(
    host: str,
    user: str,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = 20,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Collects the effective sshd configuration (sshd -T) from a remote Linux host via SSH.
    Shows the final values after defaults, includes and Match blocks are applied.
    Usually requires root, since sshd -T reads the host keys.
    """
    # sshd lives in /usr/sbin, which is often not in PATH for non-root users
    cmd = 'SSHD=$(command -v sshd || echo /usr/sbin/sshd); "$SSHD" -T'
    return run_ssh_command(host, user, cmd, port, password, key_path, timeout, accept_new_hostkey)

@mcp.tool()
def get_php_info(
    host: str,
    user: str,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = 20,
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
    timeout: int = 20,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Lists all systemd units. USE THIS TOOL to check for running, stopped, or FAILED daemon/service/unit.
    """
    cmd = "systemctl list-units --all --no-pager"
    return run_ssh_command(host, user, cmd, port, password, key_path, timeout, accept_new_hostkey)

@mcp.tool()
def get_systemd_list_failed(
    host: str,
    user: str,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = 20,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Lists failed systemd units. USE THIS TOOL to check for FAILED daemons/services/units.
    """
    cmd = "systemctl list-units --state=failed --no-pager"
    return run_ssh_command(host, user, cmd, port, password, key_path, timeout, accept_new_hostkey)


@mcp.tool()
def get_systemd_list_timers(
    host: str,
    user: str,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = 20,
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
    timeout: int = 20,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Gets the detailed status, logs, and error messages for a SPECIFIC systemd daemon/service/unit.
    """
    VALID_DAEMON_PATTERN = re.compile(r"^[a-zA-Z0-9.\-_@:]+$")
    if not VALID_DAEMON_PATTERN.match(daemon):
        return {"ok": False, 
                "error": f"Invalid daemon name: '{daemon}'. Only ASCII alphanumeric characters, '.', '-', '_', '@', and ':' are allowed."}
    safe_daemon = shlex.quote(daemon)
    cmd = f"systemctl status {safe_daemon}"
    return run_ssh_command(host, user, cmd, port, password, key_path, timeout, accept_new_hostkey)

@mcp.tool()
def get_ps_aux_top_cpu_consumers(
    host: str,
    user: str,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = 20,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Lists top 10 cpu consumers, CPU desc
    """
    cmd = "ps aux --sort=-%cpu | head -n 10"
    return run_ssh_command(host, user, cmd, port, password, key_path, timeout, accept_new_hostkey)

@mcp.tool()
def get_ps_aux_top_mem_consumers(
    host: str,
    user: str,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = 20,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Lists top 10 mem consumers, MEM desc
    """
    cmd = "ps aux --sort=-%mem | head -n 10"
    return run_ssh_command(host, user, cmd, port, password, key_path, timeout, accept_new_hostkey)

@mcp.tool()
def get_free_memory(
    host: str,
    user: str,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = 20,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Returns free memory, swap (total/free), page cache, HugePages and so on
    """
    cmd = "free -h && echo && cat /proc/meminfo"
    return run_ssh_command(host, user, cmd, port, password, key_path, timeout, accept_new_hostkey)

@mcp.tool()
def get_memory_pressure(
    host: str,
    user: str,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = 20,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Returns memory pressure if supported
    """
    cmd = "cat /proc/pressure/memory 2>/dev/null || echo 'PSI not supported'"
    return run_ssh_command(host, user, cmd, port, password, key_path, timeout, accept_new_hostkey)

@mcp.tool()
def get_top(
    host: str,
    user: str,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = 20,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Collects top's snapshot from a remote Linux host via SSH
    """
    # top -b -n 1
    # top -b -n 1 -c
    # top -b -d 1 -n 1
    # top -b -n 1 -u youruser
    cmd = "top -b -n 1 -c"
    return run_ssh_command(host, user, cmd, port, password, key_path, timeout, accept_new_hostkey)

@mcp.tool()
def get_lsblk(
    host: str,
    user: str,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = 20,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Collects lsblk output from a remote Linux host via SSH
    """
    cmd = "lsblk"
    return run_ssh_command(host, user, cmd, port, password, key_path, timeout, accept_new_hostkey)

@mcp.tool()
def get_docker_ps_all(
    host: str,
    user: str,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = 20,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Collects docker ps --all output from a remote Linux host via SSH
    """
    cmd = "docker ps --all"
    return run_ssh_command(host, user, cmd, port, password, key_path, timeout, accept_new_hostkey)

@mcp.tool()
def get_docker_images(
    host: str,
    user: str,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = 20,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Collects docker images --digests output (repository, tag, digest, image ID, age, size) from a remote Linux host via SSH
    """
    # No -a: it only adds untagged intermediate build layers, which are noise for diagnostics
    cmd = "docker images --digests"
    return run_ssh_command(host, user, cmd, port, password, key_path, timeout, accept_new_hostkey)

@mcp.tool()
def get_crontab_tasks(
    host: str,
    user: str,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = 20,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Collects crontab -l (crontab list) output from a remote Linux host via SSH
    """
    cmd = "crontab -l"
    return run_ssh_command(host, user, cmd, port, password, key_path, timeout, accept_new_hostkey)

@mcp.tool()
def get_listening_sockets(
    host: str,
    user: str,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = 20,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Collects ss -tulpn output (open ports and sockets) from a remote Linux host via SSH
    """
    cmd = "ss -tulpn"
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
    timeout: int = 20,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Gets recent journald logs for a specific systemd service.
    """
    VALID_SERVICE_PATTERN = re.compile(r"^[a-zA-Z0-9.\-_@:]+$")
    if not VALID_SERVICE_PATTERN.match(service):
        return {"ok": False, 
                "error": f"Invalid service name: '{service}'. Only ASCII alphanumeric characters, '.', '-', '_', '@', and ':' are allowed."}

    # Explicitly exclude booleans (Best practice for duck typing)
    if not isinstance(lines, int) or isinstance(lines, bool) or not (1 <= lines <= 1000):
        return {"ok": False, "error": "Invalid value of lines, should be Integer from 1 to 1000"}
    
    lines = max(1, min(lines, 1000))
    safe_service = shlex.quote(service)
    cmd = f"journalctl -xeu {safe_service} -n {lines} --no-pager"
    return run_ssh_command(host, user, cmd, port, password, key_path, timeout, accept_new_hostkey)
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
