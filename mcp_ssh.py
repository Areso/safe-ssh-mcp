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

# Runs the command (passed as $0) in bash when the host has it, and in sh otherwise:
# Alpine and other BusyBox systems ship no bash, so tool commands must also work in sh.
SHELL_LAUNCHER = 'exec "$(command -v bash || echo sh)" -c "$0"'

# How a command killed by the remote `timeout` reports back: GNU timeout exits with 124;
# BusyBox timeout (Alpine) lets the command die from the signal, which paramiko reports as -1.
TIMEOUT_EXIT_CODES = (124, -1)

def is_probable_timeout(exit_code: int, elapsed_s: float, timeout_s: int) -> bool:
    """Checks whether the command was most likely killed by the remote `timeout` wrapper:
    it ended with one of the timeout exit codes AND ran for at least the timeout."""
    return exit_code in TIMEOUT_EXIT_CODES and elapsed_s >= timeout_s

def _run_cmd(client: paramiko.SSHClient, cmd: str, timeout_s: int = 20) -> Dict[str, Any]:
    channel_timeout_s = 5 
    timeout_cmd = f"timeout {timeout_s}s sh -c {shlex.quote(SHELL_LAUNCHER)} {shlex.quote(cmd)}"
    started = time.monotonic()
    stdin, stdout, stderr = client.exec_command(timeout_cmd, timeout=timeout_s+channel_timeout_s)
    # Read the output BEFORE waiting for the exit status: once the unread output fills the
    # SSH window (about 2 MB) the remote command blocks, and waiting for its exit status
    # first would hang until the timeout and return cut-off output.
    out = stdout.read().decode(errors="replace").strip()
    err = stderr.read().decode(errors="replace").strip()
    result = {
        "command": cmd,
        "exit_code": stdout.channel.recv_exit_status(),
        "stdout": out,
        "stderr": err,
    }
    if is_probable_timeout(result["exit_code"], time.monotonic() - started, timeout_s):
        result["timed_out"] = True
    return result

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
        payload = {
            "ok": result["exit_code"] in success_exit_codes,
            "host": host,
            "collected_at_utc": collected_at,
            "data": result,
        }
        if result.get("timed_out"):
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

def busybox_fallback(cmd: str, program: str, fallback_cmd: str) -> str:
    """Runs cmd; if it fails AND program is the BusyBox one (Alpine), runs fallback_cmd instead.
    BusyBox programs lack many options of their procps / util-linux namesakes.
    A failure on a non-BusyBox host is passed through unchanged: same output on stderr,
    same exit code. cmd must be a single simple command (no pipes).
    """
    return (
        f"out=$({cmd} 2>&1); rc=$?; "
        """if [ "$rc" -eq 0 ]; then printf '%s\\n' "$out"; """
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
    timeout: int = 30,
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
    Lists installed packages with versions on a remote Linux host via SSH, using the first
    available package manager. The FIRST output line starts with '#' and names the package
    manager and the columns; the rest is one package per line:
    dpkg (Debian/Ubuntu), tab-separated: package, version, architecture, status ('ii' installed,
      'hi' installed and held), source_package, source_version. Security advisories for
      Debian/Ubuntu are keyed by SOURCE package (openssh, not openssh-server).
      Removed packages whose config files are left behind (state 'rc') are not listed.
    rpm (RHEL/Fedora/SUSE): name-version-release.arch, as printed by rpm -qa.
    apk (Alpine), tab-separated: package, version, architecture, origin. Security advisories for
      Alpine are keyed by ORIGIN (openssl, not libcrypto3); it has the same version as the package.
    """
    cmd = (
        # pipefail keeps dpkg-query's exit code, which awk would otherwise mask
        "set -o pipefail; if command -v dpkg-query >/dev/null 2>&1; then "
        f"echo {shlex.quote(DPKG_HEADER)}; {DPKG_LIST_INSTALLED}; "
        "elif command -v rpm >/dev/null 2>&1; then echo '# rpm: name-version-release.arch'; rpm -qa; "
        f"elif [ -r {APK_DB_PATH} ]; then echo {shlex.quote(APK_HEADER)}; {APK_DB_TO_TSV} {APK_DB_PATH}; "
        "elif command -v apk >/dev/null 2>&1; then echo '# apk: name-version'; apk info -v; "
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
    cmd = "dmesg"
    if since is not None:
        safe_since = normalize_since(since)
        if safe_since is None:
            return {"ok": False, "error": SINCE_ERROR}
        cmd += f" --since {shlex.quote(safe_since)}"
    return run_ssh_command(host, user, as_root(cmd), port, password, key_path, timeout, accept_new_hostkey)

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
    timeout: int = 20,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Collects the hostname of a remote Linux host via SSH, as the host itself reports it.
    Output: "hostname: <name>" (the kernel hostname, uname -n), then "fqdn: <name>"
    (hostname -f) when the host can resolve its fully qualified name; that line is
    absent otherwise.
    """
    return run_ssh_command(host, user, HOSTNAME_CMD, port, password, key_path, timeout, accept_new_hostkey)

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
    The last line, "package: <name> <version>", is the distro package version
    (e.g. 2.39-0ubuntu8.9, 2.34-289.el9, 1.2.6-r3) that security data is keyed by;
    it is taken from dpkg, rpm or apk and is absent on other distros.
    """
    # musl's ldd prints its version to stderr and exits 1, hence 2>&1 and head
    cmd = (
        "if ls /lib/ld-musl-* >/dev/null 2>&1; then ls /lib/ld-musl-*; ldd --version 2>&1 | head -n 2; "
        f"{LIBC_PACKAGE_MUSL_CMD}; "
        "else ldd --version 2>&1 | head -n 1; "
        f"{LIBC_PACKAGE_GLIBC_CMD}; fi"
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
    timeout: int = 20,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Lists top 10 cpu consumers, CPU desc (ps aux --sort=-%cpu).
    On BusyBox hosts (Alpine), where ps cannot sort, the output comes from `top -b -n 1`
    instead: its first line starts with '# BusyBox', the columns differ, and %CPU is the
    usage at this moment, not the average over the process lifetime that ps reports.
    """
    cmd = PS_TOP_CPU_CMD
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
    Lists top 10 mem consumers, MEM desc (ps aux --sort=-%mem).
    On BusyBox hosts (Alpine), where ps cannot sort and has no %MEM, the output is
    `ps -o pid,user,rss,vsz,args` sorted by RSS instead: its first line starts with
    '# BusyBox' and sizes are in KB unless they carry an m or g suffix.
    """
    cmd = PS_TOP_MEM_CMD
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
    DEPRECATED: use get_pressure, which returns CPU, I/O and memory pressure in one call.
    Returns memory pressure if supported
    """
    cmd = "cat /proc/pressure/memory 2>/dev/null || echo 'PSI not supported'"
    return run_ssh_command(host, user, cmd, port, password, key_path, timeout, accept_new_hostkey)

@mcp.tool()
def get_mounts(
    host: str,
    user: str,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = 20,
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
def get_pressure(
    host: str,
    user: str,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = 20,
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
    cmd = (
        'for r in cpu io memory; do echo "== $r =="; '
        "cat /proc/pressure/$r 2>/dev/null || echo 'PSI not supported'; done"
    )
    return run_ssh_command(host, user, cmd, port, password, key_path, timeout, accept_new_hostkey)

@mcp.tool()
def get_vmstat(
    host: str,
    user: str,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = 20,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Samples system activity for 4 seconds with vmstat (5 reports, 1 second apart): run queue and
    blocked processes (r, b), memory, swap-in/out (si, so), block I/O (bi, bo), interrupts and
    context switches (in, cs) and the CPU split (us, sy, id, wa, st).
    USE THIS TOOL to see what the host is doing right now: swapping, I/O wait, CPU saturation.
    The FIRST report line is the average since boot - judge the current state by the other four.
    """
    cmd = "vmstat 1 5"
    return run_ssh_command(host, user, cmd, port, password, key_path, timeout, accept_new_hostkey)

BUSYBOX_TOP_HEADER = "# BusyBox: top -b -n 1"

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
    Collects top's snapshot from a remote Linux host via SSH (top -b -n 1 -c).
    On BusyBox hosts (Alpine), where top has no -c, the output is plain `top -b -n 1`:
    its first line starts with '# BusyBox' and the columns differ.
    """
    # top -b -n 1
    # top -b -n 1 -c
    # top -b -d 1 -n 1
    # top -b -n 1 -u youruser
    cmd = busybox_fallback("top -b -n 1 -c", "top", f"echo {shlex.quote(BUSYBOX_TOP_HEADER)}; top -b -n 1")
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
    timeout: int = 20,
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
    timeout: int = 20,
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
    return run_ssh_command(host, user, cmd, port, password, key_path, timeout, accept_new_hostkey)

@mcp.tool()
def get_docker_stats(
    host: str,
    user: str,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = 20,
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
    timeout: int = 20,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Inspects a SPECIFIC docker container, given by name or ID, on a remote Linux host via SSH.
    Returns a curated subset of docker inspect: image, entrypoint/cmd, state (status, exit code,
    OOMKilled, start/finish time, health check log), restart count and policy, memory/CPU limits,
    networks, ports, mounts and log driver. Environment variables are NOT returned.
    When the login user cannot reach the docker daemon (not root, not in the docker group),
    the command is run through passwordless sudo or doas (sudo -n / doas -n).
    """
    if not is_valid_container_ref(container):
        return {"ok": False, "error": CONTAINER_ERROR}

    cmd = docker_cmd(
        f"inspect --type container --format {shlex.quote(DOCKER_INSPECT_FORMAT)} "
        f"{shlex.quote(container)}"
    )
    return run_ssh_command(host, user, cmd, port, password, key_path, timeout, accept_new_hostkey)

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
    timeout: int = 20,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Gets the last `lines` log lines of a SPECIFIC kubernetes pod (kubectl logs) by running
    kubectl on a remote Linux host via SSH. kubectl must be configured for the SSH user there.
    container selects a container in a multi-container pod.
    previous=True returns logs of the previous, crashed instance - use it for CrashLoopBackOff.
    Optional since limits them to a time window: '30 min ago', '2 hours ago', '30m', '1h30m'
    or an absolute UTC time 'YYYY-MM-DDTHH:MM:SSZ'.
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
    return run_ssh_command(host, user, cmd, port, password, key_path, timeout, accept_new_hostkey)

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
    timeout: int = 20,
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
    """
    safe_type = normalize_k8s_resource_type(resource_type)
    if safe_type is None:
        return {"ok": False, "error": K8S_RESOURCE_TYPE_ERROR}
    if not is_valid_dns_subdomain(name):
        return {"ok": False, "error": K8S_NAME_ERROR}
    if not is_valid_dns_label(namespace):
        return {"ok": False, "error": K8S_NAMESPACE_ERROR}

    cmd = f"kubectl describe {safe_type} {shlex.quote(name)} --namespace={shlex.quote(namespace)}"
    return run_ssh_command(host, user, cmd, port, password, key_path, timeout, accept_new_hostkey)

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
    timeout: int = 20,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Gets the most recent `lines` kubernetes events (kubectl get events), oldest first, below the
    column header, by running
    kubectl on a remote Linux host via SSH. kubectl must be configured for the SSH user there.
    USE THIS TOOL FIRST when you don't know what is wrong in a cluster.
    Events of ALL namespaces are returned unless namespace is given.
    warnings_only=True keeps only events of type Warning (FailedScheduling, BackOff, Unhealthy...).
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
    return run_ssh_command(host, user, cmd, port, password, key_path, timeout, accept_new_hostkey)

# ---- Kubernetes: crictl (node level) ----

@mcp.tool()
def get_crictl_ps(
    host: str,
    user: str,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = 20,
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
    timeout: int = 20,
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
    timeout: int = 20,
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
    timeout: int = 20,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Gets the last `lines` log lines (stdout and stderr merged) of a SPECIFIC CRI container on a
    kubernetes node from a remote Linux host via SSH. Works when the API server is down.
    Use get_crictl_ps first to find the container ID. Usually requires root.
    Optional since limits them to a time window: '30 min ago', '2 hours ago', '30m', '1h30m'
    or an absolute UTC time 'YYYY-MM-DDTHH:MM:SSZ'.
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
    return run_ssh_command(host, user, cmd, port, password, key_path, timeout, accept_new_hostkey)

REDACTED = "<redacted>"

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
    timeout: int = 20,
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
    timeout: int = 20,
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
    timeout: int = 20,
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

@mcp.tool()
def get_ip_addr(
    host: str,
    user: str,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = 20,
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
    timeout: int = 20,
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
    timeout: int = 20,
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
    timeout: int = 20,
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
    timeout: int = 20,
    accept_new_hostkey: bool = False,
    since: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Gets recent journald logs for a specific systemd service.
    Optional since limits them to a time window: '30 min ago', '2 hours ago', 'today',
    'yesterday' or 'YYYY-MM-DD HH:MM:SS' (the last `lines` entries within it are returned).
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
    return run_ssh_command(host, user, cmd, port, password, key_path, timeout, accept_new_hostkey)

@mcp.tool()
def get_journal_errors(
    host: str,
    user: str,
    lines: int = 200,
    current_boot_only: bool = False,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = 20,
    accept_new_hostkey: bool = False,
    since: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Gets recent journald entries of priority warning and above (warning, err, crit, alert, emerg)
    from ALL units and the kernel. USE THIS TOOL FIRST when you don't know which service is at fault.
    With current_boot_only=True only entries since the last boot are returned.
    Optional since limits them to a time window: '30 min ago', '2 hours ago', 'today',
    'yesterday' or 'YYYY-MM-DD HH:MM:SS' (the last `lines` entries within it are returned).
    """
    if not is_valid_lines(lines):
        return {"ok": False, "error": LINES_ERROR}
    if not isinstance(current_boot_only, bool):
        return {"ok": False, "error": "Invalid value of current_boot_only, should be Boolean"}

    cmd = f"journalctl -p warning -n {lines} --no-pager"
    if current_boot_only:
        cmd += " -b"
    if since is not None:
        safe_since = normalize_since(since)
        if safe_since is None:
            return {"ok": False, "error": SINCE_ERROR}
        cmd += f" --since {shlex.quote(safe_since)}"
    return run_ssh_command(host, user, cmd, port, password, key_path, timeout, accept_new_hostkey)

BUSYBOX_LAST_HEADER = "# BusyBox: last (short times without the year)"
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
    timeout: int = 20,
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
    timeout: int = 20,
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
    timeout: int = 20,
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
