#!/usr/bin/env python3
from __future__ import annotations

import socket
import configparser
import uvicorn
import os
from datetime import datetime, timezone
from typing import Optional, Dict, Any, ContextManager
from contextlib import contextmanager
import threading
import time

import paramiko
#from mcp.server.fastmcp import FastMCP
from fastmcp import FastMCP

# Initialize MCP Server
mcp = FastMCP("SRE Collector")


def load_config():
    config = configparser.ConfigParser()
    # Default values
    settings = {
        "transport": "streamable-http",
        "host": "127.0.0.1",
        "port": "8000"
    }
    config_file_name = "mcp_config.ini"
    if os.path.exists(config_file_name):
        config.read(config_file_name)
        if "server" in config:
            settings.update(dict(config.items("server")))     
    return settings

# ---- SSH helpers ----
SSH_POOL: Dict[str, Dict[str, Any]] = {}
pool_lock = threading.Lock()
IDLE_TIMEOUT_SECONDS = 300

def _cleanup_idle_connections():
    """Background janitor thread to close stale SSH connections."""
    while True:
        time.sleep(60) # Wake up and check every 60 seconds
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
                print(f"[SSH Pool Janitor] Closed idle connection: {key}")

janitor_thread = threading.Thread(target=_cleanup_idle_connections, daemon=True)
janitor_thread.start()


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
        client.connect(
            hostname=host,
            port=port,
            username=user,
            password=password,
            key_filename=key_path,
            timeout=timeout,
            banner_timeout=timeout,
            auth_timeout=timeout,
            look_for_keys=True,
            allow_agent=True,
        )
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
    pool_key = f"{user}@{host}:{port}"
    
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
            
            # If dead, clean it up before creating a new one
            client.close()
            del SSH_POOL[pool_key]

        # 2. Create a new connection
        client = paramiko.SSHClient()
        client.load_system_host_keys()
        client.set_missing_host_key_policy(
            paramiko.AutoAddPolicy() if accept_new_hostkey else paramiko.RejectPolicy()
        )

        client.connect(
            hostname=host,
            port=port,
            username=user,
            password=password,
            key_filename=key_path,
            timeout=timeout,
            banner_timeout=timeout,
            auth_timeout=timeout,
            look_for_keys=True,
            allow_agent=True,
        )
        
        # 3. Save to pool WITH the current timestamp
        SSH_POOL[pool_key] = {
            "client": client,
            "last_used": time.time()
        }
        return client

def _run_cmd(client: paramiko.SSHClient, cmd: str, timeout: int = 20) -> Dict[str, Any]:
    stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)
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
    timeout: int = 20,
    accept_new_hostkey: bool = False,
    success_exit_codes: tuple = (0,)
) -> Dict[str, Any]:
    """Helper to run an SSH command and capture generalized return payload/errors."""
    collected_at = datetime.now(timezone.utc).isoformat()
    try:
        #with ssh_session(
        #) as client
        client = get_ssh_client(
            host, user, port, password, key_path, timeout, accept_new_hostkey
        )
        result = _run_cmd(client, cmd_str, timeout=timeout)
        return {
            "ok": result["exit_code"] in success_exit_codes,
            "host": host,
            "collected_at_utc": collected_at,
            "data": result,
        }
    except paramiko.AuthenticationException:
        return {"ok": False, "error": "Authentication failed."}
    except Exception as e:
        return {"ok": False, "error": f"Error: {str(e)}"}

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
def get_disk_usage(
    host: str,
    user: str,
    path: str = "/",
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: int = 20,
    accept_new_hostkey: bool = False,
) -> Dict[str, Any]:
    """
    Collects disk usage for a specific path from a remote Linux host via SSH.
    Returns the top 20 largest files/folders in the specified directory.
    """
    cmd = f"du -sh {path}/* 2>/dev/null | sort -rh | head -n 20"
    result = run_ssh_command(
        host, user, cmd, port, password, key_path, timeout, accept_new_hostkey, 
        success_exit_codes=(0, 1) # du may return 1 on partial permission denied
    )
    if result["ok"]:
        result["path"] = path
    return result

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
    cmd = f"systemctl status {daemon}"
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

## == END OF TOOLS == ##

def main():
    cfg = load_config()
    transport_type = cfg.get("transport", "sse")
    host = cfg["host"]
    port = int(cfg["port"])
    if transport_type in ("sse", "streamable-http"):
        print(f"Starting MCP server [{transport_type}] on http://{host}:{port}")
        mcp.run(transport=transport_type, host=host, port=port)
    else:
        # Fallback to standard I/O for CLI/Desktop clients
        mcp.run(transport="stdio")

if __name__ == "__main__":
    main()
