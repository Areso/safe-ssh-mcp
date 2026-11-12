# Safe SSH MCP Server
A secure and scoped SSH MCP server for executing read-only diagnostic commands over SSH.  
In this project, "safe" refers specifically to host safety: the server is designed to prevent modifications to the remote system and reduce the risk of operational harm. It does NOT attempt to guarantee that command output cannot be misused by external agents.

## Badges
[![Snyk Vulnerability Database report](https://snyk.io/advisor/images/snyk-poweredby.svg)](https://security.snyk.io/package/pip/safe-ssh-mcp) - security check  
[![PyPI Downloads](https://static.pepy.tech/personalized-badge/safe-ssh-mcp?period=total&units=ABBREVIATION&left_color=BLACK&right_color=GREEN&left_text=downloads)](https://pepy.tech/projects/safe-ssh-mcp)  

## Overview

The core philosophy behind this MCP server is safety first. Instead of providing an AI agent with an unrestricted bash shell, this server exposes only carefully curated, read-only commands for system diagnostics and monitoring.

## Available Tools (Partial List)
A few examples from each group; `<...>` marks a validated parameter.

**Disk and filesystems**
- get_disk_free : `df -h`
- get_disk_usage : `find <path> -mindepth 1 -maxdepth 1 -exec du -sh -- {} + 2>/dev/null | sort -rh | head -n 20`
- get_mounts : `findmnt` (or `cat /proc/mounts`)

**CPU, memory and processes**
- get_top : `top -b -n 1 -c`
- get_vmstat : `vmstat 1 5`
- get_pressure : `cat /proc/pressure/{cpu,io,memory}`

**Systemd and logs**
- get_systemd_list_failed : `systemctl list-units --state=failed --no-pager`
- get_systemd_status : `systemctl status <daemon>`
- get_journal_errors : `journalctl -p warning -n <lines> --no-pager`
- get_dmesg : `dmesg`

**Network**
- get_listening_sockets : `ss -tulpn`
- get_ip_route : `ip route show` and `ip -6 route show`
- get_dns_lookup : `getent ahosts <name>` or `dig <name> <record_type>`
- check_tcp_connect : `nc -vz -w 3 <target_host> <target_port>`

**Docker**
- get_docker_ps_all : `docker ps --all`
- get_docker_logs : `docker logs --tail <lines> <container>`
- get_docker_stats : `docker stats --no-stream`

**Kubernetes**
- get_kubectl_events : `kubectl get events --sort-by=.lastTimestamp`
- get_kubectl_logs : `kubectl logs --tail=<lines> --namespace=<namespace> <pod>`
- get_crictl_ps : `crictl ps --all`

**System, logins and crashes**
- get_distroname_version : `cat /etc/os-release`
- get_installed_packages : `dpkg-query -W` (with source package), `rpm -qa` or `/lib/apk/db/installed` (with origin)
- get_failed_logins : `lastb -F -n <lines>`
- get_coredumps : `coredumpctl list --no-pager`

Click to open [full list of available tools](tools.md)  

## Example of invocation
`okay, could u check disk usage on /root/ path with help of safe-ssh-mcp server on a remote myserver.mydomain.pro using root and /Users/myUser/.ssh/id_rsa to login?`

## Means of connection
The server supports SSH account-password authentication and private-key
authentication. Configure the private-key passphrase source in
`mcp_config.ini`:

```ini
# ENV_VAR (SSH_KEY_PASSPHRASE) or KEYCHAIN (ssh-agent)
ssh_key_passphrase_method=ENV_VAR
```

1. SSH account password: provide `password` to the MCP tool. Do not use this
   for a private-key passphrase.
2. Unprotected SSH key: use `key_path`. The default `ENV_VAR` setting also
   supports unprotected keys; `SSH_KEY_PASSPHRASE` is not required.
3. Passphrase-protected SSH key from an environment variable: leave
   `ssh_key_passphrase_method=ENV_VAR`, set `SSH_KEY_PASSPHRASE` in the
   environment that starts the MCP server, and provide `key_path`.

   ```bash
   export SSH_KEY_PASSPHRASE='your-key-passphrase'
   safe-ssh-mcp
   ```

4. macOS Keychain / SSH agent: set
   `ssh_key_passphrase_method=KEYCHAIN`, then unlock the key in the same user
   session that starts the MCP server. The server receives SSH signatures from
   `ssh-agent`; it does not read the key passphrase or the `key_path`.

   ```bash
   ssh-add --apple-use-keychain ~/.ssh/id_ed25519

   # Optional: make the loaded identity expire after one hour.
   ssh-add -t 1h ~/.ssh/id_ed25519

   # Remove one identity, or clear every loaded identity.
   ssh-add -d ~/.ssh/id_ed25519
   ssh-add -D
   ```

5. Cursor launched from the macOS Dock: use `KEYCHAIN` (recommended). You can
   run `ssh-add` from any Terminal window; it updates the SSH agent for your
   macOS login session, so Cursor does not need to be started from that
   Terminal.

   ```bash
   ssh-add --apple-use-keychain ~/.ssh/id_ed25519
   ssh-add -l
   ```

   After changing `mcp_config.ini`, restart the MCP server in Cursor (or fully
   quit and reopen Cursor). When invoking a tool in `KEYCHAIN` mode, omit
   `key_path`; the agent selects from its loaded identities.

   If you must use `ENV_VAR`, set it in the macOS launchd session before
   opening Cursor from the Dock, then fully quit and reopen Cursor:

   ```bash
   launchctl setenv SSH_KEY_PASSPHRASE 'your-key-passphrase'
   ```

   This value lasts only for the current login session, and putting a
   passphrase directly in a command may save it in shell history. Prefer
   `KEYCHAIN`.

For `KEYCHAIN`, the MCP server must inherit `SSH_AUTH_SOCK` from that user
session. This is normally automatic for a stdio server started from a desktop
application. `ENV_VAR` stores the passphrase in the server process environment,
so restrict access to the process and avoid putting it in source control.

## [Changelog](CHANGELOG.md)

## Project Contents
1. mcp_ssh.py - the SSH MCP server
2. mcp_config.ini - the server's config
3. check_health_sse.py - check the server's tools and either it's up (sse transport)
4. check_health_stdio.py - check the server's tools and either it's up (stdio transport)

## Compatibility
Tested manually on Python3.11 running on MacOS against remote Ubuntu server  
Autotested with Python 3.11 3.12 3.13 3.14  

## The MCP Registry
mcp-name: io.github.Areso/safe-ssh-mcp

## The License
This project is licensed under the GNU AGPLv3 License.

### Why AGPL?
This server acts as core infrastructure and contains no business logic. By using the AGPL license, we ensure that any security improvements, bug fixes, or new diagnostic tools added to the server are shared back with the open-source community.

### Note for Client Developers 
Because MCP clients communicate with this server via standard Inter-Process Communication (IPC) or network protocols (like HTTP/SSE), the AGPL license does not "infect" or restrict the client applications connecting to it.   
You can safely connect proprietary, closed-source, or permissively licensed (e.g., MIT, Apache 2.0) AI agents to this server without violating the license terms.
