# Safe SSH MCP Server
A secure and scoped Model Context Protocol (MCP) server for executing safe, read-only diagnostic commands over SSH.

## Badges
[![Snyk Vulnerability Database report](https://snyk.io/advisor/images/snyk-poweredby.svg)](https://security.snyk.io/package/pip/safe-ssh-mcp) - security check  
[![PyPI Downloads](https://static.pepy.tech/personalized-badge/safe-ssh-mcp?period=total&units=ABBREVIATION&left_color=BLACK&right_color=GREEN&left_text=downloads)](https://pepy.tech/projects/safe-ssh-mcp)  

## Overview

The core philosophy behind this MCP server is safety first. Instead of providing an AI agent with an unrestricted bash shell, this server exposes only carefully curated, read-only commands for system diagnostics and monitoring.

## Available Tools (Partial List)
1. get_disk_free : `df -h`
2. get_disk_usage : `du -sh {path}/* 2>/dev/null | sort -rh | head -n 20`
3. get_dmesg : `dmesg`
4. get_uptime : `uptime`
5. get_current_datetime : `date`
6. get_distroname_version : `cat /etc/os-release`
7. get_systemd_list_all : `systemctl list-units --all --no-pager`
8. get_systemd_list_faild : `systemctl list-units --state=failed --no-pager`
9. get_systemd_list_timers : `systemctl list-timers --no-pager`
10. get_systemd_status : `systemctl status {daemon}`
11. get_top : `top -b -n 1 -c`

## Example of invocation
`okay, could u check disk usage on /root/ path with help of safe-ssh-mcp server on a remote myserver.mydomain.pro using root and /Users/myUser/.ssh/id_rsa to login?`

## Project Contents
1. mcp_ssh.py - the SSH MCP server
2. mcp_config.ini - the server's config:
    * ip address to listen (default 127.0.0 - available only from the localhost)
    * port (4747 for default)
    * transport (sse)
3. check_tools.py - check the server's tools with schemas, and list them
4. check_health.py - check the server's tools and either it's up

## The MCP Registry
mcp-name: io.github.Areso/safe-ssh-mcp

## The License
This project is licensed under the GNU AGPLv3 License.

### Why AGPL?
This server acts as core infrastructure and contains no proprietary business logic. By using the AGPL license, we ensure that any security improvements, bug fixes, or new diagnostic tools added to the server are shared back with the open-source community.

### Note for Client Developers 
Because MCP clients communicate with this server via standard Inter-Process Communication (IPC) or network protocols (like HTTP/SSE), the AGPL license does not "infect" or restrict the client applications connecting to it.   
You can safely connect proprietary, closed-source, or permissively licensed (e.g., MIT, Apache 2.0) AI agents to this server without violating the license terms.
