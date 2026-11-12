# Changelog

All notable changes to **safe-ssh-mcp** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> **Pre-1.0 note:** While the version is `0.x`, the tool surface (tool names and
> parameters) is still considered unstable and may change between minor releases.

## 0.2.0 - 2026-11-12
### Added
- New tool `get_hostname` — the host's own name (`uname -n`, so it works without the
  `hostname` program) and, when the host can resolve it, its FQDN (`hostname -f`).
- New tool `get_mounts` — mounted filesystems with source, type and mount options
  (`findmnt`; `/proc/mounts` if findmnt is not installed).
- New tool `get_pressure` — pressure stall information for CPU, I/O and memory in
  one call (`/proc/pressure/{cpu,io,memory}`).
- New tool `get_vmstat` — 5 one-second samples of run queue, memory, swap, block
  I/O and CPU activity (`vmstat 1 5`). The first sample is the average since boot.
- New tool `check_tcp_connect` — checks from the remote host whether a TCP connection
  to `target_host:target_port` can be opened (`nc -vz -w 3`), after checking that nc
  is installed. One port per call; no data is sent.
- Shared validator `is_valid_tcp_port`.
- Shared helper `tail_keeping_header`: `get_coredumps` (list) and `get_kubectl_events`
  always return the column header; `lines` counts the rows below it.
- Shared validators `is_valid_lines`, `is_valid_pid` and `is_valid_coredump_command`,
  replacing the checks that were written inline in each tool.
- New tool `get_dns_lookup` — resolves a hostname (or reverse-resolves an IP
  address) on the remote host and prints its `/etc/resolv.conf`. Uses
  `getent ahosts` / `getent hosts` by default; `use_dig=True` switches to `dig`
  (full output, no `+short`) after checking that dig is installed.
  With dig, `record_type` selects one of a closed list of record types (A by
  default, AAAA, CNAME, MX, NS, TXT, SOA, PTR, SRV, CAA) and `server` queries a
  specific DNS server (`dig @server`) instead of the ones in `/etc/resolv.conf`.
- Shared validators `is_valid_hostname`, `is_valid_ip_address` and
  `normalize_dns_record_type`.
- New tool `get_ip_addr` — network interfaces with their state and IPv4/IPv6
  addresses (`ip addr show`).
- New tool `get_ip_route` — IPv4 and IPv6 routing tables (`ip route show` and
  `ip -6 route show`).
- New tool `get_journal_errors` — recent journald entries of priority warning and
  above from all units and the kernel (`journalctl -p warning -n N --no-pager`);
  `current_boot_only=True` limits them to the current boot (`-b`).
- New tool `get_last_logins` — recent successful logins (`last`).
- New tool `get_failed_logins` — recent failed login attempts (`lastb`; usually
  requires root).
- New tool `get_coredumps` — core dumps recorded by systemd-coredump
  (`coredumpctl list` / `coredumpctl info`). The command is a closed list: `debug`
  (interactive gdb) and `dump` (raw process memory) are deliberately not exposed.
- Optional `since` parameter on `get_service_logs_from_journalctl`, `get_journal_errors`,
  `get_dmesg`, `get_last_logins`, `get_failed_logins` and `get_coredumps`, e.g. `30 min ago`,
  `yesterday`, `2026-11-10 14:00`. It is validated by the shared `normalize_since`
  function, which accepts only the time syntax common to systemd and util-linux.
  `dmesg --since` requires util-linux 2.37+ on the remote host.
- New tool `get_docker_logs` — last N log lines of a container, stdout and stderr
  merged (`docker logs --tail N`), with an optional `since`. It is validated by the
  separate `normalize_since_docker` function, which accepts Go durations (`30m`,
  `1h30m`) as well as the relative/absolute forms above and converts them to what
  the docker CLI expects; `today` / `yesterday` are not supported there.
- New tool `get_docker_stats` — one-shot resource usage of running containers
  (`docker stats --no-stream`).
- New tool `get_docker_inspect` — curated subset of `docker inspect` for a container
  (state, health, restart count/policy, limits, networks, ports, mounts).
  Environment variables are deliberately not returned.
- Shared container validators `is_valid_container_name`, `is_valid_container_id`
  and `is_valid_container_ref`.
- Kubernetes, cluster level (kubectl must be configured for the SSH user on the host):
  - `get_kubectl_logs` — last N log lines of a pod (`kubectl logs --tail`), with
    optional `container`, `previous` and `since`.
  - `get_kubectl_describe` — `kubectl describe` of one resource. The resource type
    is a closed list (pod, node, deployment, service, ...); `secret` and `configmap`
    are deliberately not available.
  - `get_kubectl_events` — recent events of all namespaces or one, optionally
    warnings only (`kubectl get events --sort-by=.lastTimestamp`).
- Kubernetes, node level (crictl, usually requires root):
  - `get_crictl_ps` (`crictl ps --all`), `get_crictl_images` (`crictl images`),
    `get_crictl_imagefsinfo` (`crictl imagefsinfo`).
  - `get_crictl_logs` — last N log lines of a CRI container, with an optional `since`.
  - `get_crictl_inspect` and `get_crictl_inspect_image` — `crictl inspect` /
    `crictl inspecti` as JSON. Values of environment variables are replaced by
    `<redacted>` on the MCP server before the result is returned; output that
    cannot be parsed is dropped.
- Shared validators `is_valid_image_name`, `is_valid_image_id`, `is_valid_image_ref`,
  `is_valid_dns_label`, `is_valid_dns_subdomain`, `normalize_k8s_resource_type`,
  `normalize_since_kubernetes` and `is_go_duration`.

### Changed
- `get_listening_sockets` runs through `sudo -n` / `doas -n` when the login user is
  not root, so process names are shown for all sockets. If that is not allowed it runs
  as the login user and says so in a `# not run as root` line.
- `get_libc_version` adds a last line `package: <name> <version>` with the distro
  package version of the C library (`2.39-0ubuntu8.9`, `2.34-289.el9`, `1.2.6-r3`),
  taken from dpkg, rpm or apk. Before, RHEL-family and Alpine hosts showed only the
  upstream version.
- The docker tools (`get_docker_ps_all`, `get_docker_images`, `get_docker_logs`,
  `get_docker_stats`, `get_docker_inspect`) now work for a login user who is neither
  root nor in the `docker` group: when the daemon refuses the user, the command is run
  through passwordless `sudo -n` or `doas -n` (new helper `docker_cmd`). A user who can
  already reach the daemon is not escalated. A host without docker now answers
  `docker is not installed on this host`.
- `get_dmesg`, `get_sshd_effective_config` and `get_failed_logins` now work for a
  non-root login user: their command is run through passwordless `sudo -n` or `doas -n`
  (Alpine) when the host has one. Only these three fixed, read-only commands are
  escalated (new helper `as_root`); see `decision_records/as_root.md`.
- `get_lockfiles` also finds `poetry.lock`, `uv.lock`, `Pipfile.lock`, `yarn.lock`,
  `pnpm-lock.yaml`, `Gemfile.lock`, `go.sum` and `Cargo.lock`.
- `get_installed_packages` output now carries package provenance for security tooling,
  and its first line (starting with `#`) names the package manager and the columns:
  - dpkg: tab-separated package, version, architecture, status, source package and
    source version (Debian/Ubuntu security data is keyed by source package).
  - apk: tab-separated package, version, architecture and origin, read from
    `/lib/apk/db/installed` (`apk info -v` has no origin; it remains the fallback).
  - rpm: unchanged apart from the header line.

### Fixed
- `get_listening_sockets` falls back to `netstat -tulnp` when `ss` is not installed
  (Alpine); the output then starts with `# ss is not installed: netstat -tulnp`. With
  neither installed it says so instead of `ss: not found`.
- `get_top` and `get_last_logins` now work on BusyBox hosts (Alpine), where `top` has no
  `-c` and `last` takes no options: they fall back to `top -b -n 1` and to plain `last`
  cut to `lines` rows (new helper `busybox_fallback`); the fallback output starts with a
  `# BusyBox` line. `get_last_logins` with `since` fails there with a message saying
  BusyBox `last` cannot filter by time.
- `get_last_logins` and `get_failed_logins` now fail with `last is not installed on this
  host` / `lastb is not installed on this host` when the program is missing (Debian 13
  no longer installs them by default). Through sudo, a missing `lastb` used to show up
  as the misleading `sudo: a password is required`.
- A command stopped by the timeout is now reported as such: the result gets
  `data.timed_out: true` and an `error` saying it probably timed out. Before, the only
  sign was exit code 124, or -1 with empty stderr on BusyBox hosts (Alpine).
- `get_ps_aux_top_cpu_consumers` and `get_ps_aux_top_mem_consumers` no longer return
  `ok: True` with empty output on BusyBox hosts (Alpine), where `ps` has no `--sort`.
  They fall back to `top -b -n 1` (CPU) and `ps -o pid,user,rss,vsz,args` sorted by RSS
  (memory); the fallback output starts with a `# BusyBox` line.
- Hosts without bash (Alpine and other BusyBox systems) no longer fail every tool with
  `timeout: can't execute 'bash'`: commands run in bash when the host has it and in
  `sh` otherwise.
- `get_lockfiles` with `include_contents=True` no longer cuts files at 100 KB, which
  left broken JSON. A file is now returned whole or not at all: a file over 5 MB, or
  one that would take the output over 10 MB in total, gets a
  `===== <path> (skipped: ...) =====` line with its size instead. Each returned file's
  header now carries its size: `===== <path> (<size> bytes) =====`.
- Commands printing more than about 2 MB no longer hang until the timeout and come back
  cut off: the output is now read before waiting for the exit status.
- `get_installed_packages` on Debian/Ubuntu no longer lists removed packages whose
  config files are left behind (dpkg state `rc`); only installed packages are returned.

### Deprecated
- `get_memory_pressure` — use `get_pressure` instead. The tool still works and will be
  removed in a later release.

## [0.1.16] - 2026-11-09
### Added
- New tool `get_installed_packages` — lists installed packages with versions using
  the first available package manager: `dpkg-query -W`, `rpm -qa` or `apk info -v`.
- New tool `get_kernel_version` — kernel name, release, build version and
  architecture (`uname -srvm`).
- New tool `get_libc_version` — C library implementation and version
  (`ldd --version`; musl detected via `/lib/ld-musl-*`).
- New tool `get_sshd_effective_config` — effective sshd configuration (`sshd -T`);
  usually requires root.
- New tool `get_php_info` — PHP CLI version and SAPI, installed `php-cgi` /
  `php-fpm` binaries with versions, running php-fpm/php-cgi processes, and
  Apache mod_php status (enabled `LoadModule` directives and `apachectl -M`).
- New tool `get_docker_images` — local images with digests (`docker images --digests`).
- New tool `get_lockfiles` — finds `composer.lock`, `package-lock.json` and
  `requirements*.txt` under given app paths (skipping `node_modules`, `vendor`, `.git`,
  venvs); optionally prints their contents (capped at 20 files, 100 KB each).

## [0.1.15] - 2026-08-19
- added support for SSH keys protected by passphrase
- to use protected keys either set SSH_KEY_PASSPHRASE var in the env
- or change method in mcp_config.ini to KEYCHAIN and unlock the key with KEYCHAIN


## [0.1.14] - 2026-06-04
### Added
- CHANGELOG.md
- tools.md (generated by scripts/generate_tools_md.py)

### Changed
- Moved json-dev-logger to developer dependency
- Instead of json-dev-logger wrote one from scratch
- Fixed print-to-stdio bugs

## [0.1.13] - 2026-06-03

### Added
- New tool `get_is_installed` — checks whether a given binary/command is
  installed and callable on the remote host (`command -v <binary>`), with the
  same forbidden-character validation as the other parameterized tools.
- Structured file logging via the `json-dev-logger` package (`py_logger.setup_logger`);
  validation failures and executed commands are now logged instead of printed.
- Debug log lines in `main()` for argument parsing and config loading.

### Changed
- Replaced ad-hoc `print(...)` diagnostics in the file-listing tools with
  `logger.error(...)` calls.
- **Dependency bumps:**
  - `paramiko` `>=4.0.0,<5` → `>=5.0.0,<6` (major version bump).
  - `fastmcp` `>=3.1.1,<4` → `>=3.2.0,<4`.
  - Added `json-dev-logger>=0.0.15`.

### Known issues
- **Possible behavioral degradation introduced by the dependency bumps**
  (`paramiko` 4.x → 5.x major upgrade, `fastmcp` 3.1.1 → 3.2.x upgrade). This is flagged in the
  release commit message (`"bumped dependencies (possible degradation)"`)  
  Users who need the
  previously verified behavior can pin to `0.1.11`.
  _TODO: confirm the exact symptom/root cause and link a tracking issue._
- Several copied validation log messages in `get_is_installed` and the
  file-listing tools reference the wrong tool name
  (e.g. `"get_list_of_files_with_filter tool: ..."`), which can be misleading
  when reading logs.

## [0.1.12] - 2026-06-02

### Added
- Expanded automated test coverage (`tests/test_tools.py`,
  `tests/test_validation.py`) for the file-listing tools and additional
  validation paths.

### Notes
- Version `0.1.11` was skipped; there is no `v0.1.11` release.

## [0.1.10] - 2026-06-02

### Added
- New tool `get_list_of_files` — directory listing via `ls -lah` for an
  absolute path, with path validation and forbidden-character filtering.
- New tool `get_list_of_files_with_filter` — same listing piped through
  `grep <filter>`, with validation on both the path and the filter.
- Health-check helper scripts `check_health_sse.py` and `check_health_stdio.py`
  to verify the server is up and enumerate its tools over each transport.

## [0.1.9] - 2026-05-18

### Added
- Test suite and CI pipeline (merged via PR #1): pytest fixtures/`conftest.py`,
  input-validation tests, parametrized tests for all tool handlers,
  `run_ssh_command` orchestration tests, SSH-pool/janitor tests, and
  `load_config` tests.
- GitHub Actions CI running pytest with coverage on Python 3.11 / 3.12 / 3.13.
- `dev` optional dependencies and pytest/coverage configuration in
  `pyproject.toml`.

### Changed
- SSH connection-pool handling improved; the pool is now keyed by the full
  connection details provided (close #5).
- Per-command timeouts for SSH execution (close #3).
- Fixed an improper f-string template bug in command construction (close #2).
- Build/packaging tweaks for Poetry compatibility (bounded Python to `<4.0`,
  added `[tool.poetry]` packages config).

### Removed
- `requirements.txt` (dependencies are managed via `pyproject.toml`).
- `poetry.lock` excluded from version control (library consumers resolve from
  the declared ranges).

## [0.1.8] - 2026-03-22

### Added
- New tool `get_docker_ps_all` — `docker ps --all`.

## [0.1.7] - 2026-03-22

### Added
- New tools: `get_inode_usage` (`df -i`), `get_ps_aux_top_cpu_consumers`,
  `get_ps_aux_top_mem_consumers`, `get_free_memory`, `get_memory_pressure`,
  and `get_service_logs_from_journalctl` (journald logs for a specific
  systemd service, with service-name validation and a bounded line count).

## [0.1.6] - 2026-03-22

### Added
- New tools: `get_lsblk`, `get_crontab_tasks`, and `get_listening_sockets`
  (`ss -tulpn`).

### Changed
- Pinned dependency version ranges: `paramiko>=4.0.0,<5`, `fastmcp>=3.1.1,<4`.

## [0.1.5] - 2026-03-19

### Security
- Sanitized the `systemctl status` call: the daemon name is now validated
  against an allowlist pattern and shell-quoted before use.

### Added
- `get_disk_usage` now properly handles and validates the target path
  (absolute-path checks, normalization, forbidden-character filtering).
- README updated with an example invocation.

## [0.1.4] - 2026-03-19

### Added
- Listed on the MCP Registry (`io.github.Areso/safe-ssh-mcp`).

## [0.1.3] - 2026-03-19

### Fixed
- Defaulted transport to `stdio` in an additional code path that was missed
  in `0.1.2`.

## [0.1.2] - 2026-03-19

### Fixed
- Config loading when the server is launched by Cline.

### Changed
- Default transport switched to `stdio` for shipping.

## [0.1.1] - 2026-03-17

### Added
- `cline_mcp_settings.json` example configuration.
- Ability to run with either `stdio` or `sse` transport based on CLI arguments.

### Changed
- Improved error handling in `run_ssh_command`.

### Removed
- `uvicorn` dependency.

## [0.1.0] - 2026-03-16

### Added
- Initial public release: FastMCP-based SSH server exposing read-only
  diagnostic tools (disk, systemd, uptime, OS info, `top`, etc.) over `stdio`
  and `sse` transports.
- Connection pooling with an idle-connection janitor thread and graceful
  shutdown on SIGTERM/SIGINT.
- Building and publishing setup (`pyproject.toml`, PyPI publish workflow).
- Licensed under GNU AGPLv3.
