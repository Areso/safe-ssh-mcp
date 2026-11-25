# Changelog

All notable changes to **safe-ssh-mcp** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> **Pre-1.0 note:** While the version is `0.x`, the tool surface (tool names and
> parameters) is still considered unstable and may change between minor releases.
## Unreleased
### Added
- `get_lspci`: the PCI devices of the host (`lspci -nnk`): class, `[vendor:device]` IDs and
  the kernel driver in use. Where pciutils is missing (Alpine, minimal images) one line per
  device from `/sys/bus/pci/devices`: class, IDs, subsystem IDs and driver, without names.
- `get_lsusb`: the USB devices of the host (`lsusb`, then `lsusb -t` for the tree, speeds and
  interface drivers). Where usbutils is missing (Alpine, minimal images) one line per device
  from `/sys/bus/usb/devices`: bus, device, ID, the names the device reports, speed and
  interface drivers. Serial numbers are not read.
- `get_socket_summary(top=20)`: TCP connections as counts, small however many sockets the host
  has: `ss -s`, sockets by state, connections by state x direction x port x process and the
  peers of ESTAB connections (top `top` rows each). Counted on the host from `ss -tanp`, or
  `netstat -tanp` where ss is missing (Alpine). Process names through `sudo -n` / `doas -n`,
  else as the login user with a note.
- `get_tcp_connections(state, tcp_port, lines=200)`: the raw `ss -tanp` lines (or `netstat -tanp`
  on Alpine) of one TCP state and / or one local-or-peer port, filtered on the host and capped
  at `lines` with a `# showing the first N of M` line: drilling into what `get_socket_summary`
  counted.
- `scripts/socket_load/`: makes TCP load from one disposable VM against another (held,
  leaked and churned connections, SYN-SENT to a blackhole) and checks that
  `get_socket_summary` shows each state on one counted line and stays small, and that
  `get_tcp_connections` lists and caps the sockets behind them.

### Changed
- `get_lsblk`: where lsblk (util-linux) is missing (Alpine), the same columns are read from
  `/sys/block`, with mount points from `/proc/mounts` and `/proc/swaps`, instead of failing
  with `lsblk: not found`.
- `get_host_overview`: new section `socket_summary` (`get_socket_summary`, top 20), after
  `listening_sockets`.

## 0.3.2 - 2026-11-24
### Added
- `get_process_info`: one process by `pid`, `name` (its COMM, matched exactly) or both (then
  only if that PID still has that name): `ps`, `/proc/<pid>/status`, `cgroup`, open files
  against `limits`, `oom_score`, `io`. The command line is redacted; the environment is not
  read. Runs through `sudo -n` / `doas -n`, else as the login user with a note.

### Changed
- paramiko and bash wrappers are now enforcing timeouts between 1 and 360 seconds
- added Python3.15 support to CI matrix. The whole product tested on it successfully
- once again, redact procedures reworked plus now covers kubectl and crictl

## 0.3.1 - 2026-11-23
### Added
- `get_systemd_unit_definition`: a unit's definition as systemd reads it (`systemctl cat`):
  the unit file and its drop-ins, with `ExecStart=`, `WorkingDirectory=`, `Restart=`,
  `StandardOutput=` / `StandardError=` (where output goes when it is not in the journal)
  and `EnvironmentFile=` (its path only; the file is not read). Secrets are redacted.
- `scripts/redaction_test/`: plants fake secrets on disposable Debian/Ubuntu and Alpine VMs
  and checks what every tool shows.

### Changed
- Secrets are now redacted by `get_systemd_status`, `get_ps_aux_top_cpu_consumers`,
  `get_ps_aux_top_mem_consumers`, `get_top`, `get_docker_logs`, `get_docker_inspect`,
  `get_service_logs_from_journalctl` and `get_journal_errors` (process command lines, log
  lines), `get_fstab` and `get_mount_problems` (cifs `password=`, `pass=`, `password2=`,
  `user=name%password` and `credentials=` in mount options, `,,` inside a password
  included; the options after them stay visible, see
  [decision_records/redact_mount_options.md](decision_records/redact_mount_options.md)),
  and by the matching `get_host_overview` sections (`redaction_replaced` per section,
  `redaction_note` in `data`).
- Redaction also catches names ending in `_KEY`, `_PWD` and `_PAT` (`STRIPE_KEY`,
  `MYSQL_PWD`, `GITHUB_PAT`; not `PRIMARY_KEY`, `PUBLIC_KEY`, `SORT_KEY` and other non-secret
  keys), Stripe (`sk_live_`), GitHub (`ghp_`), Slack (`xoxb-`) and AWS (`AKIA`) tokens
  anywhere (the prefix is kept), long options such as `--db-password x`, and URLs without
  a user (`redis://:password@host`).

### Fixed
- Redaction took a `;` right after a secret as part of it, so `API_KEY=x; ./run` became
  `API_KEY=<redacted> ./run` and `Password=x;Database=app` hid the database name. An
  unquoted value now ends at `;`.

## 0.3.0 - 2026-11-23
### Added
- `get_host_overview`: a broad first look at a host in one tool call, in 16 sections:
  hostname, OS release, kernel, libc, uptime, CPU, memory, pressure, disk space, inodes,
  mount problems, failed units, top CPU and memory processes, listening sockets and
  journal errors. Each section is exactly the result of an existing tool (named in
  `source_tool`) with that tool's defaults, run over the pooled SSH connection. Facts
  only: no thresholds, no findings. A section that does not apply (no systemd on Alpine)
  fails on its own and the others still run. `timeout`, when given, replaces every
  section's default limit. Output is not shortened (10-25 KB of JSON on the test VMs).
  See [decision_records/get_host_overview.md](decision_records/get_host_overview.md).
- `get_cron_jobs`: every cron job of the host: `/etc/crontab`, `/etc/anacrontab`,
  `/etc/cron.d/*`, the crontab of every user (Debian `/var/spool/cron/crontabs`, RHEL
  `/var/spool/cron`, Alpine `/etc/crontabs`; a directory reached through a symlink is
  read once) and the script names in the run-parts directories (`/etc/cron.daily`, ...,
  `/etc/periodic/*`). Comments and blank lines are left out, at most 200 lines per
  file. Runs through `sudo -n` / `doas -n` when the login user is not root and falls back
  to what the login user can read, with a `# not run as root` first line. See
  [decision_records/as_root.md](decision_records/as_root.md).
- `get_fstab`: `/etc/fstab` as written, comments included.
- `get_mount_problems`: checks every `/etc/fstab` entry against what is mounted now and
  prints one line per problem, then a summary (`no problems found (N fstab entries
  checked)` on a healthy host): `NOT MOUNTED`, `READ-ONLY` (configured read-write but
  mounted read-only, usually after I/O errors), `SWAP NOT ACTIVE` and `SWAP NOT FOUND`.
  Entries are matched by mount point, so `UUID=` and `LABEL=` sources need no
  resolving; `noauto` entries are skipped. Then `findmnt --verify` says whether each
  entry would still mount on the next boot; it runs through `sudo -n` / `doas -n` when
  the login user is not root and falls back to the login user, with a
  `# not run as root` line, if that is refused. Where findmnt has no `--verify`
  (Alpine, util-linux < 2.29) that part says it was not checked. Problems are part of
  the answer: the call exits 0 and `ok` is true. See
  [decision_records/as_root.md](decision_records/as_root.md).
- `get_iostat`: disk I/O and CPU usage now (`iostat -x -m -y <interval> <samples>`,
  3 reports 1 second apart by default): r/s, w/s, MB/s, r_await, w_await, aqu-sz and
  %util per device; loop and ram devices are left out.
- `get_mpstat`: CPU usage per core (`mpstat -P ALL <interval> <samples>`): the all-CPU
  row of each sample, then an Average row per CPU, including %steal.
- Both need sysstat. Where it is missing (Alpine; BusyBox iostat has no await or
  %util), the output starts with a `# sysstat is not installed` line and the same
  columns are computed from `/proc/stat` and `/proc/diskstats`, so they work on every
  host. `samples` (1-30) and `interval` (1-10 s) are validated, and a sampling that
  would not fit in `timeout` is refused before connecting.
- `get_cpu_info`: the CPUs of the host (`lscpu`): model, CPU, socket, core and thread
  counts, caches, NUMA nodes, hypervisor, vulnerability mitigations, and a last line
  with the current frequency from `/proc/cpuinfo` (min, average and max over all CPUs;
  lscpu 2.38+ no longer prints it). The `Flags:` line is left out unless
  `include_flags=True`. Where lscpu is not installed (Alpine), the output starts with
  `# lscpu is not installed: summary of /proc/cpuinfo` and lists each distinct model line
  of `/proc/cpuinfo` once.
- `get_journalctl_disk_usage`: how much disk space the systemd journal takes
  (`journalctl --disk-usage`). Runs through `sudo -n` / `doas -n` when the login user is
  not root, so every journal is counted, and falls back to the login user, with a
  `# not run as root` first line, if that is refused. Says `journalctl is not installed
  on this host` on hosts without systemd. See
  [decision_records/as_root.md](decision_records/as_root.md).
- Redaction of secrets in free-text output: `redact_secrets` / `redact_secrets_in_result`
  replace values that look like passwords, tokens, keys and credentials in URLs with
  `<redacted>` and add a `redaction` field (`replaced` count and a note on its limits) to
  the result. Pattern-based, so not complete. Used by `get_crontab_tasks` and
  `get_cron_jobs`. See [decision_records/redact_secrets.md](decision_records/redact_secrets.md).

### Changed
- `get_crontab_tasks` (and the new `get_cron_jobs`) start with a line saying whether a
  cron daemon is running (`cron`, `crond`, `fcron` or `dcron`, found in `/proc/<pid>/comm`):
  `# cron daemon: running: cron (pid 612)`, `# cron daemon: NOT RUNNING ...: scheduled
  jobs are not executed`, or `cannot tell` for a non-root user on a `/proc` mounted with
  `hidepid`. Shared helper `cron_daemon_check_cmd`.
- `get_crontab_tasks` redacts values that look like secrets (see Redaction above) and
  its result has a `redaction` field.
- On hosts with GNU timeout, commands run under `timeout -k 2`: a command that ignores
  TERM is killed 2 s later instead of running on. See
  [decision_records/remote_timeout.md](decision_records/remote_timeout.md).
- A result can carry `output_never_ended: true` (see Fixed).
- Internal: `LIBC_VERSION_CMD`, the command of `get_libc_version` as a shared constant
  (the command is unchanged).

### Fixed
- Timeouts on BusyBox hosts (Alpine): BusyBox `timeout` stops only the process it
  started, so the rest of a pipeline (`du | sort`) or a background job lived on. It kept
  the SSH output open: the call hung until `timeout_s` + 5 s, returned
  `Network error: Could not connect` with the output lost, and the processes kept running
  on the host. Commands now run in their own session (`setsid`) with a watchdog that stops
  the whole process group (TERM, then KILL 2 s later) and exits 124 like GNU timeout.
  Hosts with GNU timeout keep using it. Checked on Debian 13, Ubuntu 24.04, Fedora 44,
  CentOS Stream 10 and Alpine 3.24. See
  [decision_records/remote_timeout.md](decision_records/remote_timeout.md).
- Output that is still open after `timeout_s` + 5 s is no longer reported as a network
  error: the result has `timed_out: true`, `output_never_ended: true`, the output that
  arrived until then, and an error saying that processes may still run on the host.
- `get_crontab_tasks` returned `ok: false` for a user without a crontab (`crontab -l`
  exits 1). It now returns `# no crontab for the login user (<user>)` with exit code 0;
  an empty crontab says so too. Other failures (permission denied, not allowed to use
  crontab) still fail, with their message. Not done with `success_exit_codes=(0, 1)`,
  which would have hidden those.

### Removed
- `get_memory_pressure`, deprecated since 0.2.0: use `get_pressure`, which returns
  memory pressure together with CPU and I/O pressure.

## 0.2.3 - 2026-11-17
### Added
- `get_process_files`: for every running process, its executable and the shared libraries
  it has loaded (`/proc/<pid>/maps`), followed by the package that owns each of those
  files (dpkg, rpm or apk). Answers "which services really use this library" and "which
  processes still run code an upgrade has replaced". The `/proc` part runs through
  `sudo -n` / `doas -n` when the login user is not root and falls back to the login
  user's own processes, with a `# not run as root` first line, if that is refused. See
  [decision_records/as_root.md](decision_records/as_root.md).

## 0.2.2 - 2026-11-17
### Changed
- `get_installed_packages` on rpm hosts (RHEL, CentOS, Fedora, SUSE) prints tab-separated
  package, epoch, version, release, architecture and source RPM, as the dpkg and apk
  branches already do, instead of plain `rpm -qa` (`name-version-release.arch`). The
  header line is now `# rpm, tab-separated: package epoch version release architecture
  source_rpm`. A package without an epoch gets `0`. Imported GPG keys (`gpg-pubkey`)
  are no longer listed. **Breaking** for anything that parsed the old rpm listing.
- `get_top` takes two samples 1 second apart and returns the second one
  (`top -b -n 2 -d 1 -c -w 512`), so CPU usage is the current one and not the average
  since boot. Lines are up to 512 columns wide instead of 80, and the output is cut to
  the first 30 lines (the summary and the top CPU consumers). The call takes about
  1 second longer. The BusyBox fallback is cut to 30 lines too, and a failure of
  BusyBox top is no longer hidden. `busybox_fallback` got an
  optional `output_filter` for this.

## 0.2.1 - 2026-11-14
### Added
- Shared validator `is_valid_systemd_unit_name` / `systemd_unit_name_error`.

### Changed
- The log file moved out of the working directory. The default is now a per-user
  path: `$XDG_STATE_HOME/safe-ssh-mcp/` or `~/.local/state/safe-ssh-mcp/` on Linux,
  `~/Library/Logs/safe-ssh-mcp/` on macOS, `%LOCALAPPDATA%\safe-ssh-mcp\Logs\` on
  Windows. Set `SAFE_SSH_MCP_LOG_FILE=safe-ssh-mcp.log` to get the old behaviour.
- The log is rotated at 5 MB with 3 old files kept, and the default level is `INFO`
  instead of `DEBUG` (`SAFE_SSH_MCP_LOG_LEVEL=DEBUG` brings it back).
- If the log file cannot be created or opened, the server starts without logging and
  says why on stderr, instead of failing at import.

### Fixed
- Security: `get_systemd_status` no longer accepts a unit name that starts with `-`
  (it was read as a systemctl option; `-Hroot@otherhost` made systemctl connect to
  another host) and passes the name after `--`. A trailing newline is rejected too.
  The error now says what exactly is wrong with the name. `-.mount` and `-.slice`
  can no longer be asked for.
- Security: `get_list_of_files_with_filter` passes the filter to grep with `-e`. A
  filter starting with `-` was read as grep options; `-rne.` made grep print the
  contents of every file under the SSH user's home directory.

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
