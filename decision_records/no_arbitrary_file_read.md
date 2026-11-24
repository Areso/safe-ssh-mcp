# No arbitrary file reads: no tool prints a file the caller names

Date: 2026-11-24
Status: accepted

## Decision

No tool takes a path from the caller and returns the contents of the file there. There is
no `cat <file>`, `head`, `tail`, `less`, `grep <pattern> <file>`, `awk`/`sed` over a file,
`strings`, `xxd` or similar on a path the caller chooses, and no generic log-file reader.

- The tools that take a path (`get_disk_usage`, `get_list_of_files`,
  `get_list_of_files_with_filter`, `get_lockfiles`) return metadata only: names, sizes,
  permissions, mtimes. The one exception is `get_lockfiles(include_contents=True)`, below.
- The `grep` in `get_list_of_files_with_filter` filters the output of `ls`, never a file.
  The filter is passed with `-e`, so a filter such as `-r` is a pattern and cannot turn it
  into a recursive read.
- Where a tool does read a file, the path (or file name pattern) is fixed in the code, not
  taken from the caller, and the tool is listed under [Known exceptions](#known-exceptions).

## Why

- Read-only is not the same as non-sensitive. The SSH user is often root, or gets root via
  `sudo -n` / `doas -n`, so a path parameter would reach `/etc/shadow`, private keys,
  `.env` files, application configs with database passwords and shell histories. Whatever
  a tool returns goes to the model provider and into the MCP client's logs.
- Redaction ([redact_secrets.md](redact_secrets.md)) is pattern-based and not a guarantee.
  It works on outputs whose format is known; for an arbitrary file it is not.
- The path checks (absolute path, forbidden characters) stop shell injection, not the
  choice of file: `/etc/shadow` passes them.
- With fixed sources, an operator can read this list and know exactly what can leave the
  host. The server's purpose is diagnosis up to, not including, remediation, without
  exposing data the operator did not choose to expose.

## Known exceptions

Tools that do get their data from files, as of 2026-11-24. `get_host_overview` sections
read what their source tools read.

### 1. Kernel state in /proc and /sys (fixed paths)

Counters and kernel state, no user data. Not redacted.

| Path | Tools |
|---|---|
| `/proc/cpuinfo` | `get_cpu_info` (without lscpu, and the MHz line) |
| `/proc/meminfo` | `get_free_memory` |
| `/proc/pressure/{cpu,io,memory}` | `get_pressure` |
| `/proc/stat`, `/proc/uptime`, `/proc/diskstats`, `ls /sys/block` | `get_iostat`, `get_mpstat` (only without sysstat) |
| `/proc/mounts`, `/proc/swaps` | `get_mounts` (without findmnt), `get_mount_problems`, `get_cron_jobs` / `get_crontab_tasks` (hidepid check) |
| `/proc/sys/kernel/hostname` | `get_hostname` (when `uname -n` fails) |
| `/proc/<pid>/comm` | `get_cron_jobs`, `get_crontab_tasks` (is a cron daemon running), `get_process_files` |
| `/proc/<pid>/maps`, `readlink /proc/<pid>/exe` | `get_process_files`: only the paths of mapped executable files, not memory |

### 2. Fixed system files

| File | Tools | What is printed | Redacted |
|---|---|---|---|
| `/etc/os-release` | `get_distroname_version` | whole file | no |
| `/etc/fstab` | `get_fstab` | whole file | yes, `MOUNT_SECRET_PATTERNS` |
| `/etc/fstab` | `get_mount_problems` | fields 1-4 of entries with problems, `findmnt --verify` output | yes, `MOUNT_SECRET_PATTERNS` |
| `/etc/resolv.conf` | `get_dns_lookup` | whole file | no |
| `/etc/crontab`, `/etc/anacrontab`, `/etc/cron.d/*`, `/var/spool/cron/crontabs/*`, `/var/spool/cron/*`, `/etc/crontabs/*` | `get_cron_jobs` | non-comment lines, at most 200 per file; as root when `sudo -n` / `doas -n` allows. Run-parts directories (`/etc/cron.{hourly,...}`, `/etc/periodic/*`): script names only | yes |
| the login user's crontab (`crontab -l`) | `get_crontab_tasks` | whole crontab | yes |
| `/etc/apache2/mods-enabled/*.load`, `/etc/apache2/httpd.conf`, `/etc/apache2/conf.d/*.conf`, `/etc/httpd/conf/httpd.conf`, `/etc/httpd/conf.modules.d/*.conf` | `get_php_info` | only `LoadModule php..._module` lines | no |
| `/lib/apk/db/installed` (Alpine package DB) | `get_installed_packages`, `get_process_files` | package name, version, arch, origin; file-to-package owners | no |

### 3. Files read by a program, not by the tool

The program reads its own files; the tool returns what the program prints.

| Program | Source | Tools | Limit | Redacted |
|---|---|---|---|---|
| `systemctl cat` | unit file and drop-ins of the named unit | `get_systemd_unit_definition` | one unit | yes, `SYSTEMD_SECRET_PATTERNS` |
| `systemctl status` | unit state and its last journal lines | `get_systemd_status` | one unit | yes |
| `journalctl` | the journal | `get_journal_errors`, `get_service_logs_from_journalctl` | `lines`, `since` | yes |
| `journalctl --disk-usage` | the journal | `get_journalctl_disk_usage` | sizes only | no |
| `sshd -T` | `sshd_config` and its includes, as the effective config | `get_sshd_effective_config` | - | no |
| `last`, `lastb` | `/var/log/wtmp`, `/var/log/btmp` | `get_last_logins`, `get_failed_logins` | 50 entries | no |
| `dmesg` | kernel ring buffer (not a file) | `get_dmesg` | `since` | no |
| `docker logs`, `crictl logs` | container output | `get_docker_logs`, `get_crictl_logs` | `lines`, `since` | yes |
| `kubectl logs` | container output | `get_kubectl_logs` | `lines`, `since` | **no** |
| `docker inspect`, `crictl inspect`, `crictl inspecti` | container / image config | `get_docker_inspect`, `get_crictl_inspect`, `get_crictl_inspect_image` | one object | yes |
| `kubectl describe` | object spec and status | `get_kubectl_describe` | one object | **no** |
| `coredumpctl list` | core dump metadata | `get_coredumps` | `lines` | yes |
| `dpkg-query`, `rpm` | package databases | `get_installed_packages`, `get_libc_version`, `get_process_files` | - | no |
| `findmnt --verify` | `/etc/fstab` | `get_mount_problems` | - | yes |

### 4. Caller-chosen directories, fixed file names: `get_lockfiles(include_contents=True)`

The only tool that prints files under paths the caller gives. It is bounded by the code:

- only files named `composer.lock`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`,
  `requirements*.txt`, `poetry.lock`, `uv.lock`, `Pipfile.lock`, `Gemfile.lock`, `go.sum`,
  `Cargo.lock` (`LOCKFILE_NAMES`);
- regular files only (`find -type f`, which does not follow symlinks), at most 10 start
  paths, `max_depth` 1-10, `node_modules`, `vendor`, `.git`, `venv`, `.venv` skipped;
- the first 20 files, each whole or skipped: at most 5 MB per file, 10 MB in total.

Accepted because dependency versions are what a vulnerability check needs, and lockfiles
are generated files that seldom hold secrets. Since 2026-11-24 the contents are redacted
with a rule set of their own, credentials in URLs and token prefixes only
(`--index-url https://user:<redacted>@host`, `git+https://<redacted>@host`), so that
package names and versions stay intact: see [redact_lockfiles.md](redact_lockfiles.md).

## Open points

Gaps found while writing this record, not fixed by it:

- `get_kubectl_logs` and `get_kubectl_describe` are not redacted, unlike their docker and
  crictl counterparts. `kubectl describe pod` shows literal `env` values of the pod spec.
- `get_failed_logins` (`lastb`) shows the user names of failed logins, and people
  sometimes type a password into the user name prompt.

## Adding a tool that reads a file

1. The path or file name pattern is fixed in the code, never taken from the caller.
2. The output is bounded (lines, bytes or entries).
3. Free text that can hold credentials is redacted ([redact_secrets.md](redact_secrets.md)).
4. The tool is added to [Known exceptions](#known-exceptions).

## Alternatives

| Option | Why not |
|---|---|
| A generic `read_file(path)`, redacted | Any file the SSH user can read, in any format; redaction cannot be trusted on unknown formats |
| `tail` of log files by path | The same problem for `/var/log`, which also holds application logs with request data |
| Files allow-listed by the operator in `mcp_config.ini`, off by default, tail-only, redacted | Not built. If file reading comes back, start from this: the operator, not the model, chooses what is exposed |

## Where

- The tools listed above in `mcp_ssh.py`.
- Path validation: `get_disk_usage`, `get_list_of_files`, `get_list_of_files_with_filter`,
  `get_lockfiles`.
