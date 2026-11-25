# as_root: a closed list of tools escalates through sudo -n / doas -n

Date: 2026-11-11
Status: accepted

## Decision

These tools run their command as root when the login user is not root:

- `get_dmesg`, `get_sshd_effective_config`, `get_failed_logins` — always;
- the docker tools (`get_docker_ps_all`, `get_docker_images`, `get_docker_logs`,
  `get_docker_stats`, `get_docker_inspect`) — only when the login user cannot reach the
  docker daemon (added 2026-11-12, see "Docker tools" below);
- `get_listening_sockets` — always, but falls back to the login user if escalation is
  refused (added 2026-11-12, see "Tools that fall back" below).
- `get_process_files` — the same, for its `/proc` part only (added 2026-11-17, see
  "Tools that fall back" below).
- `get_journalctl_disk_usage` — the same (added 2026-11-22, see "Tools that fall back"
  below).
- `get_mount_problems` — the same, for its `findmnt --verify` part only (added
  2026-11-22, see "Tools that fall back" below).
- `get_cron_jobs` — the same (added 2026-11-22, see "Tools that fall back" below).
- `get_socket_summary`, `get_tcp_connections` — the same, for their `ss -tanp` /
  `netstat -tanp` part only (added 2026-11-25, see "Tools that fall back" below).

The helper `as_root` picks, on the remote host:

1. nothing, if the login user is already root;
2. `sudo -n`, if `sudo` exists;
3. `doas -n`, if `doas` exists (Alpine);
4. nothing, if neither exists, so the command fails with its usual permission error.

It is automatic: there is no parameter to turn it on.

## Why

These three commands read data only root can read (the kernel log under
`kernel.dmesg_restrict=1`, the sshd host keys, `btmp`). Without escalation the only
way to use them is to log in over SSH as root, which gives the whole connection root.
With it, the login user can be unprivileged and root is granted for a short list of
read-only commands.

It is automatic rather than opt-in because a `use_sudo` parameter adds no protection:
the commands are fixed, and an agent would simply retry with it switched on.

The helper detects the tool, not the distribution: `doas` exists outside Alpine and
`sudo` can be installed on it.

## Docker tools

The docker daemon refuses any user who is not root or in the `docker` group, and that
group is root-equivalent on the host. Escalating lets the login user stay outside it.

`docker_cmd` first runs `docker version`, which asks the daemon and so proves access:

- it works (root, docker group, rootless docker): docker is called directly, no escalation;
- it fails: docker is called through `sudo -n` / `doas -n`.

The direct call comes first on purpose. A docker-group user with no sudo rule would
otherwise be broken by `sudo: a password is required`.

What the tools run, for the host admin writing the sudoers / doas rule:

```
docker ps --all
docker images --digests
docker stats --no-stream
docker logs --tail N [--since T] CONTAINER
docker inspect --type container --format TEMPLATE CONTAINER
```

Writing the rule is the admin's job. Two things they should know:

- Allowing plain `docker` gives full root. List the subcommands.
- sudoers wildcards are loose: `docker inspect *` also permits a full inspect, which
  prints the environment. The tool never asks for it (see
  [get_docker_inspect.md](get_docker_inspect.md)), but the rule would allow it to
  anyone who can log in as that user.

Known gap: when the daemon is down and the user has no sudo rule, the tool reports
`sudo: a password is required` instead of the daemon error.

## Tools that fall back

`as_root` itself has no fallback: if sudo or doas refuses, the tool fails with that
error. That is right for commands that are useless without root.

`get_listening_sockets` is different. `ss -tulpn` (or `netstat -tulnp` where ss is not
installed) works for any user; root only adds the process names of other users'
sockets. So it uses `as_root_or_plain`: the command is tried through `sudo -n` /
`doas -n`, and if that is refused or neither exists, it is run as the login user after
this line:

```
# not run as root (no sudo -n / doas -n access): process names are shown only for the login user's own sockets
```

The sudo/doas refusal itself is not shown. Commands for the admin's rule:

```
ss -tulpn
netstat -tulnp
```

`get_socket_summary` and `get_tcp_connections` (added 2026-11-25) do the same with the same
line, for `ss -tanp` / `netstat -tanp` only: `ss -s`, the counting and the filtering run as the
login user. Commands for the
admin's rule:

```
ss -tanp
netstat -tanp
```

`get_process_files` (added 2026-11-17) does the same. Any user can read `/proc/<pid>/exe`
and `/proc/<pid>/maps` of their own processes; root can read everyone's. Only that
loop is escalated, as `sh -c '<fixed script>'`. The second half of the tool, asking the
package database who owns the files, runs as the login user: it needs no root. The
fallback line is:

```
# not run as root (no sudo -n / doas -n access): only the login user's own processes are listed
```

For the admin's rule this is the weak spot of the list: the command is `sh -c` with a
long script as its argument, which a sudoers rule can only match in full (copy it from
`PROCESS_FILES_PROC_SCRIPT` in `mcp_ssh.py`) and which changes if the script changes.
Allowing plain `sh` would allow everything. A host that already gives the login user
unrestricted `sudo -n` / `doas -n` (the usual cloud image setup) needs nothing.

The alternative, a fixed list of commands such as `cat /proc/*/maps`, was rejected:
the shell expands the glob before sudo sees it, so the rule would have to allow `cat`
on any path, which is worse.

`get_process_info` (added 2026-11-24) does the same for one process: any user can read
`status`, `cgroup`, `limits` and `oom_score` of every process, but `/proc/<pid>/fd` and
`/proc/<pid>/io` only of their own. The script is `sh -c '<PROCESS_INFO_SCRIPT>' sh PID NAME`,
so a sudoers rule has to match the script and allow any two arguments. "No such process" and
"the PID has another name" exit 3 and are returned as they are, not re-run as the login user.
The fallback line is:

```
# not run as root (no sudo -n / doas -n access): open files and I/O of other users' processes are not readable
```

`get_journalctl_disk_usage` (added 2026-11-22) does the same. `journalctl --disk-usage`
works for any user, but it only adds up the journal files that user can read: usually
just its own user journal, unless it is in the `systemd-journal` or `adm` group. The
fallback line is:

```
# not run as root (no sudo -n / doas -n access): only the journal files the login user can read are counted
```

Command for the admin's rule:

```
journalctl --disk-usage
```

`get_mount_problems` (added 2026-11-22) falls back too, but cannot use
`as_root_or_plain`. That helper treats any non-zero exit as a refused escalation, and
`findmnt --verify` exits 1 whenever it finds a problem in fstab: a real finding made as
root would be thrown away, rerun as the login user and labelled "not run as root". So the
tool decides from the output instead: the escalation was refused only when it starts with
`sudo:` or `doas:`. Without root, findmnt still checks sources, mount points and types as
written, but cannot read the on-disk filesystem type, and warns about it for every
entry. The fallback line is:

```
# not run as root (no sudo -n / doas -n access): on-disk filesystem types were not checked, so 'cannot detect on-disk filesystem type' warnings can be ignored
```

Command for the admin's rule:

```
findmnt --verify --tab-file /etc/fstab
```

The first part of the tool (fstab against `/proc/mounts` and `/proc/swaps`) reads only
world-readable files and runs as the login user.

`get_cron_jobs` (added 2026-11-22) falls back through `as_root_or_plain`. User
crontabs are readable by root only (`/var/spool/cron/crontabs` is `drwx-wx--T`, so
others cannot even list it; Alpine's `/etc/crontabs/<user>` files are `0600`), while
`/etc/crontab` and `/etc/cron.d` are usually world-readable. Without root the tool shows
what the login user can read, after:

```
# not run as root (no sudo -n / doas -n access): only the cron files the login user can read are shown; user crontabs usually need root
```

Like `get_process_files`, it escalates one fixed `sh -c '<script>'` (copy it from
`CRON_JOBS_SCRIPT` in `mcp_ssh.py` for a sudoers rule), because the files to read are
only known after listing directories that need root. The cron daemon check before it
reads `/proc/<pid>/comm` and runs as the login user.

**Reminder: root output can hold other users' secrets.** Escalating to read files that
belong to other users means their secrets come back too: crontabs carry passwords and
tokens inline. `get_cron_jobs` therefore redacts values that look like secrets before
returning anything; that redaction is pattern-based and not complete. Any new tool that
reads other users' or system files as root should do the same. See
[redact_secrets.md](redact_secrets.md).

## Limits

- Closed list. Only the tools above escalate, each with a fixed command built by the
  tool. There is no general "run with sudo" switch.
- `-n` never waits for a password. The host admin decides what is allowed through the
  sudoers or doas rules; without a passwordless rule the tool fails at once with the
  sudo/doas error (`get_listening_sockets` runs unprivileged instead).
- If `sudo` exists but is not allowed, `doas` is not tried.

## Consequence

"This server never escalates privileges" is no longer true. It never escalates
anything except these fixed, read-only commands, and only as far as the host's own
rules allow.

## Where

- `AS_ROOT_PREFIX`, `as_root`, `as_root_or_plain`, `DOCKER_PREFIX` and `docker_cmd` in
  `mcp_ssh.py`.
