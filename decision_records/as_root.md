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
