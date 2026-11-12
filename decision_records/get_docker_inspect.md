# get_docker_inspect: curated fields, no environment; command line is returned

Date: 2026-11-11
Status: accepted

## Decision

`get_docker_inspect` does not return the full `docker inspect` output. It returns a
curated set of fields through a `--format` template that never references the
environment (`.Config.Env`).

## Why

A full `docker inspect` prints the container's environment, which is where secrets
usually live.

## Known gap: command-line arguments

Only the environment is left out. The template returns `Entrypoint` and `Cmd`, so a
secret passed as a command-line argument (`--password=...`, a connection string) is
visible to the agent.

They are returned because the command line is usually what you need to see when
diagnosing a container, and there is no reliable way to tell which argument is a
secret.

## Where

- `DOCKER_INSPECT_FORMAT` in `mcp_ssh.py`.

## Related

- [get_crictl_inspect.md](get_crictl_inspect.md) — the crictl inspect tools solve the
  environment problem by redacting values locally, and have the same gap.
