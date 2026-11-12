# get_crictl_inspect / get_crictl_inspect_image: environment values are redacted

Date: 2026-11-10
Status: accepted

## Decision

The two crictl inspect tools redact environment variable values. The server parses
the JSON locally and replaces each value with `<redacted>`, keeping the variable
names. If the output isn't valid JSON it is dropped instead of being returned
unredacted.

## Why

`crictl inspect` and `crictl inspecti` print the container's and the image's
environment, which is where secrets usually live. The variable names are kept
because knowing that a variable is set is useful for diagnostics on its own.

## Where

- `redact_env_values` and `_redact_env_in_json_stdout` in `mcp_ssh.py`.
- Every `env` / `envs` key is redacted, at any depth and in any letter case.

## Known gap: command-line arguments

Redaction covers environment variables only. A secret passed as a command-line
argument (`--password=...`, a connection string) is still returned: `crictl inspect`
prints the container's command and arguments (`info.config.command` / `args`,
`info.runtimeSpec.process.args`), and `crictl inspecti` prints the image's
entrypoint and cmd.

They are not redacted because the command line is usually what you need to see when
diagnosing a container, and there is no reliable way to tell which argument is a
secret.

## Related

- `get_docker_inspect` solves the same problem differently: it returns a curated
  set of fields through a `--format` template that never references the environment
  (see [get_docker_inspect.md](get_docker_inspect.md)).
