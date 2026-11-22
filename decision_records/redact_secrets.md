# redact_secrets: values that look like secrets are redacted in free-text output

Date: 2026-11-22
Status: accepted

## Decision

Tools whose output is free text that often holds credentials pass their result through
`redact_secrets_in_result` before returning it. It replaces every value that looks like
a secret with `<redacted>` and adds a `redaction` field to the result:

```json
"redaction": {"replaced": 2, "note": "Values that look like secrets ... may still be shown, ..."}
```

The field is there even when nothing was replaced, so the model always knows the output
was filtered and that the filter is not a guarantee.

Used by: `get_crontab_tasks`, `get_cron_jobs`.

## Why

Read-only is not the same as non-sensitive. Crontabs are a typical case: jobs are
written as one-line shell commands, and credentials end up inline:
`mysqldump -pS3cret`, `curl -H "Authorization: Bearer ..."`, `PGPASSWORD=... pg_dump`,
`https://user:token@host`. `get_cron_jobs` reads the crontabs of every user as root, so
without redaction one call would hand all of them to the model and to the MCP client's
logs.

## Trade-off

Three options were considered:

| Option | For | Against |
|---|---|---|
| A. Redact values that match known patterns (chosen) | Catches the common forms; the rest of the line stays readable, so the job can still be debugged | Not complete: a secret in an unusual form is still shown. Can hide a harmless value that looks like a secret |
| B. Return everything, warn in the docs | Simple, nothing is hidden | Every secret in every crontab reaches the model |
| C. Return only the schedule and the program name | Nothing leaks | Too little to debug a failing job: the arguments are usually the point |

A was chosen because it removes most of the risk at little cost to diagnostics. Its
limit is stated wherever it is used: in the docstring of each tool, and in the `note`
of every result. It must never be described as making output safe.

Known false positives: a value after a word like `token` or `password` in log text
(`invalid token: expired` hides `expired`), a port passed as `-pNNNN` to a MySQL
client. Known misses: secrets in positional arguments (`app connect s3cret`), in
variables whose names do not contain a secret-like word (`APP_PASS=`, `PASS=`: a bare
`pass` is not a keyword, as it would also match `BYPASS`, `PASSTHROUGH`; `db_pass` is
the one exception), base64 blobs without a key name, and anything split across lines
except PEM private keys.

## Where it runs

On the MCP server, after the output was read over SSH and before the result is
returned. The secrets do cross the SSH connection into the server process, but they
reach neither the model nor the client. The server does not log command output.

## How to extend

- The patterns are `SECRET_PATTERNS` in `mcp_ssh.py`: one regex each, with a group
  `k` (kept), `v` (replaced) and optionally `s` (kept after). A narrow pattern must come
  before a broad one that would match the same text.
- Every pattern must skip a value that is already `<redacted>`, so that a value matched
  by two patterns is counted once and redacting twice changes nothing.
- Each new pattern gets a positive and a negative case in `tests/test_redact.py`.
- A new tool opts in by returning `redact_secrets_in_result(run_ssh_command(...))` and
  saying so in its docstring.

## Related

- `redact_env_values` (the crictl inspect tools) is structured redaction: it parses JSON
  and blanks every `env` value, which is complete for that one field. Free text has no
  such structure, hence the pattern-based approach here. See
  [get_crictl_inspect.md](get_crictl_inspect.md).
- The crictl and docker inspect tools leave secrets in command-line arguments as a known
  gap ([get_crictl_inspect.md](get_crictl_inspect.md),
  [get_docker_inspect.md](get_docker_inspect.md)); `redact_secrets` is a candidate to
  close it.
- [as_root.md](as_root.md): `get_cron_jobs` reads other users' files as root, which is
  why it redacts.
