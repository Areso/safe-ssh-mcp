# redact_secrets: values that look like secrets are redacted in free-text output

Date: 2026-11-22, updated 2026-11-24
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

## Which tools redact, with which function and patterns

As of 2026-11-24: 19 tools redact free text, 2 redact structured JSON, and 4 sections of
`get_host_overview` are redacted as their tools are. Every other tool returns its output
as it is.

The functions:

- `redact_secrets(text, patterns=SECRET_PATTERNS)`: redacts a string with a rule set;
  returns the text and the number of values replaced.
- `redact_secrets_in_result(result, patterns=SECRET_PATTERNS, redactor=None)`: redacts the
  stdout and stderr of a `run_ssh_command` result with `redact_secrets` and `patterns`, or
  with `redactor` when given, and adds the `redaction` field.
- `redact_k8s_describe(text)`: a `redactor` for `kubectl describe`: every literal value in
  `Environment:` blocks, then `SECRET_PATTERNS` on the other lines.
- `_redact_env_in_json_stdout(result)` with `redact_env_values`: parses JSON and replaces
  every `env` / `envs` value, at any depth; output that is not valid JSON is dropped. No
  `redaction` field.

The rule sets (all in `mcp_ssh.py`):

| Rule set | What it is |
|---|---|
| `SECRET_PATTERNS` | the general rules, listed under [Why](#why) below |
| `SYSTEMD_SECRET_PATTERNS` | `Environment="NAME=a b"` (the quotes wrap the whole assignment), then `SECRET_PATTERNS` |
| `MOUNT_SECRET_PATTERNS` | comma-separated mount options (`password=`, `pass=`, `user=name%pw`, `credentials=`), then `SECRET_PATTERNS`; see [redact_mount_options.md](redact_mount_options.md) |
| `LOCKFILE_SECRET_PATTERNS` | credentials in URLs, secret query parameters, token prefixes; INSTEAD of `SECRET_PATTERNS`, which breaks package names (`secretstorage==3.3.3`); see [redact_lockfiles.md](redact_lockfiles.md) |

| Area | Tool | Function | Patterns |
|---|---|---|---|
| cron | `get_crontab_tasks` | `redact_secrets_in_result` | `SECRET_PATTERNS` |
| cron | `get_cron_jobs` | `redact_secrets_in_result` | `SECRET_PATTERNS` |
| systemd | `get_systemd_status` | `redact_secrets_in_result` | `SECRET_PATTERNS` |
| systemd | `get_systemd_unit_definition` | `redact_secrets_in_result` | `SYSTEMD_SECRET_PATTERNS` |
| processes | `get_ps_aux_top_cpu_consumers` | `redact_secrets_in_result` | `SECRET_PATTERNS` |
| processes | `get_ps_aux_top_mem_consumers` | `redact_secrets_in_result` | `SECRET_PATTERNS` |
| processes | `get_top` | `redact_secrets_in_result` | `SECRET_PATTERNS` |
| processes | `get_process_info` | `redact_secrets_in_result` | `SECRET_PATTERNS` (the command line); see [get_process_info.md](get_process_info.md) |
| journal | `get_service_logs_from_journalctl` | `redact_secrets_in_result` | `SECRET_PATTERNS` |
| journal | `get_journal_errors` | `redact_secrets_in_result` | `SECRET_PATTERNS` |
| docker | `get_docker_logs` | `redact_secrets_in_result` | `SECRET_PATTERNS` |
| docker | `get_docker_inspect` | `redact_secrets_in_result` | `SECRET_PATTERNS` |
| kubernetes | `get_kubectl_logs` | `redact_secrets_in_result` | `SECRET_PATTERNS` |
| kubernetes | `get_kubectl_events` | `redact_secrets_in_result` | `SECRET_PATTERNS` |
| kubernetes | `get_kubectl_describe` | `redact_secrets_in_result(redactor=redact_k8s_describe)` | every literal env value, then `SECRET_PATTERNS`; see [get_kubectl_describe_pod.md](get_kubectl_describe_pod.md) |
| kubernetes | `get_crictl_logs` | `redact_secrets_in_result` | `SECRET_PATTERNS` |
| kubernetes | `get_crictl_inspect` | `_redact_env_in_json_stdout` | structured: every `env` value; command-line arguments are not redacted, see [get_crictl_inspect.md](get_crictl_inspect.md) |
| kubernetes | `get_crictl_inspect_image` | `_redact_env_in_json_stdout` | structured: every `env` value; entrypoint and cmd are not redacted |
| mounts | `get_fstab` | `redact_secrets_in_result` | `MOUNT_SECRET_PATTERNS` |
| mounts | `get_mount_problems` | `redact_secrets_in_result` | `MOUNT_SECRET_PATTERNS` |
| lockfiles | `get_lockfiles`, with `include_contents=True` only | `redact_secrets_in_result` | `LOCKFILE_SECRET_PATTERNS` |
| overview | `get_host_overview`: sections `mount_problems`, `top_cpu_processes`, `top_memory_processes`, `journal_errors` | `redact_secrets_in_result`, per section | the section's tool's set, from `HOST_OVERVIEW_REDACTED_TOOLS`: `MOUNT_SECRET_PATTERNS` for `mount_problems`, `SECRET_PATTERNS` for the others; the other sections are not redacted, as their tools are not |
| - | every other tool (`get_mounts`, `get_coredumps`, `get_dns_lookup`, ...) | none | |

`tests/test_redact.py::test_exactly_these_tools_redact` fails when a tool starts or stops
adding a `redaction` field without `REDACTING_TOOLS` being updated (`get_lockfiles`, which
redacts only with a parameter, `get_process_info`, which needs a pid or a name, and the crictl
inspect tools, which add no field, have tests of their own), and `tests/test_overview.py` checks that each redacted overview section
matches its tool's output. Update this table with them.

## Why

Read-only is not the same as non-sensitive. Crontabs are a typical case: jobs are
written as one-line shell commands, and credentials end up inline:
`mysqldump -pS3cret`, `curl -H "Authorization: Bearer ..."`, `PGPASSWORD=... pg_dump`,
`https://user:token@host`. `get_cron_jobs` reads the crontabs of every user as root, so
without redaction one call would hand all of them to the model and to the MCP client's
logs.

The same holds wherever a command line or a log line is shown. On test VMs with planted
secrets (2026-11-23, `scripts/redaction_test/`), before they redacted:
`get_systemd_status` showed the `ExecStart=` arguments and the unit's last log lines; the
ps tools, `get_top` and the overview showed process arguments (`--password=...`); the
journal tools showed what services log; `get_docker_logs` and `get_docker_inspect`
showed the container's output and command line; `get_fstab` and `get_mount_problems`
showed cifs passwords in mount options.

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

What is caught (`SECRET_PATTERNS`, in this order): PEM private keys; `scheme://user:pw@host`
and `scheme://:pw@host`; `Authorization:` headers and `Bearer` tokens; long options with a
secret word, also after a prefix (`--password x`, `--db-password=x`, `--client-secret x`;
not `--password-stdin` / `--password-file`, which take no secret); `mysql -pX`;
`sshpass -p X`; `curl -u user:X`; names ending in `_KEY`, `_PWD` or `_PAT`
(`STRIPE_KEY=`, `MYSQL_PWD=`, `GITHUB_PAT=`); names containing a secret word
(`DB_PASSWORD=`, `password: x`, `"secret": "x"`); and, anywhere, tokens with a known
prefix: `sk_live_` (Stripe), `ghp_` (GitHub), `xoxb-` (Slack), `AKIA` (AWS access key
ID). A token keeps its prefix (`ghp_<redacted>`), so its kind stays visible, and needs a
realistic length after it (`ghp_short` is left alone).

A value is quoted, or runs to the next whitespace, quote or `;` (a shell command separator,
and the field separator of connection strings such as `Password=x;Database=app`), so the
command or field after it stays visible. Mount options end values at a comma instead; see
[redact_mount_options.md](redact_mount_options.md).

`_KEY` names that are not secrets are excluded by name: `PUBLIC_KEY`, `PRIMARY_KEY`,
`FOREIGN_KEY`, `UNIQUE_KEY`, `SORT_KEY`, `PARTITION_KEY`, `ROUTING_KEY`, `CACHE_KEY`,
`LOOKUP_KEY` (`_NOT_SECRET_KEYS`), also with a prefix (`db_primary_key`). A bare `PWD` /
`OLDPWD` is the working directory and needs the underscore to count.

Known false positives: a value after a word like `token` or `password` in log text
(`invalid token: expired` hides `expired`), a port passed as `-pNNNN` to a MySQL
client, a `_KEY` name not in the exclusion list (`HASH_KEY=id`), and `credentials=` with
a file path (see [redact_mount_options.md](redact_mount_options.md)). Known misses:
secrets in positional arguments (`app connect s3cret`), free text without `=` or `:`
(`token s3cret`), a secret piped in (`echo s3cret | docker login --password-stdin`),
variables whose names do not contain a secret word or suffix (`APP_PASS=`, `PASS=`: a
bare `pass` is not a keyword, as it would also match `BYPASS`, `PASSTHROUGH`; `db_pass`
is the one exception), token formats not in the prefix list, base64 blobs without a key
name, and anything split across lines except PEM private keys.

## Where it runs

On the MCP server, after the output was read over SSH and before the result is
returned. The secrets do cross the SSH connection into the server process, but they
reach neither the model nor the client. The server does not log command output.

## How to extend

- The patterns are `SECRET_PATTERNS` in `mcp_ssh.py`: one regex each, with a group
  `k` (kept), `v` (replaced) and optionally `s` (kept after). A narrow pattern must come
  before a broad one that would match the same text; the token-prefix rule comes last,
  so a token that is the value of an assignment is counted once.
- A rule that is only right for one kind of output (it would leak or over-redact
  elsewhere) goes into a rule set of its own, `<rules> + SECRET_PATTERNS`, passed as
  `patterns` by the tools that print that output: `SYSTEMD_SECRET_PATTERNS`,
  `MOUNT_SECRET_PATTERNS`. Words and lists shared by several rules: `_SECRET_WORDS`,
  `_NOT_SECRET_KEYS`, `_TOKEN_PREFIXES`.
- Every pattern must skip a value that is already `<redacted>`, so that a value matched
  by two patterns is counted once and redacting twice changes nothing.
- Each new pattern gets a positive and a negative case in `tests/test_redact.py`.
- A new tool opts in by returning `redact_secrets_in_result(run_ssh_command(...))` (with
  its rule set when it has one), saying so in its docstring, and being added to
  `REDACTING_TOOLS` in `tests/test_redact.py`, which fails until it is (a tool that
  redacts only with a parameter, as `get_lockfiles`, gets a test of its own instead). A tool that is a
  `get_host_overview` section also goes into `HOST_OVERVIEW_REDACTED_TOOLS`, with the
  same rule set.
- Live check: `scripts/redaction_test/` plants marked fake secrets (and non-secret
  controls that must stay visible) on disposable Debian/Ubuntu and Alpine VMs and runs
  every tool; see its README for adding a case.

## Related

- `redact_env_values` (the crictl inspect tools) is structured redaction: it parses JSON
  and blanks every `env` value, which is complete for that one field. Free text has no
  such structure, hence the pattern-based approach here. See
  [get_crictl_inspect.md](get_crictl_inspect.md).
- [redact_mount_options.md](redact_mount_options.md): why mount options have their own
  rules.
- `get_docker_inspect` redacts its command line since 2026-11-23
  ([get_docker_inspect.md](get_docker_inspect.md)). The crictl inspect tools still leave
  secrets in command-line arguments as a known gap
  ([get_crictl_inspect.md](get_crictl_inspect.md)); `redact_secrets` is a candidate to
  close it there too.
- [as_root.md](as_root.md): `get_cron_jobs` reads other users' files as root, which is
  why it redacts.
- [no_arbitrary_file_read.md](no_arbitrary_file_read.md): no tool prints a file the caller
  names, since redaction cannot be trusted on files of unknown format. It lists every tool
  that does read a file and whether it redacts.
- [redact_lockfiles.md](redact_lockfiles.md): the lockfile rule set, used instead of
  `SECRET_PATTERNS`, not after it.
