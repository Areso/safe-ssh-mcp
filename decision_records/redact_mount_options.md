# get_fstab / get_mount_problems: a separate redaction rule set for mount options

Date: 2026-11-23
Status: accepted

## Decision

`get_fstab` and `get_mount_problems` redact their output with `MOUNT_SECRET_PATTERNS`: two
rules for mount options, run before all of the general `SECRET_PATTERNS`. The
`mount_problems` section of `get_host_overview` uses the same set. `get_mounts` does not
redact.

The mount rules:

| Rule | Catches | Value ends at |
|---|---|---|
| `password=`, `password2=`, `passwd=`, `pass=`, `credentials=` at the start of an option | cifs passwords; the credentials file path (see below) | whitespace or a single comma (`,,` is part of the value) |
| `user=name%` / `username=name%` | the cifs `user=name%password` form | the same |

## Why mount options get their own rules

Both tools can show cifs passwords: `get_fstab` prints `/etc/fstab` as written, and
`get_mount_problems` prints the whole fstab entry, options included, for every entry
that is not mounted:

```
NOT MOUNTED (nofail: the boot went on without it): //fs/share /mnt/s cifs user=bob%<redacted>,nofail,_netdev
```

The general rules were written for shell lines, where a value ends at whitespace or a
quote. In mount options a value ends at a comma. With only the general rules, on the test
VMs:

| fstab options | general rules only | with the mount rules |
|---|---|---|
| `username=bob,password=S3c,vers=3.0,noauto` | `password=<redacted>`: everything after the password is gone | `password=<redacted>,vers=3.0,noauto` |
| `user=bob%S3c,nofail` | shown: no keyword before the `%` | `user=bob%<redacted>,nofail` |
| `pass=S3c,username=bob` | shown: bare `pass` is not a keyword (it would match `bypass`) | `pass=<redacted>,username=bob` |
| `password=ab,,cd,vers=3.0` | `cd` would be lost with the rest of the line | `password=<redacted>,vers=3.0` (mount.cifs writes a comma inside a password as `,,`) |

The rules are not added to the general set because they are only right for mount
options. In a shell line or a log, a comma can be part of a value
(`--password=a,b`, `DATABASE_URL=...?x=1,y=2`): ending the value there would show the
rest of the secret. A bare `pass=` outside mount options is too often not a password.
The same reason gave `get_systemd_unit_definition` its own set; see the table below.

## Trade-off: credentials= is hidden

`credentials=/etc/cifs.cred` names a file (mount.cifs reads the username and password
from it); the path is not a secret and is useful when a mount fails. It is hidden
anyway: "credentials" is a general keyword, so the broad `NAME=value` rule would hide the
path and every option after it. The mount rule ends the value at the comma, so only the
path is lost. Keeping the path would need a mount-only copy of the broad rule that skips
`credentials=/...`; this was considered (2026-11-23) and left out for now.

## Why get_mounts does not redact

`get_mounts` prints `findmnt` or `/proc/mounts`, which the kernel builds: the cifs module
shows `username=` but never the password. It was not tested live with a mounted cifs
share. If another filesystem turns out to print a secret there, `get_mounts` opts in
with `MOUNT_SECRET_PATTERNS`.

## The redaction functions and where each rule set is applied

There are four free-text rule sets, all applied by the same two functions, and one
structured redaction:

- `redact_secrets(text, patterns=SECRET_PATTERNS)`: redacts a string, returns it and the
  number of values replaced.
- `redact_secrets_in_result(result, patterns=SECRET_PATTERNS)`: applies `redact_secrets`
  to the stdout and stderr of a `run_ssh_command` result and adds the `redaction` field.
- `redact_env_values` / `_redact_env_in_json_stdout`: parse JSON and blank every `env`
  value (crictl). See [get_crictl_inspect.md](get_crictl_inspect.md).

| Tool | Function | Rule set |
|---|---|---|
| `get_crontab_tasks`, `get_cron_jobs` | `redact_secrets_in_result` | `SECRET_PATTERNS` |
| `get_systemd_status` | `redact_secrets_in_result` | `SECRET_PATTERNS` |
| `get_ps_aux_top_cpu_consumers`, `get_ps_aux_top_mem_consumers`, `get_top` | `redact_secrets_in_result` | `SECRET_PATTERNS` |
| `get_service_logs_from_journalctl`, `get_journal_errors` | `redact_secrets_in_result` | `SECRET_PATTERNS` |
| `get_docker_logs`, `get_docker_inspect` | `redact_secrets_in_result` | `SECRET_PATTERNS` |
| `get_systemd_unit_definition` | `redact_secrets_in_result` | `SYSTEMD_SECRET_PATTERNS`: a rule for `Environment="NAME=a b"`, where the quotes wrap the whole assignment, then `SECRET_PATTERNS` |
| `get_fstab`, `get_mount_problems` | `redact_secrets_in_result` | `MOUNT_SECRET_PATTERNS`: the mount rules above, then `SECRET_PATTERNS` |
| `get_lockfiles` with `include_contents=True` | `redact_secrets_in_result` | `LOCKFILE_SECRET_PATTERNS`: credentials in URLs, secret query parameters and token prefixes, without `SECRET_PATTERNS` ([redact_lockfiles.md](redact_lockfiles.md)) |
| `get_host_overview` | `redact_secrets_in_result`, per section | the section's tool's set, from `HOST_OVERVIEW_REDACTED_TOOLS`: `mount_problems` with `MOUNT_SECRET_PATTERNS`; `top_cpu_processes`, `top_memory_processes`, `journal_errors` with `SECRET_PATTERNS`; the other sections are not redacted, as their tools are not |
| `get_crictl_inspect`, `get_crictl_inspect_image` | `_redact_env_in_json_stdout` | structured: every `env` / `envs` value |
| every other tool, `get_mounts` included | none | |

`tests/test_redact.py::test_exactly_these_tools_redact` fails when a tool starts or stops
redacting without this list being updated, and `tests/test_overview.py` checks that each
redacted overview section matches its tool's output.

## Tested

- Unit tests: `tests/test_redact.py` (`test_mount_patterns`,
  `test_mount_tools_use_the_mount_patterns`).
- Live: `scripts/redaction_test/` plants cifs entries (`nofail` / `noauto`) in
  `/etc/fstab` on Ubuntu 24.04 and Alpine 3.24 with controls (`domain=`, `uid=`) after
  the password that must stay visible; both tools redact every password and keep the
  controls.

## Related

- [redact_secrets.md](redact_secrets.md): the general rules and the trade-off behind them.
- [get_mounts.md](get_mounts.md).
