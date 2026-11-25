# AGENTS.md

Instructions for AI coding agents working on safe-ssh-mcp.

## Run the tests after every change

After ANY change to `mcp_ssh.py` (or to a test, script or rule it depends on), rerun the
tests before saying the change is done. Unit tests alone are not enough: also run the live
scripts that cover what changed.

| What changed | Run |
|---|---|
| anything | `uv run pytest -q` |
| a tool's command, a builder, a new or removed tool | `.venv/bin/python scripts/ab_test/ab_test.py commands` (offline: every existing tool must send the same command unless the change meant otherwise) |
| SSH, the remote wrapper, `timeout_wrapped` / `TIMEOUT_SCRIPT`, `_run_cmd` | `scripts/ab_test/ab_test.py fleet` and `timeouts` |
| redaction (patterns, rule sets, which tools redact) | `scripts/redaction_test/redaction_test.py plant` then `check`, and `scripts/ab_test/ab_test.py fleet` (on output nobody planted, the only differences must be values that became `<redacted>`: check each one is a secret or an accepted over-redaction) |
| `get_socket_summary`, `get_tcp_connections` (their commands, the awk counting and filtering, the ss / netstat paths) | `scripts/socket_load/socket_load.py run` (one VM makes TCP load against another; every generated state must show up) |

- After changing a shared definition (a constant, pattern or validator such as
  `PROCESS_NAME_CHARS`, `*_PATTERN`, `is_valid_*`, `*_error`, `_SECRET_WORDS`, `AS_ROOT_PREFIX`),
  queue a check of every tool it affects: find them with `grep -n NAME mcp_ssh.py`, following
  helper functions up to the `@mcp.tool()` functions, then run `scripts/ab_test/ab_test.py commands`
  and `fleet` and check that those tools behave the same except where the change meant otherwise.
  List the affected tools in the report. If `fleet` calls them only with placeholder arguments
  (`REQUIRED` in `ab_test.py`), add `VARIANTS` that hit the changed case (a value at the edge of the
  pattern, e.g. a name with `-` or a space), or compare HEAD and the working tree on real objects.
- When a fix adds a new case, add it to the live script too (a marker in
  `scripts/redaction_test/`, a scenario in `scripts/ab_test/`), not only to the unit tests.
- The live scripts need disposable test VMs (see each script's README). If none are
  running, say so; do not skip the live run silently.
- Before every A/B `fleet` or `timeouts` run, rewrite `scripts/ab_test/hosts.txt` (git-ignored)
  from the VMs that are up now: `doctl list` (a shell alias; where aliases are not loaded,
  run `python3 ../do_handler/digitalocean_vms.py list`). One line per VM, `NAME USER@PUBLIC_IP`, with the image's distro
  as NAME (`ubuntu`, `debian`, `fedora`, `centos`, `alpine`, ...); USER is `alpine` on Alpine
  images and `root` on the others. When a kubeadm test cluster is up, add its control plane
  as `ubuntu-k8s root@PUBLIC_IP` (NAME must be unique), so that the kubectl and crictl tools
  run against a real cluster. `fleet` calls them with placeholder names (`pod: web-1`), so
  after a change to how they redact, also compare HEAD and the working tree on real objects
  (a pod, its container, a deployment). Take the `--target`s of `scripts/redaction_test/` from
  the same list (`debian=` for Debian/Ubuntu, `alpine=` for Alpine, `k8s=` for the control
  plane of a kubeadm test cluster).
- Report which suites ran and their results (passed / failed counts, failures by name).

## No token-shaped strings in the repo

GitHub push protection blocks a push that contains anything shaped like a real secret
(Stripe `sk_live_...`, GitHub `ghp_...`, Slack `xoxb-...`, AWS `AKIA...`, PEM private key
blocks), even a fake one in a test. Never write such a value as one literal:

- Python tests: build it at run time from parts, as `tests/test_redact.py` does
  (`STRIPE = "sk_" + "live_" + "..."`, `GHP`, `SLACK`, `AWS_ID`, the PEM `begin` / `end`).
- Shell scripts: write the prefix as a placeholder (`@GHP@`, `@SKLIVE@`, `@XOXB@`,
  `@AKIA@`) and replace it with `sed` on the host, as `scripts/redaction_test/plant_*.sh`
  do (`fill_tokens`).
- Before committing, check: `git grep -n -E 'sk_live_[A-Za-z0-9]{6,}|ghp_[A-Za-z0-9]{8,}|xox[abposr]-[0-9]|AKIA[A-Z0-9]{12,}|BEGIN [A-Z ]*PRIVATE KEY-----'`
  should find only `mcp_ssh.py` (the patterns themselves) and short negative cases.

## Related

- `scripts/ab_test/README.md`, `scripts/redaction_test/README.md`, `scripts/socket_load/README.md`:
  how to run the live tests.
- `decision_records/`: why things are the way they are; update the relevant record when a
  decision changes.
