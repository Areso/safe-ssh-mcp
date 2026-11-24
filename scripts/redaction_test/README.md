# Live redaction test

Plants fake secrets on disposable VMs in the places where real ones turn up (unit files,
drop-ins, crontabs, `/etc/cron.d`, cifs entries in `/etc/fstab`, process arguments, the
journal, a docker container, lockfiles under `/srv/zqleak`), runs
every tool against them and reports which secrets each tool shows.

```sh
T="--target debian=root@1.2.3.4 --target alpine=alpine@5.6.7.8 --key $HOME/.ssh/id_rsa_private"

.venv/bin/python scripts/redaction_test/redaction_test.py plant $T   # over plain ssh: writes
.venv/bin/python scripts/redaction_test/redaction_test.py check $T   # the tools, as Python functions
.venv/bin/python scripts/redaction_test/redaction_test.py check $T --save /tmp/redaction.json
.venv/bin/python scripts/redaction_test/redaction_test.py clean $T
```

(In zsh, `$T` is not split into words: write the options out, or use `${=T}`.)

Profiles: `debian` (Debian/Ubuntu, as root; installs `docker.io` unless `SKIP_DOCKER=1`, a few
minutes on a 512 MB VM), `alpine` (a non-root user with `doas -n`; no systemd, no docker) and
`k8s` (root on a kubeadm control plane with kubectl and crictl: a deployment with secrets in
its env, args and logs, in namespace `zqleak`, pinned to that node so that crictl sees it;
check looks up the pod name and container ID itself).
Exit code 0 means no failure.

## Markers

Every planted secret is `ZQ<letter><2 digits>`. `MARKERS` in `redaction_test.py` says where
each one is planted and what kind it is:

| Kind | Meaning | check fails when |
|---|---|---|
| `secret` | must be hidden by every tool that redacts | a redacting tool shows it |
| `gap` | a form redaction cannot catch (`token x` without `=`, `echo x \| docker login --password-stdin`) | never; listed as "known gaps" |
| `control` | looks like a secret but is not (`PRIMARY_KEY=`, `PUBLIC_KEY=`, `SORT_KEY=`, `OLDPWD=`) | a tool that should show it does not (over-redaction) |

A call listed in `MUST_REDACT` (its output always holds a planted secret) that replaced
nothing also fails: the planting did not land.

## Reading the results

- `ok` rows are the tools that redact: their result has a `redaction` field. For
  `get_host_overview` these are the sections with `redaction_replaced` (mount problems, top
  CPU and memory processes, journal errors); markers in its other sections are listed, not failed.
- `info` rows are the tools without redaction; "no redaction, shows ..." lists what they
  showed. As of 2026-11-23 none shows a planted secret.
- Markers no tool shows: the environment file (`ZQF01`), docker env and labels
  (`ZQK01`-`ZQK04`), the Alpine periodic script contents (`ZQB04`) and syslog (`ZQB05`).

## Adding a case

Plant it in `plant_<profile>.sh` with a new marker (next free number of its letter), add the
marker to `MARKERS`, add a control to `CONTROLS` when it must stay visible, and add the
cleanup to `clean_<profile>.sh`. Use realistic token shapes: `AKIA` needs exactly 16
characters after it, `ghp_` at least 30.

## Notes

- Disposable VMs only: plant runs a busy loop (`nice 19`) and a 150 MB process, adds a user
  and leaves secret-looking lines in the journal (`clean` does not rotate it).
- New tools with required parameters need a value in `REQUIRED`.
- First used for `get_systemd_unit_definition`, the `_KEY`/`_PWD`/`_PAT` and token-prefix
  rules and redaction of the process, journal, docker and mount tools (2026-11-23), on Ubuntu
  24.04 and Alpine 3.24 droplets. The fstab entries are `nofail` or `noauto`, so a reboot
  does not wait for them; `clean` removes them.
