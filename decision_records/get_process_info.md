# get_process_info: one process, by pid or name, from ps and /proc

Date: 2026-11-24
Status: accepted

## Decision

`get_process_info(pid=None, name=None)` describes one process (or, by name, at most 5):
`ps` (state, elapsed time, %CPU, threads, wait channel, command line) and, from `/proc/<pid>/`,
`status` (memory now and at its peak, swap, context switches, capabilities), `cgroup` (the
systemd unit or container), the count of open file descriptors, `limits`, `oom_score` /
`oom_score_adj` and `io`. The command line is redacted with `SECRET_PATTERNS`.

- **pid, or name, or both.** Neither is an error. Both is an AND: the process is described only
  if that PID still has that name, else the error says what the PID is now
  (`PID 1 is 'systemd', not 'nginx': the process may have exited and its PID been given to
  another one`).
- **name is matched exactly** against `/proc/<pid>/comm` (COMM in ps), as a string, in the shell.
  Several matches: the 5 with the lowest PIDs, after a line saying how many there are.
- **Input:** `pid` is `is_valid_pid` (an integer 1..4194304, not a bool). `name` is at most 15
  characters (the kernel's COMM length) of ASCII letters, digits and `. _ - : / @ + ( )`, spaces
  only inside (`process_name_error`). Both reach the fixed script as its arguments `$1` / `$2`,
  shell-quoted, never as part of the code.
- **Root:** the script runs through `sudo -n` / `doas -n` first; if that is refused it runs as
  the login user after a `# not run as root` line (as `get_process_files`). "No such process"
  and "PID has another name" exit 3, which counts as an answer of the root run, not as a
  refusal, so they do not trigger the plain re-run.

## Why

The process tools (`get_ps_aux_top_*`, `get_top`) find which PID is the problem; nothing said
what is wrong with it: stuck in the kernel (`D` + wait channel), a zombie, restarting (small
elapsed time), leaking threads or file descriptors (open files against `Max open files`),
swapped out, starved of CPU (non-voluntary context switches), which unit or pod owns it, who
the OOM killer takes first.

- **AND for both:** the PID usually comes from an earlier call. After a restart (the crash
  loop on fr1, 2026-11-23) the kernel may have given it to another process, and the agent would
  be told about the wrong one without knowing it.
- **Exact COMM, not pgrep:** `pgrep` takes a regex (`.` in `php-fpm8.2` matches anything) and
  `pgrep -f` searches the whole command line (`php` would match `vim /etc/php.ini`). A string
  compare on COMM is predictable, and the name never becomes code or a pattern.
- **The character set:** the kernel allows nearly any byte in COMM; the set covers real names
  (`nginx`, `php-fpm8.2`, `kube-apiserver`, `kworker/0:1H`, `(sd-pam)`, `Web Content`) and
  rejects shell and regex syntax, quotes, non-ASCII and newlines. A name longer than 15 is
  rejected with the reason: the kernel cuts it (`systemd-journald` is `systemd-journal`), so it
  could never match.

## Not shown

- `/proc/<pid>/environ`: that is where secrets are.
- The targets of `/proc/<pid>/fd`: only their count (file names, sockets, pipes could be many).
- `/proc/<pid>/cmdline` directly: the command line comes from `ps` (`args`), and is redacted.

All the paths are fixed `/proc/<pid>/` files with a validated PID: the kernel-state exception
of [no_arbitrary_file_read.md](no_arbitrary_file_read.md).

## BusyBox (Alpine)

BusyBox `ps` has no `-p`, `%CPU`, `%MEM`, threads or wait channel: there the tool prints
`ps -o pid,ppid,user,stat,nice,etime,time,rss,vsz,args` filtered to the PID, after a line
saying so. `/proc` is the same everywhere.

## Tested

- Unit tests: `tests/test_validation.py` (`TestProcessInfoValidation`), `tests/test_tools.py`
  (`test_process_info_*`).
- Live, 2026-11-24: Ubuntu 24.04 (root), Alpine 3.24 (non-root user with `doas -n`) and a
  kubeadm 1.37 node: by pid, by name with several matches, pid + name matching and not, a
  missing PID, an unknown name; the planted busy loop's `--password=` is hidden
  (`scripts/redaction_test/`, `ZQP01` / `ZQP11`). `ab_test.py commands` has variants for it.

## Related

- [as_root.md](as_root.md): the root fallback and the sudoers note for `sh -c` scripts.
- [redact_secrets.md](redact_secrets.md): which tools redact, with which rule set.
