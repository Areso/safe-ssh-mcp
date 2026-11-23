# Remote timeout: a command is stopped together with everything it started

Date: 2026-11-23
Status: accepted

## Decision

Every command runs on the host through `timeout_wrapped` (`TIMEOUT_SCRIPT` in
`mcp_ssh.py`):

- **GNU timeout present** (Debian, Ubuntu, RHEL, Fedora): `timeout -k 2 <N>s ...`, as
  before plus `-k 2`.
- **Otherwise** (BusyBox `timeout` on Alpine, or no `timeout` at all): the command runs in
  its own session (`setsid`), and a watchdog sends TERM to that session's whole process
  group at the limit, KILL 2 s later, and the wrapper exits 124.

On the server, `_run_cmd` stops reading when the output is still open `timeout_s` + 5 s
after the start, and returns what it has with `timed_out` and `output_never_ended`.

## Why

A time limit must stop all of a command, not just its first process:

| | GNU timeout | BusyBox timeout |
|---|---|---|
| Signals | the whole process group | only the process it started |
| `sleep 60` | stopped | stopped (ash runs the last simple command by `exec`) |
| `du / \| sort`, `cmd &` | stopped | only the shell dies; the rest gets PID 1 as parent and runs on |
| Exit status | 124 | the process dies from the signal: none over SSH (-1) |

Measured on Alpine 3.24 (BusyBox 1.37) with the old wrapper and `timeout_s=3`:
`sleep 712 | cat` held the SSH output open, so the call took 8.3 s, returned
`Network error: Could not connect to ...` (a `socket.timeout` from reading, caught as a
`socket.error`), lost the output printed before, and left `sleep` and `cat` running.
Many tool commands are pipelines, and a "read-only" server must not leave load behind
on the host it inspects.

GNU timeout without `-k` has the same gap for a command that ignores TERM: it then
waits for ever. Measured on all four GNU hosts: the call ended only at the server's
read deadline, and the processes stayed.

## How the watchdog works

```sh
setsid sh -c LAUNCHER "$0" & pid=$!          # own session: pgid = pid
setsid sh -c 'sleep N; kill -USR1 <wrapper>; kill -TERM -<pid>; sleep 2; kill -KILL -<pid>' ... >/dev/null 2>&1 & dog=$!
wait $pid                                    # USR1 interrupts it: fired=1
fired? wait again, exit 124 : stop the watchdog's group, exit with the command's status
```

- **USR1** tells the wrapper that it was the watchdog. A command killed for another
  reason (OOM, `kill -9`) keeps its own exit status (137, ...), not 124.
- The watchdog's output goes to `/dev/null`, so it never holds the SSH channel open, and
  it is stopped (its group, so its `sleep` too) when the command ends first.
- `kill -TERM -PGID` without `--`: BusyBox ash's `kill` rejects `--`.
- `wait ... 2>/dev/null`: ash prints `Terminated` for a waited job that was signalled. The
  notice is about the wrapper, not the command, and GNU hosts do not print it.
- `setsid` does not fork here: a background job of a non-interactive shell is not a
  process-group leader, so `$!` is the new session's ID. Checked with BusyBox and
  util-linux `setsid`.
- Without `setsid`, only the command's shell can be signalled, as with BusyBox
  timeout; the server's read deadline then still ends the call.
- The detection is `timeout --version` containing `GNU coreutils`. Anything else gets
  the watchdog, including uutils coreutils (Ubuntu 25.10+), whose group handling was not
  checked.

## Exit codes

`TIMEOUT_EXIT_CODES = (124, -1)`: 124 from GNU timeout or the watchdog; -1 when there is
no exit status: GNU timeout that had to send KILL (it kills its own group, itself
included), or `_run_cmd` giving up on output that never ended. As before, a timeout is
reported only when the command also ran for at least `timeout_s`.

## Why the server-side deadline as well

The remote side can still fail to stop everything: no `setsid`, or a process that left
the group by starting its own session. Before, the output's read timeout raised
`socket.timeout`, which was reported as "Could not connect" and dropped the output. Now
`_run_cmd` reads with `channel.recv` and keeps every chunk, so on that timeout it returns
what arrived, takes only the stderr already there, does not wait for an exit status
(which would wait for ever) and closes the channel. The error says that some processes
may still run on the host.

The reading order (all of stdout, then stderr) is unchanged; see
[run_cmd_output_reading.md](run_cmd_output_reading.md).

## Rejected

- **The watchdog everywhere.** It is simpler to have one path, but GNU timeout is the
  well-tested one, and the four GNU hosts already worked.
- **Asking the host which timeout it has once per connection.** One more round trip and
  a cache, to save one `timeout --version` per command.
- **`set -m` (job control) instead of `setsid`.** ash turns job control off without a
  terminal, and SSH exec channels have none.
- **Killing orphans by name afterwards.** Fragile, and it could hit processes that are
  not ours.

## Tests

- `tests/test_builders.py`: real runs with fake tools on PATH (a fake GNU `timeout`, a
  real `setsid` in Python because macOS has none): the GNU branch passes `-k 2`; the
  watchdog stops pipelines, background jobs and a command that ignores TERM, leaves no
  process behind, keeps exit codes and output, and works without `setsid`.
- `tests/test_run_ssh_command.py`: chunked reads, the reading order, and output that
  never ends.
- Live, on the five test VMs: nine scenarios each (simple, pipeline, output then
  pipeline, background job, ignores TERM, exit code and stderr, pipefail, 8 MB of
  stdout, finishing just in time), with a check for leftover processes after each.
