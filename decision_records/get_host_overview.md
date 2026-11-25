# get_host_overview: one call, many facts, each one an existing tool's output

Date: 2026-11-23
Status: accepted (v1)

## Decision

`get_host_overview` runs a fixed list of sections (`HOST_OVERVIEW_SECTIONS`) and
returns them under `data.sections`. Every section is exactly what one existing tool
returns with its defaults: the same builder or constant, the same `run_ssh_command`
path, the same default timeout. Each section names that tool in `source_tool`.

v1 sections: hostname, os_release, kernel, libc, uptime, cpu, memory, pressure,
disk_free, inode_usage, mount_problems, failed_units, top_cpu_processes,
top_memory_processes, listening_sockets, journal_errors. Added 2026-11-25: socket_summary
(`get_socket_summary` with its default top 20, after listening_sockets): TCP connection
counts, about 1 KB however many sockets the host has, so it does not grow the overview on
a busy host.

## Facts only

The server reports facts; it does not judge them. The overview has no thresholds
("disk over 90%"), no findings, no severity and no ranking. Interpretation belongs to
the caller: `sre_agent`, another LLM client, or a person. Reasons:

- What is "too much" depends on the host and the question; a threshold in the server
  would be wrong for someone, and then silently shape every conclusion drawn from it.
- Thresholds and their wording can be benchmarked and changed in `sre_agent` without a
  server release.
- It keeps the overview the same kind of thing as the other 63 tools: what the host
  says, framed with exit codes.

## Each section is a tool's output, not a variant

- An agent that has read a tool's description knows how to read its section, and can
  call that tool again to look closer or to compare.
- `tests/test_overview.py` checks that each section sends exactly what its tool sends,
  so the two cannot drift apart. Checked live on five VMs: static sections are
  byte-identical to the tool's result, live ones differ only in their data.
- No shortening or compact variants in v1 (no byte caps, `journal_errors` keeps the
  tool's 200 lines, `memory` keeps `/proc/meminfo`). Measured: 10-25 KB of JSON. Caps or
  compact variants, if they come, become builder parameters shared with the tools.
- Root: the sections that need it for part of their output (`findmnt --verify` in
  mount_problems, process names in listening_sockets and socket_summary) are included, with their tools'
  `sudo -n` / `doas -n` fallbacks.

## One SSH channel per section, not one script

Tried first: all sections in one remote script, framed by nonce markers, in one channel
(1.9 s on a 70 ms link). Rejected, because the script carrying all 16 commands (about
40 KB) is on the command line of a running process, so `top_cpu_processes` listed the
overview itself: 44 KB instead of about 1 KB. It also needed a marker parser and the
rule that the outer time limit must never fire first (a limit stops only its own process
group, see [remote_timeout.md](remote_timeout.md)).

Chosen: the sections run one after another, each in its own channel on the pooled SSH
connection, through `run_ssh_command`. One command per section: 17 sections send 17
commands, each the same command string its tool sends, over one SSH connection (set up
once, or reused from the pool). A call is the same as calling those 17 tools in a row. About 4 round trips per section: 5.5-7.5 s on the
test VMs (70 ms), which is acceptable for a first look. Identical output to the tools
comes by construction, and the per-command timeout handling is reused unchanged.

If latency matters later: send the one script over stdin instead of argv. That needs
stdin support in `_run_cmd`, and the watchdog in `TIMEOUT_SCRIPT` would have to pass
stdin to the command (a background job gets `/dev/null`).

## Result

- `ok` is True when the host was reachable for every section, whatever the sections
  returned: a failing section (`systemctl: not found` on Alpine, exit 127) is a fact,
  and the others still run.
- No connection at the first section: that error is returned as it is. Connection lost
  later: the overview stops, returns the sections collected so far, and says which
  section it stopped at.
- `timeout` (1-360 s, the bounds every tool has), when given, replaces every section's default limit (60 s).

## Name

`get_host_overview`, chosen over `_report` (that is what a reader writes from these
facts), `_status` (promises a verdict; next to `get_systemd_status`), `_info` (too vague;
`get_cpu_info` uses "info" for static facts) and `_snapshot` (in ops it usually means a
VM or disk snapshot, a write action).

## Later

Candidates left out of v1: lsblk, IP addresses, journal disk usage, dmesg, cron jobs,
and a CPU/IO sample (3-4 s each). They can come as opt-in flags once it is clear what
callers ask for after the overview.
