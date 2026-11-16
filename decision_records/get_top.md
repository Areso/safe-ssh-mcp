# get_top: second sample of two, cut to 30 lines

Date: 2026-11-17
Status: accepted

## Decision

`get_top` runs `top -b -n 2 -d 1 -c -w 512`, keeps the second sample only and cuts it
to the first 30 lines. Before it ran `top -b -n 1 -c` and returned everything.

On BusyBox hosts (Alpine) it still runs plain `top -b -n 1`, now cut to 30 lines too
(the `# BusyBox` header line plus 29 lines of top). Its lines are not cut in width.

## Why two samples

With `-n 1` procps top has no interval to measure: the `%Cpu(s)` line is the average
since boot and the per-process `%CPU` is not the current usage. The second sample
covers the delay between the two, so it shows what the host is doing now.

BusyBox top needs no such thing: it measures a short interval on its own before the
first output.

## Why a 1 second delay

`-d 0.5` was the first idea. It was dropped:

- procps top reads the delay in the host's locale, so `0.5` is rejected where the
  decimal separator is a comma. An integer works everywhere, with no `LC_ALL=C`;
- CPU time is counted in ticks of about 10 ms, so half a second gives coarse numbers;
- `get_vmstat` (`vmstat 1 5`) samples every second too, so the numbers compare.

The price is a call about 1 second longer.

## Why -w 512

Without a tty, top in batch mode cuts lines at 80 columns, so `-c` showed only the
start of each command line. 512 is the most `-w` accepts.

`-w 200` was tried first and dropped: the end of a long command line is often the
useful part (the jar, the config file, the script that `sh -c` runs). With 30 lines
the output stays small anyway, and it grows only on hosts where the command lines
really are long.

## Why 30 lines

The full list is one line per process, hundreds of lines on a busy host. 30 lines are
the 7 summary lines and the 23 biggest CPU consumers.

On an idle host almost every process is at 0.0 %CPU and ties are ordered by PID, so
those 23 rows are `init` and kernel threads. This is accepted: `get_top` answers "what
is using CPU now", and `get_ps_aux_top_cpu_consumers` / `get_ps_aux_top_mem_consumers`
list processes otherwise.

## Why the filter is not a plain pipe

`top ... | awk ... | head` returns the exit code of `head`, always 0. A failing top
would be hidden and, on Alpine, the BusyBox fallback would never run: empty output and
success.

So `busybox_fallback` got an optional `output_filter`. The output of the command is
captured, its exit code is checked, and only then the output is piped through the
filter. The filter is not applied to the fallback command.

The BusyBox branch follows the same rule: the output of top is captured first, so a
failing BusyBox top keeps its exit code and stderr. It is cut with `awk 'NR <= 29'`.

## Why the BusyBox lines are not cut in width

BusyBox top has no width option and prints long command lines in batch mode: 434
columns were seen on Alpine. Cutting them to 200 columns with
`awk '{print substr($0, 1, 200)}'` was tried and reverted, for the same reason as
`-w 200`: the whole command line is worth more than the bytes saved.

## Not done

- Very old procps (3.2, CentOS 6) has no `-w`: `get_top` fails there with top's own
  error message.

## Checked on

Debian 13, Ubuntu 24.04, Fedora 44, CentOS Stream 10 (second sample, 30 lines) and
Alpine 3.24 (BusyBox fallback, 30 lines), 2026-11-17.

## Where

- `get_top`, `TOP_SECOND_SAMPLE_FILTER`, `BUSYBOX_TOP_CMD` and `busybox_fallback` in
  `mcp_ssh.py`.
