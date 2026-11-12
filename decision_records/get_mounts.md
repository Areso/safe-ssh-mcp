# get_mounts: findmnt first, nothing filtered

Date: 2026-11-11
Status: accepted

## Decision

`get_mounts` runs `findmnt` and falls back to `cat /proc/mounts` when findmnt is
not installed. The output is not filtered.

## Why findmnt first

It prints the same data as `/proc/mounts` (target, source, type, options) but as a
tree, so nested mounts are readable. Hosts without util-linux fall back to
`/proc/mounts`.

## Why nothing is filtered

The output includes pseudo filesystems (proc, sysfs, cgroup) and, on Docker hosts,
one overlay line per container, so it can be long.

`findmnt --real` would cut that down, but it needs util-linux 2.33+ and hides
tmpfs, so it was left out.

## Alternative

A `real_only` switch that adds `--real` on request.

## Where

- `get_mounts` in `mcp_ssh.py`.
