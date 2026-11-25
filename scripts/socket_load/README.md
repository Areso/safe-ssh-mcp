# Live socket load test

Makes TCP load from one disposable VM (the client) against another (the server), then runs
`get_socket_summary` on both: each generated state must show up as one counted line, and the
server's summary must stay small (at most 4 KB) while raw `ss -tanp` grows with the sockets.
Then `get_tcp_connections` must list the sockets behind those lines and cap the long ones.

```sh
S="--server root@1.2.3.4 --client alpine@5.6.7.8 --key $HOME/.ssh/id_rsa"

.venv/bin/python scripts/socket_load/socket_load.py run $S     # start, wait 30 s, check, stop
.venv/bin/python scripts/socket_load/socket_load.py start $S   # or step by step
.venv/bin/python scripts/socket_load/socket_load.py check $S
.venv/bin/python scripts/socket_load/socket_load.py stop $S
```

(In zsh, `$S` is not split into words: write the options out, or use `${=S}`.)

- `--server`: root on a Debian/Ubuntu VM. `server_start.sh` installs nginx if it is missing
  and starts a python3 helper on :9000; `server_stop.sh` removes only what start added.
- `--client`: any user on a VM with `nc`, `timeout`, `wget` and `setsid` (BusyBox is fine;
  the Alpine fleet VM as `alpine` works).
- `--held 200 --closed 50 --seconds 240`: the load (defaults shown); `--settle 30`: how long
  `run` waits between start and check. `check` takes the same `--held` / `--closed` as `start`.
Exit code 0 means every check passed.

## What is generated and what check expects

| Load | Server (ss path) | Client |
|---|---|---|
| `--held` connections to :9000, kept open | `ESTAB in :9000 python3` | `ESTAB out SERVER:9000 nc` |
| `--closed` connections to :9000, closed after 3 s; the helper never closes its end | `CLOSE-WAIT in :9000 python3` (the leak pattern) | `FIN-WAIT-2` |
| 8 `wget` loops against nginx for `--seconds` | `TIME-WAIT in :80`, at least 100 | |
| 3 connects from the helper to `10.255.255.1:5432` (blackholed) | `SYN-SENT out 10.255.255.1:5432 python3` | |

`get_tcp_connections` checks: `state=close-wait, tcp_port=9000` lists the leaked sockets of
`python3` on the server; `state=time-wait, tcp_port=80, lines=10` shows exactly 10 rows and a
`# showing the first 10 of N` line with N >= 100; `state=established, tcp_port=9000` on the
client lists the held ones (netstat lines on BusyBox).

Counts pass at 90% of what was generated. `check` also prints the size of raw `ss -tanp` on
the server for comparison.

## Notes

- Disposable VMs only: start installs nginx and opens a few hundred connections.
- TIME-WAIT stops at `net.ipv4.tcp_max_tw_buckets` (2048 on a 512 MB VM): the kernel drops
  the rest, so more `wget` loops do not raise it.
- Stopping goes by pid files and process groups (`/run/socket_load` on the server,
  `$TMPDIR/socket_load` or `/tmp/socket_load` on the client), not `pkill -f`: a `pkill -f`
  pattern also matches the remote shell whose command line holds it, and kills the session.
- If `10.255.255.1` answers or is unreachable at once on your network, the SYN-SENT check fails;
  change `BLACKHOLE` in `server_start.sh` and `socket_load.py` together.
