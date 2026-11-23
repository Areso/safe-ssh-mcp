# A/B test of mcp_ssh.py

Compares a git ref (A, default `HEAD`) with the working tree (B), to check that a refactor
changes nothing it should not. Each version runs in its own Python process.

```sh
cp scripts/ab_test/hosts.example.txt scripts/ab_test/hosts.txt   # then fill in (git-ignored)

.venv/bin/python scripts/ab_test/ab_test.py commands              # offline, seconds
.venv/bin/python scripts/ab_test/ab_test.py fleet --key ~/.ssh/id_rsa_private
.venv/bin/python scripts/ab_test/ab_test.py timeouts --key ~/.ssh/id_rsa_private
.venv/bin/python scripts/ab_test/ab_test.py fleet --ref v0.2.3 --save /tmp/ab.json
```

Exit code 0 means no difference (or all scenarios passed), 1 otherwise.

## Modes

| Mode | Needs hosts | Checks | Use after |
|---|---|---|---|
| `commands` | no | the exact command every tool sends (plus variants for parameterised tools, and validation errors) and the remote wrapper | a refactor that must not change any command: expect **0 differ** |
| `fleet` | yes | every tool on every host, A and B: `ok`, exit code, `timed_out`, `error`, stderr; which stdouts differ | any change to `mcp_ssh.py` |
| `timeouts` | yes | B only: 9 scenarios (pipeline, background job, command that ignores TERM, 8 MB output, ...) and processes left running afterwards | changes to `timeout_wrapped` / `TIMEOUT_SCRIPT` / `_run_cmd` |

## Reading the results

- `fleet`: any line under a host other than "stdout differs" is a real difference. Stdout
  of live data (uptime, top, vmstat, journal, process lists) always differs between two
  runs, so only its length is shown; look at it with `--save` when the length jumps.
  `check_tcp_connect` stderr can differ by DNS round-robin.
- `timeouts`: every row should be `PASS` with 0 leftovers. A failed "ignores TERM"
  leaves processes that need `pkill -KILL`.

## Notes

- Use disposable VMs only: tools run as the given user, and `timeouts` starts processes
  that are meant to be killed.
- New tools with required parameters need a value in `REQUIRED` in `ab_test.py`; tools
  whose parameters change the command can get extra calls in `VARIANTS`.
- First used for the builder refactor (2026-11-22) and the remote timeout fix
  (2026-11-23, see [../../decision_records/remote_timeout.md](../../decision_records/remote_timeout.md)).
