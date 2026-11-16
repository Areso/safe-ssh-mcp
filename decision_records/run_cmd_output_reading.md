# _run_cmd: stdout is read to the end before stderr; a huge stderr can stall

Date: 2026-11-14
Status: accepted, open to revision

## Decision

`_run_cmd` reads the whole stdout, then the whole stderr, then asks for the exit
status. The two streams are not read at the same time. This is left as it is.

## Background

Until 0.2.0 the exit status was requested before any output was read. SSH buffers only
about 2 MB of unread output, so a command that printed more stalled until the timeout
killed it, and the output came back cut off. 0.2.0 fixed that by reading the output
first (checked with 8 MB of stdout on a real host).

## Known gap

Stderr is not touched until stdout has ended. A command that writes more than about
2 MB to stderr while stdout is still open stalls the same way: it waits for someone to
read stderr, and the server waits for stdout to end. The call then ends at the timeout
with incomplete output.

## Why it is left

- No tool produces anything close to 2 MB of stderr. The gap is theoretical.
- `_run_cmd` is the one function every tool goes through. A change there carries more
  risk than the gap does.
- When it does happen, the result is a reported timeout, not wrong data.

## Alternative one: read stderr in a background thread

Start a short-lived thread that calls `stderr.read()`, read stdout in the main code as
now, then join the thread. Both streams are drained at the same time, so neither can
fill up.

- About six lines of change.
- Both `.read()` calls stay, so the mocked SSH client and the tests built on it keep
  working.
- The timeout path is untouched.
- Cost: one extra thread per command, alive only while the command runs.

This is the one to take if the gap ever needs closing.

## Alternative two: read both streams in turns in one loop

Replace the two `.read()` calls with a loop that takes whatever stdout and stderr have
ready, until the command finishes, and then drains what is left.

- No extra thread.
- Rewrites the core of `_run_cmd` by hand. Known traps: output that arrives just as the
  command exits is easy to lose; waiting for "anything ready" either burns CPU or adds
  a delay to every call; chunks can split a multi-byte character, so bytes must be
  collected and decoded once at the end.
- Needs its own deadline instead of paramiko's channel timeout, so the timeout
  behaviour and its detection (`is_probable_timeout`) have to be verified again.
- The mocked SSH client fakes `stdout.read()` / `stderr.read()`; the fixture and its
  tests would have to be rewritten.

## Rejected: merge stderr into stdout

`channel.set_combine_stderr(True)` removes the problem with one line, but the result
would no longer say which stream a line came from. The separate `stdout` and `stderr`
fields are kept on purpose: the origin of a line is diagnostic information.

## Not covered here

Output has no size cap. None of the alternatives changes that; it is a separate
question.

## Where

- `_run_cmd` in `mcp_ssh.py`.
