# redact_lockfiles: lockfile contents get URL and token rules only

Date: 2026-11-24, updated 2026-11-24 (query parameters)
Status: accepted

## Decision

`get_lockfiles(include_contents=True)` passes its output through
`redact_secrets_in_result(result, LOCKFILE_SECRET_PATTERNS)`. The rule set has four rules
and none of the general ones:

1. `scheme://user:password@host`: the password is replaced
   (`--index-url https://deploy:<redacted>@pypi.example.com/simple`).
2. `http(s)://token@host`, also `git+https://`: a user name with no password is replaced,
   as it is a token there (`git+https://<redacted>@gitlab.example.com/org/lib.git`).
3. Query parameters whose name holds a secret word (`_SECRET_WORDS`), or is `sig`,
   `*signature` or `auth`: the value is replaced
   (`…/lib.tgz?private_token=<redacted>`, `…&X-Amz-Security-Token=<redacted>&X-Amz-Signature=<redacted>`,
   `…&sig=<redacted>`). Every such parameter of a URL, up to the next `&`, `#`, space or quote.
4. Tokens by their known prefix (`ghp_`, `sk_live_`, `xoxb-`, `AKIA`), as in `SECRET_PATTERNS`.

A `${VAR}` placeholder in place of the user or password stays visible. Without
`include_contents` the output is `ls -l` of the files found and is not redacted.

## Why

`requirements*.txt` keeps credentials in URLs: private index URLs
(`--index-url`, `--extra-index-url`, `-i`) and VCS or direct URLs with a token
(`git+https://<token>@host/...`, `pkg @ https://<token>@host/pkg.whl`). Other lockfiles
can hold registry credentials the same way (`resolved` in `package-lock.json`, `remote:` in
`Gemfile.lock`). See [no_arbitrary_file_read.md](no_arbitrary_file_read.md) for why this is
the only tool that prints files under paths the caller gives.

Some services take the token as a query parameter, and package managers copy such a URL
into the lockfile as given: GitLab (`?private_token=`, `?job_token=`) in npm/yarn/pnpm
`resolved` / `tarball`, in `requirements.txt` direct URLs and in Composer `dist.url`; the old
GitHub API (`?access_token=`, removed by GitHub in 2020) in old `composer.lock` files; and
signed URLs (S3 `X-Amz-Security-Token` / `X-Amz-Signature`, Azure SAS `sig`, GCS
`X-Goog-Signature`). Signed URLs expire, so in a lockfile they are usually dead, but
`X-Amz-Security-Token` is a session credential, and hiding them costs nothing.
The rule matches only after `?` or `&`: lockfiles have those only in URLs, and a package
line never has one before a name, so `tokenizers==0.15.0` cannot be hit. It goes by the
parameter name, never the value: `?branch=token-fix`, `?rev=`, `?tag=` (Cargo and pip git
URLs) and `#sha512-...` integrity fragments stay.

`SECRET_PATTERNS` is not used, not even after the lockfile rules (unlike the systemd and
mount rule sets, which add to it):

| Line | `SECRET_PATTERNS` gives | Problem |
|---|---|---|
| `secretstorage==3.3.3` | `secretstorage=<redacted>` | the version is gone (`secret` in the name) |
| `tokenizers==0.15.0` | `tokenizers=<redacted>` | the same (`token`) |
| `"node_modules/js-tokens": {` | `"node_modules/js-tokens": <redacted>` | the JSON no longer parses |
| `git+https://<token>@gitlab...` | unchanged | a user name alone is not caught |
| `https://deploy:${PIP_TOKEN}@host` | `https://deploy:<redacted>@host` | hides a placeholder, which is not a secret |

The tool exists to report exact dependency versions, and the docstring says files are
returned whole so that they can be parsed. Rules that fire on package names would break
both, on common packages (`secretstorage` comes with `keyring`, `js-tokens` with React).

## Trade-off

Only the URL and token-prefix forms are caught. A secret written another way in a lockfile
is still shown: a comment (`# password=x`), an option such as `--trusted-host` with a
token in it, or a token without a known prefix outside a URL. Lockfiles are generated
files and seldom hold such forms; `requirements*.txt` is the hand-written one, and pip
takes credentials in URLs there. Also still shown:

- a token in the URL path, which has no name to go by (Cloudsmith:
  `https://dl.cloudsmith.io/<token>/org/repo/...`);
- a query parameter with an innocent name (`?k=`, `?t=`);
- GitHub's `https://<token>:x-oauth-basic@github.com/...`, where the token is the user name
  and the password a fixed word: user names are not redacted (decided 2026-11-24), only
  the fixed word is.

`X-Amz-Credential` is hidden although it is an access key ID with its scope, not a secret
(its name holds `credential`); harmless.

The user-name-only rule hides a plain user name in an `https://user@host` URL with no
password (pip would prompt for the password). That is rare in a file meant to run
unattended, and it is the form GitHub, GitLab and others use for tokens.

The `===== <path> (<size> bytes) =====` lines give the size of the file on disk, before
redaction.

## Where

- `LOCKFILE_SECRET_PATTERNS`, `_URL_PLACEHOLDER` and `_TOKEN_PREFIX_RULE` (shared with
  `SECRET_PATTERNS`) in `mcp_ssh.py`; applied in `get_lockfiles`.
- Unit tests: `tests/test_redact.py` (`test_lockfile_patterns_*`, `test_lockfiles_*`).
- Live: markers `ZQL01`-`ZQL08`, `ZQL11`, `ZQL12` and controls `ZQX12`-`ZQX17` in
  `scripts/redaction_test/`, planted in `/srv/zqleak` (2026-11-24: all hidden, all
  controls shown, on Ubuntu 24.04 and Alpine 3.24).
- The general approach and its limits: [redact_secrets.md](redact_secrets.md); the table of
  which tool uses which rule set: [redact_secrets.md](redact_secrets.md#which-tools-redact-with-which-function-and-patterns).
