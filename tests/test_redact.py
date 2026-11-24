"""Tests for the free-text secret redaction (redact_secrets, redact_secrets_in_result)."""
import pytest

import mcp_ssh

R = mcp_ssh.REDACTED


@pytest.mark.parametrize("text, expected", [
    # database clients
    ("mysqldump -uroot -pS3cret db > /b.sql", f"mysqldump -uroot -p{R} db > /b.sql"),
    ("mysql -h db -u app -p'a b c' app", f"mysql -h db -u app -p{R} app"),
    ("mariadb-dump -pS3cret --all-databases", f"mariadb-dump -p{R} --all-databases"),
    ("PGPASSWORD=s3cret pg_dump app", f"PGPASSWORD={R} pg_dump app"),
    ("DB_PASS=hunter2 ./run.sh", f"DB_PASS={R} ./run.sh"),
    ("export db_pass=hunter2", f"export db_pass={R}"),
    ("MYSQL_DB_PASS='a b' ./run.sh", f"MYSQL_DB_PASS={R} ./run.sh"),
    ("app --db_pass=hunter2", f"app --db_pass={R}"),
    # long options
    ("app --password=hunter2 --verbose", f"app --password={R} --verbose"),
    ("app --password hunter2", f"app --password {R}"),
    ("tool --api-key abc123 run", f"tool --api-key {R} run"),
    ("tool --token=abc --secret xyz", f"tool --token={R} --secret {R}"),
    ("wget --http-password=pw https://x", f"wget --http-password={R} https://x"),
    # assignments, environment, config
    ("export DB_PASSWORD=hunter2", f"export DB_PASSWORD={R}"),
    ("API_TOKEN='abc def' ./run.sh", f"API_TOKEN={R} ./run.sh"),
    ('AWS_SECRET_ACCESS_KEY="abc/def"', f"AWS_SECRET_ACCESS_KEY={R}"),
    ("password: hunter2", f"password: {R}"),
    ('{"secret": "abc"}', f'{{"secret": {R}}}'),
    ("https://x/api?token=abc123&x=1", f"https://x/api?token={R}"),
    # http
    ('curl -H "Authorization: Bearer abcdefghijkl" https://x', f'curl -H "Authorization: Bearer {R}" https://x'),
    ("curl -H 'Authorization: Basic dXNlcjpwYXNz' https://x", f"curl -H 'Authorization: Basic {R}' https://x"),
    ("Bearer abcdefghijkl", f"Bearer {R}"),
    ("curl -u bob:pw123 https://x", f"curl -u bob:{R} https://x"),
    ("curl --user bob:pw123 https://x", f"curl --user bob:{R} https://x"),
    # URLs with credentials
    ("psql postgres://app:pw123@db:5432/x", f"psql postgres://app:{R}@db:5432/x"),
    ("git clone https://user:ghp_abc@github.com/x", f"git clone https://user:{R}@github.com/x"),
    # other tools
    ("sshpass -p pass ssh host", f"sshpass -p {R} ssh host"),
    ("sshpass -ppass ssh host", f"sshpass -p{R} ssh host"),
])
def test_redacts(text, expected):
    redacted, count = mcp_ssh.redact_secrets(text)
    assert redacted == expected
    assert count >= 1


@pytest.mark.parametrize("text", [
    "mkdir -p /var/backups",
    "ssh -p 2222 host",
    "mysql -p app",            # -p alone prompts for the password
    "mysql -P 3306 app",
    "PWD=/root",
    "cd / && run-parts --report /etc/cron.daily",
    "MAILTO=ops@example.com",
    "https://example.com/path@v1",
    "*/5 * * * * root /usr/bin/backup --verbose",
    "app --token --verbose",   # an option, not the token's value
    "BYPASS=1 PASSTHROUGH=yes ./run.sh",  # no bare "pass" keyword
    "Bearer short",            # too short to be a token
    "",
])
def test_leaves_harmless_text_alone(text):
    assert mcp_ssh.redact_secrets(text) == (text, 0)


def test_pem_private_key_block_is_redacted_whole():
    # built at run time like the tokens below: no key-shaped block in the source
    begin, end = "-----BEGIN RSA " + "PRIVATE KEY-----", "-----END RSA " + "PRIVATE KEY-----"
    text = f"before\n{begin}\nMIIEow\nAAAA\n{end}\nafter"
    assert mcp_ssh.redact_secrets(text) == (f"before\n{begin}{R}{end}\nafter", 1)


def test_counts_each_value_once():
    # --password=x is matched by the --password rule and by the password= rule
    assert mcp_ssh.redact_secrets("a --password=x b PASSWORD=y") == (f"a --password={R} b PASSWORD={R}", 2)


def test_redacting_twice_changes_nothing():
    once, _ = mcp_ssh.redact_secrets("mysqldump -pS3cret; export TOKEN=abc; https://u:p@h")
    assert mcp_ssh.redact_secrets(once) == (once, 0)


def test_multiline_text():
    text = "MAILTO=ops\n30 2 * * * mysqldump -pS3cret db\n0 * * * * DB_PASSWORD=x run"
    assert mcp_ssh.redact_secrets(text) == (
        f"MAILTO=ops\n30 2 * * * mysqldump -p{R} db\n0 * * * * DB_PASSWORD={R} run", 2
    )


def test_in_result_redacts_stdout_and_stderr_and_reports():
    result = {"ok": True, "data": {"command": "c", "exit_code": 0,
                                   "stdout": "export TOKEN=abc", "stderr": "mysql -pX failed"}}
    out = mcp_ssh.redact_secrets_in_result(result)
    assert out is result
    assert result["data"]["stdout"] == f"export TOKEN={R}"
    assert result["data"]["stderr"] == f"mysql -p{R} failed"
    assert result["redaction"] == {"replaced": 2, "note": mcp_ssh.REDACTION_NOTE}


def test_in_result_reports_zero_when_nothing_found():
    result = {"ok": True, "data": {"command": "c", "exit_code": 0, "stdout": "fine", "stderr": ""}}
    assert mcp_ssh.redact_secrets_in_result(result)["redaction"]["replaced"] == 0


def test_in_result_leaves_error_results_alone():
    result = {"ok": False, "error": "Network error"}
    assert mcp_ssh.redact_secrets_in_result(result) == {"ok": False, "error": "Network error"}


def test_note_states_the_tradeoff():
    assert "pattern-based" in mcp_ssh.REDACTION_NOTE
    assert "may still be shown" in mcp_ssh.REDACTION_NOTE


@pytest.mark.parametrize("tool", [mcp_ssh.get_crontab_tasks, mcp_ssh.get_cron_jobs])
def test_cron_tools_redact_their_output(tool, mock_run_ssh_command):
    mock_run_ssh_command.return_value = {
        "ok": True, "host": "h", "collected_at_utc": "t",
        "data": {"command": "c", "exit_code": 0, "stdout": "0 2 * * * mysqldump -pS3cret db", "stderr": ""},
    }
    result = tool(host="h", user="u")
    assert result["data"]["stdout"] == f"0 2 * * * mysqldump -p{R} db"
    assert result["redaction"]["replaced"] == 1


@pytest.mark.parametrize("text, expected", [
    ('Environment="API_TOKEN=a b" MODE=prod', f'Environment="API_TOKEN={R}" MODE=prod'),
    ("Environment='DB_PASS=a b c'", f"Environment='DB_PASS={R}'"),
    ('Environment="MODE=a b"', 'Environment="MODE=a b"'),
    ("Environment=DB_PASSWORD=x MODE=prod", f"Environment=DB_PASSWORD={R} MODE=prod"),
])
def test_systemd_patterns_take_quoted_assignments_whole(text, expected):
    assert mcp_ssh.redact_secrets(text, mcp_ssh.SYSTEMD_SECRET_PATTERNS)[0] == expected


def test_default_patterns_keep_the_command_after_a_quoted_assignment():
    """The systemd rule is not in the default set: in a shell line it would hide the command."""
    assert mcp_ssh.redact_secrets("sh -c 'DB_PASS=x ./run'")[0] == f"sh -c 'DB_PASS={R} ./run'"


def test_in_result_uses_the_given_patterns():
    result = {"ok": True, "data": {"command": "c", "exit_code": 0, "stdout": 'Environment="TOKEN=a b"', "stderr": ""}}
    assert mcp_ssh.redact_secrets_in_result(result, mcp_ssh.SYSTEMD_SECRET_PATTERNS)["data"]["stdout"] == \
        f'Environment="TOKEN={R}"'


@pytest.mark.parametrize("text, expected", [
    # found on the test VMs: a long option with a prefix before the word, a URL without a user
    ("/usr/bin/app --db-password s3cret", f"/usr/bin/app --db-password {R}"),
    ("app --client-secret=abc", f"app --client-secret={R}"),
    ("redis://:s3cret@localhost:6379/0", f"redis://:{R}@localhost:6379/0"),
    # options that take no secret stay as they are
    ("docker login --password-stdin registry.example.com", "docker login --password-stdin registry.example.com"),
    ("app --password-file /etc/pw", "app --password-file /etc/pw"),
    ("http://host:8080/x", "http://host:8080/x"),
    ("see https://example.com:443/a@b", "see https://example.com:443/a@b"),
])
def test_prefixed_long_options_and_userless_urls(text, expected):
    assert mcp_ssh.redact_secrets(text)[0] == expected


# Token-shaped test values are built at run time, so that no full token is in the source:
# GitHub push protection blocks a push that contains one, fake or not.
GHP = "ghp_" + "a1B2" * 9
STRIPE = "sk_" + "live_" + "4eC39HqLyjWDarjtT1zdp7dc"
SLACK = "xoxb-" + "1234-5678-abcdefghij"
AWS_ID = "AKIA" + "IOSFODNN7EXAMPLE"


@pytest.mark.parametrize("text, expected", [
    # names ending in _KEY / _PWD / _PAT
    ("STRIPE_KEY=abc", f"STRIPE_KEY={R}"),
    ("SSH_KEY=abc", f"SSH_KEY={R}"),
    ("export MYSQL_PWD=abc", f"export MYSQL_PWD={R}"),
    ("GITHUB_PAT: abc", f"GITHUB_PAT: {R}"),
    ("primary_key_secret=z", f"primary_key_secret={R}"),
    # _KEY names that are not secrets, and the working directory
    ("PRIMARY_KEY=id", "PRIMARY_KEY=id"),
    ("db_primary_key: id", "db_primary_key: id"),
    ("foreign_key: user_id", "foreign_key: user_id"),
    ("SSH_PUBLIC_KEY=ssh-ed25519", "SSH_PUBLIC_KEY=ssh-ed25519"),
    ("SORT_KEY=name PARTITION_KEY=day ROUTING_KEY=q CACHE_KEY=k LOOKUP_KEY=l UNIQUE_KEY=u",
     "SORT_KEY=name PARTITION_KEY=day ROUTING_KEY=q CACHE_KEY=k LOOKUP_KEY=l UNIQUE_KEY=u"),
    ("PWD=/root OLDPWD=/tmp", "PWD=/root OLDPWD=/tmp"),
    # tokens by their prefix, the prefix kept
    (f"curl -d k=1 {STRIPE}", f"curl -d k=1 sk_live_{R}"),
    (f"git clone https://x {GHP}", f"git clone https://x ghp_{R}"),
    (f"slack {SLACK}", f"slack xoxb-{R}"),
    (f"key id {AWS_ID}", f"key id AKIA{R}"),
    # too short or not the prefix: left alone
    ("AKIASHORT ghp_short sk_live_x risk_live_abcdefghijkl", "AKIASHORT ghp_short sk_live_x risk_live_abcdefghijkl"),
])
def test_key_pwd_pat_names_and_token_prefixes(text, expected):
    assert mcp_ssh.redact_secrets(text)[0] == expected


@pytest.mark.parametrize("text", [
    f"export AWS_ACCESS_KEY_ID={AWS_ID}",
    f"STRIPE_KEY={STRIPE}",
    f"GITHUB_PAT={GHP}",
])
def test_token_in_an_assignment_is_counted_once(text):
    redacted, count = mcp_ssh.redact_secrets(text)
    assert redacted == text.split("=")[0] + f"={R}"
    assert count == 1


def test_systemd_quoted_assignment_knows_the_suffix_names():
    text = 'Environment="STRIPE_KEY=a b" "PRIMARY_KEY=c d"'
    assert mcp_ssh.redact_secrets(text, mcp_ssh.SYSTEMD_SECRET_PATTERNS)[0] == \
        f'Environment="STRIPE_KEY={R}" "PRIMARY_KEY=c d"'


# ============================================================
# Which tools redact: a fixed list, so that adding or dropping redaction is a decision
# ============================================================

REDACTING_TOOLS = {
    "get_crontab_tasks", "get_cron_jobs", "get_systemd_unit_definition", "get_systemd_status",
    "get_ps_aux_top_cpu_consumers", "get_ps_aux_top_mem_consumers", "get_top",
    "get_docker_logs", "get_docker_inspect", "get_service_logs_from_journalctl", "get_journal_errors",
    "get_fstab", "get_mount_problems",
}
REQUIRED_ARGS = {
    "abs_paths": ["/srv"], "daemon": "nginx", "container": "web", "pod": "web-1", "resource_type": "pod",
    "name": "example.com", "container_id": "abcdef123456", "image": "nginx", "target_host": "example.com",
    "target_port": 443, "service": "nginx",
}


def _registered_tools():
    import asyncio
    return [t.name for t in asyncio.run(mcp_ssh.mcp.list_tools())]


def _call_with_secret_output(name, mock_run_ssh_command):
    import inspect
    mock_run_ssh_command.return_value = {
        "ok": True, "host": "h", "collected_at_utc": "t",
        "data": {"command": "c", "exit_code": 0, "stdout": "app --password=hunter2", "stderr": "token=abc"},
    }
    fn = getattr(mcp_ssh, name)
    params = inspect.signature(fn).parameters
    args = {p: REQUIRED_ARGS[p] for p in params
            if params[p].default is inspect.Parameter.empty and p not in ("host", "user")}
    return fn(host="h", user="u", **args)


def test_exactly_these_tools_redact(mock_run_ssh_command):
    redacting = set()
    for name in _registered_tools():
        if name == "get_host_overview":
            continue  # its sections are checked in test_overview.py
        if "redaction" in _call_with_secret_output(name, mock_run_ssh_command):
            redacting.add(name)
    assert redacting == REDACTING_TOOLS


@pytest.mark.parametrize("name", sorted(REDACTING_TOOLS))
def test_redacting_tool_hides_stdout_and_stderr(name, mock_run_ssh_command):
    result = _call_with_secret_output(name, mock_run_ssh_command)
    assert result["data"]["stdout"] == f"app --password={R}"
    assert result["data"]["stderr"] == f"token={R}"
    assert result["redaction"] == {"replaced": 2, "note": mcp_ssh.REDACTION_NOTE}


# ============================================================
# Mount options (get_fstab, get_mount_problems)
# ============================================================

@pytest.mark.parametrize("text, expected", [
    # cifs passwords: the options after the value stay visible
    ("//fs/share /mnt/s cifs username=bob,password=S3c,vers=3.0,noauto 0 0",
     f"//fs/share /mnt/s cifs username=bob,password={R},vers=3.0,noauto 0 0"),
    ("//fs/s /mnt/s cifs pass=S3c,username=bob 0 0", f"//fs/s /mnt/s cifs pass={R},username=bob 0 0"),
    ("//fs/s /m cifs password=a\\040b,password2=c,domain=CORP 0 0",
     f"//fs/s /m cifs password={R},password2={R},domain=CORP 0 0"),
    ("//fs/s /mnt/s cifs user=bob%S3c,noauto 0 0", f"//fs/s /mnt/s cifs user=bob%{R},noauto 0 0"),
    # mount.cifs writes a comma inside a password as ",,"
    ("//fs/s /m cifs password=ab,,cd,vers=3.0 0 0", f"//fs/s /m cifs password={R},vers=3.0 0 0"),
    ("//fs/s /m cifs user=bob%ab,,cd,,,uid=1 0 0", f"//fs/s /m cifs user=bob%{R},uid=1 0 0"),
    ("//fs/s /mnt/s cifs username=bob%S3c 0 0", f"//fs/s /mnt/s cifs username=bob%{R} 0 0"),
    # credentials= is a file path, hidden all the same, but not the options after it
    ("//fs/s /mnt/s cifs credentials=/etc/cifs.cred,uid=1000 0 0",
     f"//fs/s /mnt/s cifs credentials={R},uid=1000 0 0"),
    # nothing to hide
    ("UUID=1 / ext4 errors=remount-ro 0 1", "UUID=1 / ext4 errors=remount-ro 0 1"),
    ("https://dav/ /m davfs user,noauto,uid=1000 0 0", "https://dav/ /m davfs user,noauto,uid=1000 0 0"),
    ("//fs/s /m cifs username=bob,noauto 0 0", "//fs/s /m cifs username=bob,noauto 0 0"),
    # the general rules still apply
    ("# old: mount -o password=x", f"# old: mount -o password={R}"),
])
def test_mount_patterns(text, expected):
    assert mcp_ssh.redact_secrets(text, mcp_ssh.MOUNT_SECRET_PATTERNS)[0] == expected


@pytest.mark.parametrize("tool", [mcp_ssh.get_fstab, mcp_ssh.get_mount_problems])
def test_mount_tools_use_the_mount_patterns(tool, mock_run_ssh_command):
    mock_run_ssh_command.return_value = {
        "ok": True, "host": "h", "collected_at_utc": "t",
        "data": {"command": "c", "exit_code": 0, "stdout": "//fs/s /m cifs user=bob%S3c,password=x,vers=3.0 0 0",
                 "stderr": ""},
    }
    result = tool(host="h", user="u")
    assert result["data"]["stdout"] == f"//fs/s /m cifs user=bob%{R},password={R},vers=3.0 0 0"
    assert result["redaction"]["replaced"] == 2


@pytest.mark.parametrize("text, expected", [
    # found by the A/B run: the ';' after a value was taken as part of it
    ("sh -c 'echo password=x; echo done'", f"sh -c 'echo password={R}; echo done'"),
    ("0 1 * * * export API_KEY=x; /usr/bin/true", f"0 1 * * * export API_KEY={R}; /usr/bin/true"),
    ("Server=db;Password=x;Database=app", f"Server=db;Password={R};Database=app"),
    ("app --token=x;app2", f"app --token={R};app2"),
])
def test_value_ends_at_semicolon(text, expected):
    assert mcp_ssh.redact_secrets(text)[0] == expected


# ============================================================
# Lockfiles (get_lockfiles with include_contents): URLs and token prefixes only
# ============================================================

@pytest.mark.parametrize("text, expected", [
    # requirements*.txt: index URLs with a user and a password or token
    ("--index-url https://deploy:s3cret@pypi.example.com/simple",
     f"--index-url https://deploy:{R}@pypi.example.com/simple"),
    ("--extra-index-url https://__token__:pypiAgEIcHlwaQ@pypi.example.com/simple/",
     f"--extra-index-url https://__token__:{R}@pypi.example.com/simple/"),
    ("-i https://u:p@nexus/simple", f"-i https://u:{R}@nexus/simple"),
    # a token as the user name alone, in a VCS or direct URL
    ("git+https://glpat-AbCdEf123456@gitlab.example.com/org/lib.git@v1.2#egg=lib",
     f"git+https://{R}@gitlab.example.com/org/lib.git@v1.2#egg=lib"),
    ("mylib @ https://abcdef0123456789@files.example.com/mylib-1.0-py3-none-any.whl",
     f"mylib @ https://{R}@files.example.com/mylib-1.0-py3-none-any.whl"),
    (f"git+https://{GHP}@github.com/org/lib.git", f"git+https://{R}@github.com/org/lib.git"),
    # other lockfiles keep registry credentials in URLs too
    ("  remote: https://user:pass@gems.contribsys.com/", f"  remote: https://user:{R}@gems.contribsys.com/"),
    ('  "resolved": "https://u:p@registry.example.com/x/-/x-1.0.0.tgz",',
     f'  "resolved": "https://u:{R}@registry.example.com/x/-/x-1.0.0.tgz",'),
    # a bare token by its prefix
    (f"# {GHP}", f"# ghp_{R}"),
])
def test_lockfile_patterns_redact(text, expected):
    assert mcp_ssh.redact_secrets(text, mcp_ssh.LOCKFILE_SECRET_PATTERNS)[0] == expected


@pytest.mark.parametrize("text", [
    # package names and versions the general rules would break
    "secretstorage==3.3.3",
    "tokenizers==0.15.0",
    "django-password-reset==1.0 --hash=sha256:0123abcd",
    '    "node_modules/js-tokens": {',
    'name = "keyring"\nversion = "25.0"',
    # ${VAR} placeholders are filled in by pip from the environment: not secrets
    "-i https://deploy:${PIP_TOKEN}@nexus.example.com/simple",
    "--index-url https://${PIP_USER}:${PIP_PASSWORD}@nexus.example.com/simple",
    "git+https://${GITHUB_TOKEN}@github.com/org/lib.git",
    # an ssh user name, a git ref after @, scoped npm packages
    "git+ssh://git@github.com/org/repo.git",
    "git+https://github.com/org/lib.git@v1.2#egg=lib",
    '  "resolved": "https://registry.npmjs.org/@babel/core/-/core-7.0.0.tgz",',
    '  resolved "https://registry.yarnpkg.com/@babel/core/-/core-7.0.0.tgz#abc"',
    "  remote: https://rubygems.org/",
])
def test_lockfile_patterns_keep_lockfiles_intact(text):
    assert mcp_ssh.redact_secrets(text, mcp_ssh.LOCKFILE_SECRET_PATTERNS) == (text, 0)


LOCKFILE_OUTPUT = (
    "===== /srv/app/requirements.txt (120 bytes) =====\n"
    "--index-url https://deploy:s3cret@pypi.example.com/simple\n"
    "secretstorage==3.3.3\n"
    "tokenizers==0.15.0\n"
)


def test_lockfiles_with_contents_use_the_lockfile_patterns(mock_run_ssh_command):
    mock_run_ssh_command.return_value = {
        "ok": True, "host": "h", "collected_at_utc": "t",
        "data": {"command": "c", "exit_code": 0, "stdout": LOCKFILE_OUTPUT, "stderr": ""},
    }
    result = mcp_ssh.get_lockfiles(host="h", user="u", abs_paths=["/srv/app"], include_contents=True)
    assert result["data"]["stdout"] == LOCKFILE_OUTPUT.replace("s3cret", R)
    assert result["redaction"] == {"replaced": 1, "note": mcp_ssh.REDACTION_NOTE}


def test_lockfiles_listing_is_not_redacted(mock_run_ssh_command):
    # without include_contents the output is `ls -l` of the files found: names, no contents
    assert "redaction" not in mcp_ssh.get_lockfiles(host="h", user="u", abs_paths=["/srv/app"])
