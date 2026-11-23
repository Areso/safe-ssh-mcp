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
    text = "before\n-----BEGIN RSA PRIVATE KEY-----\nMIIEow\nAAAA\n-----END RSA PRIVATE KEY-----\nafter"
    assert mcp_ssh.redact_secrets(text) == (
        f"before\n-----BEGIN RSA PRIVATE KEY-----{R}-----END RSA PRIVATE KEY-----\nafter", 1
    )


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
