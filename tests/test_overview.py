"""Tests for get_host_overview: every section is exactly what its source tool sends."""
import asyncio
import inspect

import pytest

import mcp_ssh

SECTIONS = mcp_ssh.HOST_OVERVIEW_SECTIONS


def _ok(stdout="out", exit_code=0, **extra):
    return {"ok": exit_code == 0, "host": "h", "collected_at_utc": "t",
            "data": {"command": "c", "exit_code": exit_code, "stdout": stdout, "stderr": "", **extra}}


# ============================================================
# Sections and their source tools cannot drift apart
# ============================================================

@pytest.mark.parametrize("name, tool, cmd", SECTIONS, ids=[s[0] for s in SECTIONS])
def test_section_sends_what_its_tool_sends(name, tool, cmd, mock_run_ssh_command):
    getattr(mcp_ssh, tool)(host="h", user="u")
    assert mock_run_ssh_command.call_args[0][2] == cmd


def test_source_tools_are_registered_tools():
    registered = {t.name for t in asyncio.run(mcp_ssh.mcp.list_tools())}
    assert "get_host_overview" in registered
    assert {tool for _, tool, _ in SECTIONS} <= registered


def test_section_names_are_unique():
    names = [name for name, _, _ in SECTIONS]
    assert len(names) == len(set(names))


def test_docstring_lists_every_section_with_its_tool():
    doc = " ".join(mcp_ssh.get_host_overview.__doc__.split())
    for name, tool, _ in SECTIONS:
        assert f"{name} ({tool}" in doc


def test_each_section_uses_its_tools_default_timeout(mock_run_ssh_command):
    mcp_ssh.get_host_overview(host="h", user="u")
    expected = [inspect.signature(getattr(mcp_ssh, tool)).parameters["timeout"].default for _, tool, _ in SECTIONS]
    assert [c.args[6] for c in mock_run_ssh_command.call_args_list] == expected
    assert set(expected) == {mcp_ssh.TIMEOUT_DEFAULT_S}


# ============================================================
# The call
# ============================================================

def test_runs_every_section_in_order_with_the_callers_parameters(mock_run_ssh_command):
    mcp_ssh.get_host_overview(host="h", user="u", port=2222, password="pw", key_path="/k",
                              timeout=7, accept_new_hostkey=True)
    # a given timeout replaces every tool's default
    assert [c.args for c in mock_run_ssh_command.call_args_list] == [
        ("h", "u", cmd, 2222, "pw", "/k", 7, True) for _, _, cmd in SECTIONS
    ]


def test_result_shape(mock_run_ssh_command):
    mock_run_ssh_command.side_effect = [_ok(f"out {i}") for i in range(len(SECTIONS))]
    result = mcp_ssh.get_host_overview(host="h", user="u")
    assert result["ok"] is True
    assert result["host"] == "h"
    assert "collected_at_utc" in result
    sections = result["data"]["sections"]
    assert list(sections) == [name for name, _, _ in SECTIONS]
    first = sections["hostname"]
    assert set(first) == {"source_tool", "ok", "exit_code", "stdout", "stderr", "seconds"}
    assert (first["source_tool"], first["ok"], first["exit_code"], first["stdout"]) == ("get_hostname", True, 0, "out 0")
    assert sections["journal_errors"]["stdout"] == f"out {len(SECTIONS) - 1}"


def test_a_failing_section_does_not_stop_the_others(mock_run_ssh_command):
    results = [_ok() for _ in SECTIONS]
    failed = [name for name, _, _ in SECTIONS].index("failed_units")
    results[failed] = _ok("", exit_code=127)
    results[failed]["data"]["stderr"] = "sh: systemctl: not found"
    mock_run_ssh_command.side_effect = results
    result = mcp_ssh.get_host_overview(host="h", user="u")
    assert result["ok"] is True  # the host was reachable: a section's failure is a fact
    section = result["data"]["sections"]["failed_units"]
    assert (section["ok"], section["exit_code"], section["stderr"]) == (False, 127, "sh: systemctl: not found")
    assert result["data"]["sections"]["journal_errors"]["ok"] is True


def test_timeout_and_error_of_a_section_are_kept(mock_run_ssh_command):
    results = [_ok() for _ in SECTIONS]
    results[0] = _ok("partial", exit_code=124, timed_out=True)
    results[0]["error"] = "The command probably timed out"
    mock_run_ssh_command.side_effect = results
    section = mcp_ssh.get_host_overview(host="h", user="u")["data"]["sections"]["hostname"]
    assert section["timed_out"] is True
    assert section["error"] == "The command probably timed out"
    assert section["stdout"] == "partial"


def test_no_connection_returns_that_error_as_is(mock_run_ssh_command):
    mock_run_ssh_command.return_value = {"ok": False, "error": "Authentication failed."}
    assert mcp_ssh.get_host_overview(host="h", user="u") == {"ok": False, "error": "Authentication failed."}
    assert mock_run_ssh_command.call_count == 1


def test_connection_lost_midway_stops_with_what_was_collected(mock_run_ssh_command):
    mock_run_ssh_command.side_effect = [_ok(), _ok(), {"ok": False, "error": "Network error: x"}]
    result = mcp_ssh.get_host_overview(host="h", user="u")
    assert result["ok"] is False
    assert list(result["data"]["sections"]) == ["hostname", "os_release"]
    assert result["error"] == ("Section kernel could not be collected, so the overview stopped there: "
                               "Network error: x")
    assert mock_run_ssh_command.call_count == 3


@pytest.mark.parametrize("timeout", [0, -1, 361, "20", 2.5, True])
def test_invalid_timeout(timeout, mock_run_ssh_command):
    assert mcp_ssh.get_host_overview(host="h", user="u", timeout=timeout) == {
        "ok": False, "error": mcp_ssh.HOST_OVERVIEW_TIMEOUT_ERROR}
    mock_run_ssh_command.assert_not_called()


@pytest.mark.parametrize("timeout", [1, 360])
def test_timeout_bounds(timeout, mock_run_ssh_command):
    assert mcp_ssh.get_host_overview(host="h", user="u", timeout=timeout)["ok"] is True


# ============================================================
# Redaction: a section is redacted exactly when its source tool is
# ============================================================

SECRET_TEXT = "x --password=hunter2 //fs/s /m cifs user=bob%S3c,vers=3.0 0 0"


def _tool_result(tool, mocker):
    mock = mocker.patch("mcp_ssh.run_ssh_command", return_value=_ok(SECRET_TEXT))
    result = getattr(mcp_ssh, tool)(host="h", user="u")
    mocker.stop(mock)
    return result


def test_redacted_sections_are_those_whose_tool_redacts(mocker):
    expected = {tool for _, tool, _ in SECTIONS if "redaction" in _tool_result(tool, mocker)}
    assert set(mcp_ssh.HOST_OVERVIEW_REDACTED_TOOLS) == expected
    assert expected == {"get_mount_problems", "get_ps_aux_top_cpu_consumers",
                        "get_ps_aux_top_mem_consumers", "get_journal_errors"}


def test_sections_are_redacted_like_their_tools(mocker):
    """Same text in, same text out: a section redacts with its tool's patterns."""
    tool_stdout = {tool: _tool_result(tool, mocker)["data"]["stdout"] for _, tool, _ in SECTIONS}
    mocker.patch("mcp_ssh.run_ssh_command", side_effect=[_ok(SECRET_TEXT) for _ in SECTIONS])
    result = mcp_ssh.get_host_overview(host="h", user="u")
    for name, tool, _ in SECTIONS:
        section = result["data"]["sections"][name]
        assert section["stdout"] == tool_stdout[tool], name
        if tool in mcp_ssh.HOST_OVERVIEW_REDACTED_TOOLS:
            assert "hunter2" not in section["stdout"], name
            assert section["redaction_replaced"] >= 1, name
        else:
            assert section["stdout"] == SECRET_TEXT, name
            assert "redaction_replaced" not in section, name
    assert "S3c" not in result["data"]["sections"]["mount_problems"]["stdout"]
    assert result["data"]["redaction_note"] == mcp_ssh.REDACTION_NOTE
