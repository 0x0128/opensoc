from __future__ import annotations

import base64
import subprocess
from unittest.mock import MagicMock

import pytest

from opensoc_hunting.emulation.executor import (
    AtomicExecutor,
    RemoteSession,
    encode_command,
    ps_quote,
)
from opensoc_hunting.emulation.scenarios import load_scenarios


@pytest.fixture(scope="module")
def by_id():
    return {s.id: s for s in load_scenarios()}


def test_ps_quote_escapes_quotes_including_typographic_ones():
    assert ps_quote("abc") == "'abc'"
    assert ps_quote("it's") == "'it''s'"
    assert ps_quote("a\u2019b") == "'a\u2019\u2019b'"
    assert ps_quote("$(Remove-Item C:\\)") == "'$(Remove-Item C:\\)'"


def test_encode_command_is_utf16le_base64():
    script = "Write-Host 'hello ñ €'"  # non-ASCII on purpose
    assert base64.b64decode(encode_command(script)).decode("utf-16-le") == script


def test_local_script_with_input_args(by_id):
    executor = AtomicExecutor(atomics_path="C:\\AtomicRedTeam\\atomics", test_timeout=60)
    script = executor.build_script(by_id["EMU-06"], "run", {"remote_file": "http://srv.lab.local/x.txt"})
    assert "Import-Module 'Invoke-AtomicRedTeam' -Force" in script
    assert (
        "Invoke-AtomicTest 'T1105' -TestGuids 'dd3b61dd-7bbc-48cd-ab51-49ad1a776df0'"
        " -PathToAtomicsFolder 'C:\\AtomicRedTeam\\atomics'"
        " -InputArgs @{ 'remote_file' = 'http://srv.lab.local/x.txt' } -TimeoutSeconds 60"
    ) in script
    assert "-Session" not in script


def test_input_args_from_catalog_and_override(by_id):
    executor = AtomicExecutor()
    script = executor.build_script(by_id["EMU-07"], "run")
    assert "@{ 'username' = 'evil_user' }" in script
    script = executor.build_script(by_id["EMU-07"], "cleanup", {"username": "other"})
    assert "@{ 'username' = 'other' }" in script and script.rstrip().endswith("-Cleanup")
    assert "-TimeoutSeconds" not in script


def test_injection_in_input_args_stays_quoted(by_id):
    payload = "x'; Remove-Item -Recurse C:\\; '"
    script = AtomicExecutor().build_script(by_id["EMU-06"], "run", {"remote_file": payload})
    assert "'remote_file' = 'x''; Remove-Item -Recurse C:\\; '''" in script


@pytest.mark.parametrize(
    "action, switch",
    [("prereqs", "-GetPrereqs"), ("check-prereqs", "-CheckPrereqs"), ("cleanup", "-Cleanup")],
)
def test_actions(by_id, action, switch):
    script = AtomicExecutor().build_script(by_id["EMU-01"], action)
    assert script.rstrip().endswith(switch)


def test_unknown_action(by_id):
    with pytest.raises(ValueError):
        AtomicExecutor().build_script(by_id["EMU-01"], "delete-everything")


def test_remote_session_ssh_and_winrm(by_id):
    ssh = AtomicExecutor(remote=RemoteSession("ubuntu-lab", "purple", "ssh")).build_script(by_id["EMU-08"])
    assert "$s = New-PSSession -HostName 'ubuntu-lab' -UserName 'purple'" in ssh
    assert "-Session $s" in ssh and "Remove-PSSession $s" in ssh
    winrm = AtomicExecutor(remote=RemoteSession("win10-lab", None, "winrm")).build_script(by_id["EMU-01"])
    assert "New-PSSession -ComputerName 'win10-lab'" in winrm
    with pytest.raises(ValueError):
        RemoteSession("h", transport="telnet")


def test_run_calls_pwsh_with_encoded_command(by_id):
    runner = MagicMock(return_value=subprocess.CompletedProcess([], 0, stdout="ok", stderr=""))
    executor = AtomicExecutor(shell="pwsh", runner=runner)
    result = executor.run(by_id["EMU-01"])
    assert result.ok and result.stdout == "ok"
    cmd = runner.call_args.args[0]
    assert cmd[:3] == ["pwsh", "-NoProfile", "-NonInteractive"]
    assert cmd[-2] == "-EncodedCommand"
    decoded = base64.b64decode(cmd[-1]).decode("utf-16-le")
    assert "a538de64-1c74-46ed-aa60-b995ed302598" in decoded
    assert runner.call_args.kwargs["capture_output"] is True


def test_windows_powershell_uses_execution_policy_bypass():
    cmd = AtomicExecutor(shell="powershell.exe").command("Get-Date")
    assert "-ExecutionPolicy" in cmd and "Bypass" in cmd


def test_run_without_pwsh_and_timeout(by_id):
    def missing(*a, **k):
        raise FileNotFoundError

    assert AtomicExecutor(runner=missing).run(by_id["EMU-01"]).returncode == 127

    def slow(*a, **k):
        raise subprocess.TimeoutExpired(cmd="pwsh", timeout=1)

    result = AtomicExecutor(runner=slow, process_timeout=1).run(by_id["EMU-01"])
    assert result.returncode == 124 and not result.ok
