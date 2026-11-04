"""Launching Atomic Red Team tests with Invoke-AtomicRedTeam (PowerShell).

The PowerShell script is passed with -EncodedCommand so that it does not depend on
the shell's quoting. To run on another host a PSSession (SSH or WinRM) is used, which
Invoke-AtomicTest supports through -Session.
"""

from __future__ import annotations

import base64
import os
import subprocess
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass

from .scenarios import Scenario

ACTIONS = ("run", "prereqs", "check-prereqs", "cleanup")
_ACTION_SWITCH = {"run": "", "prereqs": " -GetPrereqs", "check-prereqs": " -CheckPrereqs", "cleanup": " -Cleanup"}
# PowerShell also treats typographic single quotes as delimiters.
_PS_SINGLE_QUOTES = ("'", "‘", "’", "‚", "‛")


def ps_quote(value: str) -> str:
    """Single-quoted PowerShell string literal (no expansion)."""
    escaped = str(value)
    for quote in _PS_SINGLE_QUOTES:
        escaped = escaped.replace(quote, quote * 2)
    return f"'{escaped}'"


def ps_hashtable(values: Mapping[str, str]) -> str:
    items = "; ".join(f"{ps_quote(k)} = {ps_quote(v)}" for k, v in values.items())
    return "@{ " + items + " }"


def encode_command(script: str) -> str:
    """Format expected by -EncodedCommand: Base64 of UTF-16LE."""
    return base64.b64encode(script.encode("utf-16-le")).decode("ascii")


@dataclass(frozen=True)
class RemoteSession:
    host: str
    user: str | None = None
    transport: str = "ssh"  # ssh | winrm

    def __post_init__(self):
        if self.transport not in {"ssh", "winrm"}:
            raise ValueError("transport must be 'ssh' or 'winrm'")
        if not self.host:
            raise ValueError("empty host")

    def new_session_cmd(self) -> str:
        if self.transport == "ssh":
            cmd = f"New-PSSession -HostName {ps_quote(self.host)}"
            if self.user:
                cmd += f" -UserName {ps_quote(self.user)}"
            return cmd
        cmd = f"New-PSSession -ComputerName {ps_quote(self.host)}"
        if self.user:
            cmd += f" -Credential (Get-Credential -UserName {ps_quote(self.user)} -Message 'OpenSOC lab')"
        return cmd


@dataclass
class ExecResult:
    action: str
    returncode: int
    stdout: str
    stderr: str
    duration: float

    @property
    def ok(self) -> bool:
        return self.returncode == 0


Runner = Callable[..., subprocess.CompletedProcess]


class AtomicExecutor:
    def __init__(
        self,
        shell: str = "pwsh",
        module: str = "Invoke-AtomicRedTeam",
        atomics_path: str | None = None,
        remote: RemoteSession | None = None,
        test_timeout: int = 120,
        process_timeout: int = 900,
        runner: Runner = subprocess.run,
    ):
        self.shell = shell
        self.module = module
        self.atomics_path = atomics_path
        self.remote = remote
        self.test_timeout = test_timeout
        self.process_timeout = process_timeout
        self._runner = runner

    def build_script(
        self, scenario: Scenario, action: str = "run", input_args: Mapping[str, str] | None = None
    ) -> str:
        if action not in ACTIONS:
            raise ValueError(f"unknown action {action!r}; use one of {ACTIONS}")
        args = {**scenario.atomic.input_args, **(input_args or {})}
        invoke = (
            f"Invoke-AtomicTest {ps_quote(scenario.atomic.technique)}"
            f" -TestGuids {ps_quote(scenario.atomic.guid)}"
        )
        if self.atomics_path:
            invoke += f" -PathToAtomicsFolder {ps_quote(self.atomics_path)}"
        if args and action != "check-prereqs":
            invoke += f" -InputArgs {ps_hashtable(args)}"
        if action == "run":
            invoke += f" -TimeoutSeconds {int(self.test_timeout)}"
        invoke += _ACTION_SWITCH[action]

        lines = [
            "$ErrorActionPreference = 'Stop'",
            "$ProgressPreference = 'SilentlyContinue'",
            f"Import-Module {ps_quote(self.module)} -Force",
        ]
        if self.remote:
            lines += [
                f"$s = {self.remote.new_session_cmd()}",
                "try {",
                f"    {invoke} -Session $s",
                "} finally {",
                "    Remove-PSSession $s",
                "}",
            ]
        else:
            lines.append(invoke)
        return "\n".join(lines) + "\n"

    def command(self, script: str) -> list[str]:
        cmd = [self.shell, "-NoProfile", "-NonInteractive"]
        if os.name == "nt" or os.path.basename(self.shell).lower().startswith("powershell"):
            cmd += ["-ExecutionPolicy", "Bypass"]
        return cmd + ["-EncodedCommand", encode_command(script)]

    def run(
        self, scenario: Scenario, action: str = "run", input_args: Mapping[str, str] | None = None
    ) -> ExecResult:
        script = self.build_script(scenario, action, input_args)
        started = time.monotonic()
        try:
            proc = self._runner(
                self.command(script),
                capture_output=True,
                text=True,
                timeout=self.process_timeout,
                check=False,
            )
        except FileNotFoundError:
            return ExecResult(action, 127, "", f"'{self.shell}' not found. Install PowerShell 7 (pwsh).", 0.0)
        except subprocess.TimeoutExpired as exc:
            return ExecResult(
                action, 124, str(exc.stdout or ""), f"timed out after {self.process_timeout}s", self.process_timeout
            )
        return ExecResult(action, proc.returncode, proc.stdout or "", proc.stderr or "", time.monotonic() - started)
