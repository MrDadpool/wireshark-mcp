"""The only place this codebase spawns a subprocess. shell=False, always."""

from __future__ import annotations

import os
import signal
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .errors import ErrorKind, ToolError

_PERMISSION_MARKERS = ("permission denied", "you don't have permission", "operation not permitted")


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


def _kill_process_group(popen: subprocess.Popen) -> None:
    """Kill the child and anything it spawned. Falls back to the child alone."""
    try:
        os.killpg(os.getpgid(popen.pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError, AttributeError, OSError):
        # AttributeError: killpg/getpgid are absent on Windows.
        popen.kill()


def run_command(argv: list[str | Path], timeout_s: int) -> CommandResult:
    args = [str(a) for a in argv]
    # start_new_session puts the child in its own process group, so a timeout
    # can kill the whole group rather than orphaning any helper it spawned.
    try:
        popen = subprocess.Popen(  # argv built in code, never from the model
            args,
            shell=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
    except FileNotFoundError as exc:
        raise ToolError(
            ErrorKind.BINARY_MISSING,
            f"executable not found: {args[0]}",
            hint="Install Wireshark, or set the binary path in config.toml.",
        ) from exc

    try:
        stdout, stderr = popen.communicate(timeout=timeout_s)
    except subprocess.TimeoutExpired as exc:
        _kill_process_group(popen)
        popen.communicate()
        raise ToolError(
            ErrorKind.CAPTURE_FAILED,
            f"{args[0]} exceeded its {timeout_s}s timeout",
        ) from exc

    return CommandResult(popen.returncode, stdout, stderr)


def check(result: CommandResult, kind: ErrorKind, what: str) -> CommandResult:
    if result.returncode == 0:
        return result
    stderr = result.stderr.strip()
    if any(marker in stderr.lower() for marker in _PERMISSION_MARKERS):
        raise ToolError(
            ErrorKind.PERMISSION_DENIED,
            f"{what} was denied by the OS: {stderr}",
            hint="On macOS install ChmodBPF; on Windows check Npcap's admin restriction.",
        )
    raise ToolError(kind, f"{what} failed (exit {result.returncode}): {stderr}")
