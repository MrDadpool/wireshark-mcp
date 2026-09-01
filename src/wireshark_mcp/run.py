"""The only place this codebase spawns a subprocess. shell=False, always."""

from __future__ import annotations

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


def run_command(argv: list[str | Path], timeout_s: int) -> CommandResult:
    args = [str(a) for a in argv]
    try:
        # argv built in code, never from the model
        completed = subprocess.run(
            args,
            shell=False,
            capture_output=True,
            text=True,
            timeout=timeout_s,
            check=False,
        )
    except FileNotFoundError as exc:
        raise ToolError(
            ErrorKind.BINARY_MISSING,
            f"executable not found: {args[0]}",
            hint="Install Wireshark, or set the binary path in config.toml.",
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise ToolError(
            ErrorKind.CAPTURE_FAILED,
            f"{args[0]} exceeded its {timeout_s}s timeout",
        ) from exc
    return CommandResult(completed.returncode, completed.stdout, completed.stderr)


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
