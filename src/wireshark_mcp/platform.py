"""OS-specific resolution of Wireshark binaries and capture interfaces."""

from __future__ import annotations

import os
import platform as _platform
import shutil
from pathlib import Path

from .errors import ErrorKind, ToolError

_INSTALL_HINTS = {
    "Darwin": "Install Wireshark's CLI tools: brew install --cask wireshark "
    "(also installs ChmodBPF, required for capture without root).",
    "Windows": "Install Wireshark from https://www.wireshark.org/download.html, "
    "including Npcap.",
}
_DEFAULT_HINT = "Install Wireshark so that tshark and dumpcap are on PATH."


def current_system() -> str:
    return _platform.system()


def install_hint(system: str | None = None) -> str:
    return _INSTALL_HINTS.get(system or current_system(), _DEFAULT_HINT)


INSTALL_HINT = install_hint()


def candidate_dirs(system: str) -> list[Path]:
    if system == "Darwin":
        return [
            Path("/Applications/Wireshark.app/Contents/MacOS"),
            Path("/opt/homebrew/bin"),
            Path("/usr/local/bin"),
        ]
    if system == "Windows":
        roots = [
            os.environ.get("ProgramFiles", r"C:\Program Files"),
            os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
        ]
        return [Path(r) / "Wireshark" for r in roots if r]
    return [Path("/usr/bin"), Path("/usr/local/bin")]


def _filename(name: str, system: str) -> str:
    return f"{name}.exe" if system == "Windows" else name


def find_binary(
    name: str,
    system: str | None = None,
    path_env: str | None = None,
    override: str | None = None,
) -> Path:
    """Resolve a Wireshark binary. Order: override, PATH, known install dirs."""
    system = system or current_system()
    filename = _filename(name, system)

    if override:
        candidate = Path(override)
        if candidate.is_file():
            return candidate
        raise ToolError(
            ErrorKind.BINARY_MISSING,
            f"configured path for {name} does not exist: {override}",
            hint="Fix or remove the binary override in config.toml.",
        )

    on_path = shutil.which(filename, path=path_env)
    if on_path:
        return Path(on_path)

    for directory in candidate_dirs(system):
        candidate = directory / filename
        if candidate.is_file():
            return candidate

    raise ToolError(
        ErrorKind.BINARY_MISSING,
        f"could not find {name} on this system",
        hint=install_hint(system),
    )
