"""OS-specific resolution of Wireshark binaries and capture interfaces."""

from __future__ import annotations

import getpass
import os
import platform as _platform
import re
import shutil
from dataclasses import dataclass
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
    path_env: str | None = None,  # test seam: overrides PATH lookup for shutil.which
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


_INTERFACE_LINE = re.compile(r"^\s*\d+\.\s+(?P<id>\S+)(?:\s+\((?P<desc>.*)\))?\s*$")


@dataclass(frozen=True)
class Interface:
    id: str
    description: str
    loopback: bool


def _is_loopback(iface_id: str, description: str) -> bool:
    return iface_id in {"lo", "lo0"} or "loopback" in description.lower()


def parse_interfaces(output: str) -> list[Interface]:
    """Parse `dumpcap -D` output. Unrecognized lines are skipped, not an error."""
    interfaces: list[Interface] = []
    for line in output.splitlines():
        match = _INTERFACE_LINE.match(line)
        if not match:
            continue
        iface_id = match.group("id")
        description = match.group("desc") or ""
        interfaces.append(
            Interface(
                id=iface_id,
                description=description,
                loopback=_is_loopback(iface_id, description),
            )
        )
    return interfaces


def capture_permitted(system: str | None = None) -> tuple[bool, str]:
    """Best-effort check of whether live capture will work without elevation."""
    system = system or current_system()
    if system == "Darwin":
        import grp

        try:
            members = set(grp.getgrnam("access_bpf").gr_mem)
        except KeyError:
            return False, (
                "ChmodBPF is not installed, so /dev/bpf* is root-only. "
                "Install Wireshark's ChmodBPF component and log out and back in."
            )
        user = getpass.getuser()
        if user in members or os.geteuid() == 0:
            return True, "BPF access available via the access_bpf group."
        return False, (
            f"user {user!r} is not in the access_bpf group. "
            "Run Wireshark's 'Install ChmodBPF' and log out and back in."
        )
    if system == "Windows":
        return True, (
            "Npcap must be installed. If it was installed with "
            "'Restrict Npcap driver's access to Administrators only', this server "
            "must run elevated to capture."
        )
    return True, "Capture permission not checked on this platform."
