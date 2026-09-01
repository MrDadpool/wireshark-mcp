"""Configuration and the hard ceilings the model cannot raise."""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass
from pathlib import Path

from .errors import ErrorKind, ToolError
from .platform import current_system

MAX_DURATION_S = 300
MAX_PACKETS = 100_000
MAX_LIMIT = 500


def default_workdir(system: str | None = None) -> Path:
    system = system or current_system()
    if system == "Windows":
        base = os.environ.get("LOCALAPPDATA")
        if base:
            return Path(base) / "wireshark-mcp"
        return Path.home() / "AppData" / "Local" / "wireshark-mcp"
    return Path.home() / ".wireshark-mcp"


@dataclass(frozen=True)
class Config:
    workdir: Path
    read_only_dirs: tuple[Path, ...] = ()
    interface_allowlist: tuple[str, ...] = ()
    tshark_path: str | None = None
    dumpcap_path: str | None = None
    capinfos_path: str | None = None
    dftest_path: str | None = None


def load_config(path: Path | None = None, system: str | None = None) -> Config:
    """Load config.toml. A missing file is not an error; defaults apply."""
    system = system or current_system()
    workdir = default_workdir(system)
    path = path or (workdir / "config.toml")

    if not path.is_file():
        return Config(workdir=workdir)

    with path.open("rb") as handle:
        data = tomllib.load(handle)

    binaries = data.get("binaries", {})
    return Config(
        workdir=Path(data.get("workdir", workdir)).expanduser(),
        read_only_dirs=tuple(Path(p).expanduser() for p in data.get("read_only_dirs", [])),
        interface_allowlist=tuple(data.get("interface_allowlist", [])),
        tshark_path=binaries.get("tshark"),
        dumpcap_path=binaries.get("dumpcap"),
        capinfos_path=binaries.get("capinfos"),
        dftest_path=binaries.get("dftest"),
    )


def clamp(value: object, ceiling: int, name: str) -> int:
    """Return value as an int, or raise if it is not integral or is outside 1..ceiling.

    Never silently truncates: a fractional value is rejected rather than floored,
    because a bound that quietly changes what the caller asked for is worse than
    one that refuses.
    """
    try:
        coerced = int(value)  # type: ignore[call-overload]
    except (TypeError, ValueError, OverflowError) as exc:
        raise ToolError(
            ErrorKind.LIMIT_EXCEEDED,
            f"{name} must be an integer, got {value!r}",
        ) from exc

    if isinstance(value, float) and coerced != value:
        raise ToolError(
            ErrorKind.LIMIT_EXCEEDED,
            f"{name} must be a whole number, got {value!r}",
        )

    if coerced < 1:
        raise ToolError(ErrorKind.LIMIT_EXCEEDED, f"{name} must be at least 1, got {coerced}")
    if coerced > ceiling:
        raise ToolError(
            ErrorKind.LIMIT_EXCEEDED,
            f"{name} must be at most {ceiling}, got {coerced}",
            hint=f"Retry with {name} <= {ceiling}.",
        )
    return coerced
