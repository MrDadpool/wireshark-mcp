# wireshark-mcp Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build an MCP server that lets a local LLM client (LM Studio) enumerate network interfaces, run bounded live packet captures, and read/filter/summarize capture files through Wireshark's CLI tools.

**Architecture:** A single Python process speaking MCP over stdio. Four layers, bottom-up: `platform.py` resolves binaries and normalizes interfaces per OS; `store.py` owns the workdir and is the sole authority on file paths; `tshark.py` builds and runs read/statistics argv; `capture.py` builds and runs bounded `dumpcap` argv; `server.py` exposes them as MCP tools, resources, and prompts. Argv construction is separated from subprocess execution everywhere so the bulk of the test suite runs with no Wireshark installed.

**Tech Stack:** Python 3.11+, `mcp` SDK (FastMCP), `uv`/`uvx`, pytest, ruff. Stdlib `subprocess` and `tomllib` — no other runtime dependencies.

**Spec:** `docs/superpowers/specs/2026-09-01-wireshark-mcp-design.md`

## Global Constraints

- Python `>=3.11` (needs stdlib `tomllib`).
- Runtime dependencies: `mcp` only. Dev dependencies: `pytest`, `ruff`. Nothing else.
- macOS and Windows are both first-class. Every path operation uses `pathlib`; no hardcoded `/` separators.
- **Every** subprocess call is `subprocess.run(argv_list, shell=False, ...)`. `shell=True` must appear nowhere in the codebase.
- The model never supplies a flag. It supplies typed values that land in fixed argv positions.
- No `run_tshark` tool or any other arbitrary-argument escape hatch.
- Hard ceilings, enforced server-side, not overridable by a tool argument: `duration_s <= 300`, `max_packets <= 100_000`, `limit <= 500`.
- Every tool returns a structured error dict rather than raising. Error kinds: `binary_missing`, `permission_denied`, `bad_interface`, `bad_filter`, `path_rejected`, `limit_exceeded`, `capture_failed`, `not_found`.
- Package name `wireshark-mcp`, module `wireshark_mcp`, console script `wireshark-mcp`.
- Repo `MrDadpool/wireshark-mcp`. Commit trailer on every commit:
  `Claude-Session: https://claude.ai/code/session_01VUC66Mkn8NR63wjmvVpiGd`

---

### Task 1: Project scaffold and error model

**Files:**
- Create: `pyproject.toml`
- Create: `src/wireshark_mcp/__init__.py`
- Create: `src/wireshark_mcp/errors.py`
- Create: `tests/__init__.py`
- Test: `tests/test_errors.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `ErrorKind` (a `str`-valued `enum.StrEnum` with members `BINARY_MISSING`, `PERMISSION_DENIED`, `BAD_INTERFACE`, `BAD_FILTER`, `PATH_REJECTED`, `LIMIT_EXCEEDED`, `CAPTURE_FAILED`, `NOT_FOUND`, whose values are the lowercase strings listed in Global Constraints); `ToolError(Exception)` with `__init__(self, kind: ErrorKind, message: str, hint: str = "")` and attributes `.kind`, `.message`, `.hint`; `error_dict(exc: ToolError) -> dict[str, str]` returning `{"error": message, "kind": kind_value, "hint": hint}`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_errors.py
import pytest

from wireshark_mcp.errors import ErrorKind, ToolError, error_dict


def test_error_kind_values_are_lowercase_strings():
    assert ErrorKind.BINARY_MISSING == "binary_missing"
    assert ErrorKind.PATH_REJECTED == "path_rejected"


def test_error_dict_shape():
    exc = ToolError(ErrorKind.BAD_FILTER, "bad display filter", hint="check syntax")
    assert error_dict(exc) == {
        "error": "bad display filter",
        "kind": "bad_filter",
        "hint": "check syntax",
    }


def test_error_dict_hint_defaults_to_empty():
    exc = ToolError(ErrorKind.NOT_FOUND, "no such capture")
    assert error_dict(exc)["hint"] == ""


def test_tool_error_is_raisable_and_carries_kind():
    with pytest.raises(ToolError) as caught:
        raise ToolError(ErrorKind.LIMIT_EXCEEDED, "too many packets")
    assert caught.value.kind is ErrorKind.LIMIT_EXCEEDED
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_errors.py -v`
Expected: FAIL — collection error, `ModuleNotFoundError: No module named 'wireshark_mcp'`

- [ ] **Step 3: Write the scaffold and minimal implementation**

```toml
# pyproject.toml
[project]
name = "wireshark-mcp"
version = "0.1.0"
description = "MCP server exposing Wireshark CLI tooling (tshark/dumpcap) to local LLM clients"
readme = "README.md"
requires-python = ">=3.11"
license = { text = "MIT" }
dependencies = ["mcp>=1.2.0"]

[project.scripts]
wireshark-mcp = "wireshark_mcp.server:main"

[project.optional-dependencies]
dev = ["pytest>=8.0", "ruff>=0.6"]

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["src/wireshark_mcp"]

[tool.pytest.ini_options]
testpaths = ["tests"]
markers = [
    "requires_tshark: needs a resolvable tshark binary",
    "requires_capture: needs live capture permission on this host",
]

[tool.ruff]
line-length = 100
```

```python
# src/wireshark_mcp/__init__.py
"""MCP server exposing Wireshark's CLI tooling to local LLM clients."""

__version__ = "0.1.0"
```

```python
# src/wireshark_mcp/errors.py
"""Structured errors. Tools return these as dicts; they never raise at the MCP boundary."""

from __future__ import annotations

from enum import StrEnum


class ErrorKind(StrEnum):
    BINARY_MISSING = "binary_missing"
    PERMISSION_DENIED = "permission_denied"
    BAD_INTERFACE = "bad_interface"
    BAD_FILTER = "bad_filter"
    PATH_REJECTED = "path_rejected"
    LIMIT_EXCEEDED = "limit_exceeded"
    CAPTURE_FAILED = "capture_failed"
    NOT_FOUND = "not_found"


class ToolError(Exception):
    """An error a tool can report to the model without crashing the server."""

    def __init__(self, kind: ErrorKind, message: str, hint: str = "") -> None:
        super().__init__(message)
        self.kind = kind
        self.message = message
        self.hint = hint


def error_dict(exc: ToolError) -> dict[str, str]:
    return {"error": exc.message, "kind": str(exc.kind), "hint": exc.hint}
```

Create `tests/__init__.py` as an empty file.

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_errors.py -v`
Expected: 4 passed

- [ ] **Step 5: Commit**

```bash
git add pyproject.toml src/wireshark_mcp/__init__.py src/wireshark_mcp/errors.py tests/__init__.py tests/test_errors.py
git commit -m "feat: project scaffold and structured error model

Claude-Session: https://claude.ai/code/session_01VUC66Mkn8NR63wjmvVpiGd"
```

---

### Task 2: Platform layer — binary resolution

**Files:**
- Create: `src/wireshark_mcp/platform.py`
- Test: `tests/test_platform_binaries.py`

**Interfaces:**
- Consumes: `ErrorKind`, `ToolError` from `wireshark_mcp.errors`.
- Produces: `INSTALL_HINT: str` (platform-appropriate install instruction); `candidate_dirs(system: str) -> list[Path]`; `find_binary(name: str, system: str | None = None, path_env: str | None = None, override: str | None = None) -> Path` raising `ToolError(ErrorKind.BINARY_MISSING, ...)` when unresolvable. `name` is the bare tool name (`"tshark"`, `"dumpcap"`, `"capinfos"`); the `.exe` suffix is added internally on Windows.

Resolution order: `override` → `PATH` (via `shutil.which`, honoring `path_env`) → `candidate_dirs(system)`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_platform_binaries.py
import pytest

from wireshark_mcp.errors import ErrorKind, ToolError
from wireshark_mcp.platform import candidate_dirs, find_binary


def test_windows_candidates_include_program_files():
    dirs = [str(p) for p in candidate_dirs("Windows")]
    assert any("Wireshark" in d for d in dirs)


def test_darwin_candidates_include_app_bundle_and_homebrew():
    dirs = [str(p) for p in candidate_dirs("Darwin")]
    assert any("Wireshark.app/Contents/MacOS" in d for d in dirs)
    assert any("homebrew" in d or "/usr/local/bin" in d for d in dirs)


def test_override_wins(tmp_path):
    exe = tmp_path / "tshark"
    exe.write_text("")
    exe.chmod(0o755)
    assert find_binary("tshark", system="Darwin", override=str(exe)) == exe


def test_override_that_does_not_exist_is_an_error(tmp_path):
    with pytest.raises(ToolError) as caught:
        find_binary("tshark", system="Darwin", override=str(tmp_path / "nope"))
    assert caught.value.kind is ErrorKind.BINARY_MISSING


def test_found_on_path(tmp_path):
    exe = tmp_path / "tshark"
    exe.write_text("")
    exe.chmod(0o755)
    assert find_binary("tshark", system="Darwin", path_env=str(tmp_path)) == exe


def test_windows_appends_exe_suffix(tmp_path):
    exe = tmp_path / "tshark.exe"
    exe.write_text("")
    exe.chmod(0o755)
    found = find_binary("tshark", system="Windows", path_env=str(tmp_path))
    assert found.name == "tshark.exe"


def test_missing_binary_raises_with_install_hint(tmp_path):
    with pytest.raises(ToolError) as caught:
        find_binary("tshark", system="Darwin", path_env=str(tmp_path))
    assert caught.value.kind is ErrorKind.BINARY_MISSING
    assert caught.value.hint
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_platform_binaries.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'wireshark_mcp.platform'`

- [ ] **Step 3: Write minimal implementation**

```python
# src/wireshark_mcp/platform.py
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_platform_binaries.py -v`
Expected: 7 passed

- [ ] **Step 5: Commit**

```bash
git add src/wireshark_mcp/platform.py tests/test_platform_binaries.py
git commit -m "feat: resolve Wireshark binaries per platform

Claude-Session: https://claude.ai/code/session_01VUC66Mkn8NR63wjmvVpiGd"
```

---

### Task 3: Platform layer — interface parsing and capture permission

**Files:**
- Modify: `src/wireshark_mcp/platform.py` (append; do not alter Task 2 functions)
- Test: `tests/test_platform_interfaces.py`

**Interfaces:**
- Consumes: `find_binary` from Task 2.
- Produces: `Interface` (a frozen dataclass with fields `id: str`, `description: str`, `loopback: bool`); `parse_interfaces(output: str) -> list[Interface]` parsing `dumpcap -D` text; `capture_permitted(system: str | None = None) -> tuple[bool, str]` returning `(ok, explanation)`.

`dumpcap -D` prints one interface per line as `N. id (description)`, where the description and its parentheses are absent when the OS supplies none. macOS ids look like `en0`; Windows ids look like `\Device\NPF_{GUID}`. An interface is loopback when its id is `lo` or `lo0`, or when its description contains `loopback` case-insensitively.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_platform_interfaces.py
from wireshark_mcp.platform import Interface, capture_permitted, parse_interfaces

MACOS_DUMPCAP_D = """1. en0 (Wi-Fi)
2. lo0 (Loopback)
3. awdl0
4. utun4
"""

WINDOWS_DUMPCAP_D = (
    "1. \\Device\\NPF_{A1B2C3D4-0000-1111-2222-333344445555} (Ethernet)\n"
    "2. \\Device\\NPF_Loopback (Adapter for loopback traffic capture)\n"
)


def test_parses_macos_output():
    ifaces = parse_interfaces(MACOS_DUMPCAP_D)
    assert [i.id for i in ifaces] == ["en0", "lo0", "awdl0", "utun4"]
    assert ifaces[0].description == "Wi-Fi"


def test_interface_with_no_description_parses():
    ifaces = parse_interfaces(MACOS_DUMPCAP_D)
    assert ifaces[2].id == "awdl0"
    assert ifaces[2].description == ""


def test_macos_loopback_detected_by_id():
    ifaces = parse_interfaces(MACOS_DUMPCAP_D)
    assert [i.id for i in ifaces if i.loopback] == ["lo0"]


def test_parses_windows_npf_ids_with_braces_intact():
    ifaces = parse_interfaces(WINDOWS_DUMPCAP_D)
    assert ifaces[0].id == "\\Device\\NPF_{A1B2C3D4-0000-1111-2222-333344445555}"
    assert ifaces[0].description == "Ethernet"


def test_windows_loopback_detected_by_description():
    ifaces = parse_interfaces(WINDOWS_DUMPCAP_D)
    assert ifaces[1].loopback is True


def test_blank_and_garbage_lines_are_skipped():
    assert parse_interfaces("\n\nnot an interface line\n1. en0 (Wi-Fi)\n") == [
        Interface(id="en0", description="Wi-Fi", loopback=False)
    ]


def test_capture_permitted_returns_bool_and_explanation():
    ok, why = capture_permitted(system="Darwin")
    assert isinstance(ok, bool)
    assert why
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_platform_interfaces.py -v`
Expected: FAIL — `ImportError: cannot import name 'Interface' from 'wireshark_mcp.platform'`

- [ ] **Step 3: Write minimal implementation**

Append to `src/wireshark_mcp/platform.py`, and add `import grp`, `import re`, and `from dataclasses import dataclass` to the existing imports (guard `grp` with `if _platform.system() != "Windows"` at the point of use — it is a Unix-only stdlib module, so import it lazily inside `capture_permitted`):

```python
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
        user = os.environ.get("USER", "")
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_platform_interfaces.py -v`
Expected: 7 passed

- [ ] **Step 5: Commit**

```bash
git add src/wireshark_mcp/platform.py tests/test_platform_interfaces.py
git commit -m "feat: parse dumpcap interfaces and check capture permission

Claude-Session: https://claude.ai/code/session_01VUC66Mkn8NR63wjmvVpiGd"
```

---

### Task 4: Config and limits

**Files:**
- Create: `src/wireshark_mcp/config.py`
- Test: `tests/test_config.py`

**Interfaces:**
- Consumes: `ErrorKind`, `ToolError`.
- Produces: constants `MAX_DURATION_S = 300`, `MAX_PACKETS = 100_000`, `MAX_LIMIT = 500`; `default_workdir(system: str | None = None) -> Path`; `Config` (frozen dataclass with `workdir: Path`, `read_only_dirs: tuple[Path, ...]`, `interface_allowlist: tuple[str, ...]`, `tshark_path: str | None`, `dumpcap_path: str | None`, `capinfos_path: str | None`); `load_config(path: Path | None = None, system: str | None = None) -> Config`; `clamp(value: int, ceiling: int, name: str) -> int` raising `ToolError(ErrorKind.LIMIT_EXCEEDED, ...)` when `value > ceiling` or `value < 1`.

An empty `interface_allowlist` means every interface is allowed. Workdir is `~/.wireshark-mcp` on macOS and `%LOCALAPPDATA%\wireshark-mcp` on Windows.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_config.py
import pytest

from wireshark_mcp.config import (
    MAX_DURATION_S,
    MAX_LIMIT,
    MAX_PACKETS,
    clamp,
    default_workdir,
    load_config,
)
from wireshark_mcp.errors import ErrorKind, ToolError


def test_ceilings_match_spec():
    assert (MAX_DURATION_S, MAX_PACKETS, MAX_LIMIT) == (300, 100_000, 500)


def test_clamp_passes_value_within_ceiling():
    assert clamp(10, MAX_DURATION_S, "duration_s") == 10


def test_clamp_rejects_value_over_ceiling():
    with pytest.raises(ToolError) as caught:
        clamp(9999, MAX_DURATION_S, "duration_s")
    assert caught.value.kind is ErrorKind.LIMIT_EXCEEDED
    assert "duration_s" in caught.value.message


def test_clamp_rejects_zero_and_negative():
    for bad in (0, -1):
        with pytest.raises(ToolError):
            clamp(bad, MAX_PACKETS, "max_packets")


def test_default_workdir_is_platform_specific(monkeypatch):
    assert default_workdir("Darwin").name == ".wireshark-mcp"
    monkeypatch.setenv("LOCALAPPDATA", r"C:\Users\x\AppData\Local")
    assert default_workdir("Windows").name == "wireshark-mcp"


def test_missing_config_file_yields_defaults(tmp_path):
    cfg = load_config(tmp_path / "absent.toml", system="Darwin")
    assert cfg.interface_allowlist == ()
    assert cfg.tshark_path is None


def test_config_file_is_read(tmp_path):
    cfg_file = tmp_path / "config.toml"
    cfg_file.write_text(
        'workdir = "%s"\n'
        'interface_allowlist = ["en0", "lo0"]\n'
        "\n[binaries]\n"
        'tshark = "/opt/homebrew/bin/tshark"\n' % tmp_path.as_posix()
    )
    cfg = load_config(cfg_file, system="Darwin")
    assert cfg.interface_allowlist == ("en0", "lo0")
    assert cfg.tshark_path == "/opt/homebrew/bin/tshark"
    assert cfg.workdir == tmp_path
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_config.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'wireshark_mcp.config'`

- [ ] **Step 3: Write minimal implementation**

```python
# src/wireshark_mcp/config.py
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
    )


def clamp(value: int, ceiling: int, name: str) -> int:
    """Return value, or raise if it is outside 1..ceiling. Never silently truncates."""
    if value < 1:
        raise ToolError(ErrorKind.LIMIT_EXCEEDED, f"{name} must be at least 1, got {value}")
    if value > ceiling:
        raise ToolError(
            ErrorKind.LIMIT_EXCEEDED,
            f"{name} must be at most {ceiling}, got {value}",
            hint=f"Retry with {name} <= {ceiling}.",
        )
    return value
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_config.py -v`
Expected: 7 passed

- [ ] **Step 5: Commit**

```bash
git add src/wireshark_mcp/config.py tests/test_config.py
git commit -m "feat: config loading and hard ceilings

Claude-Session: https://claude.ai/code/session_01VUC66Mkn8NR63wjmvVpiGd"
```

---

### Task 5: CaptureStore — the path sandbox

**Files:**
- Create: `src/wireshark_mcp/store.py`
- Test: `tests/test_store.py`

**Interfaces:**
- Consumes: `Config` from Task 4; `ErrorKind`, `ToolError`.
- Produces: `CaptureStore` with `__init__(self, config: Config)`; `.captures_dir -> Path`; `.audit_log -> Path`; `.new_capture_path() -> tuple[str, Path]` returning `(capture_id, path)` where `capture_id` is `cap-<UTC timestamp>-<6 hex chars>`; `.resolve(capture_ref: str) -> Path` accepting a capture id or a filename and raising on anything escaping the sandbox; `.list_captures() -> list[dict]` with keys `id`, `path`, `size_bytes`, `created`; `.audit(tool: str, args: dict) -> None`.

`resolve` is the single chokepoint for every file argument in the codebase. It rejects: absolute paths outside the sandbox, `..` traversal, symlinks pointing outside, and (on Windows) drive-relative and UNC paths. It accepts a bare capture id, a bare filename, and any path that fully resolves inside `captures_dir` or a configured read-only dir.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_store.py
import pytest

from wireshark_mcp.config import Config
from wireshark_mcp.errors import ErrorKind, ToolError
from wireshark_mcp.store import CaptureStore


@pytest.fixture
def store(tmp_path):
    return CaptureStore(Config(workdir=tmp_path))


def test_creates_captures_dir(store, tmp_path):
    assert store.captures_dir == tmp_path / "captures"
    assert store.captures_dir.is_dir()


def test_new_capture_path_is_unique_and_inside_sandbox(store):
    id_a, path_a = store.new_capture_path()
    id_b, path_b = store.new_capture_path()
    assert id_a != id_b
    assert path_a.suffix == ".pcapng"
    assert path_a.parent == store.captures_dir


def test_resolve_accepts_bare_capture_id(store):
    capture_id, path = store.new_capture_path()
    path.write_bytes(b"")
    assert store.resolve(capture_id) == path


def test_resolve_accepts_bare_filename(store):
    capture_id, path = store.new_capture_path()
    path.write_bytes(b"")
    assert store.resolve(path.name) == path


def test_resolve_rejects_traversal(store):
    with pytest.raises(ToolError) as caught:
        store.resolve("../../etc/passwd")
    assert caught.value.kind is ErrorKind.PATH_REJECTED


def test_resolve_rejects_absolute_path_outside_sandbox(store):
    with pytest.raises(ToolError) as caught:
        store.resolve("/etc/passwd")
    assert caught.value.kind is ErrorKind.PATH_REJECTED


def test_resolve_rejects_unc_paths(store):
    with pytest.raises(ToolError) as caught:
        store.resolve(r"\\server\share\x.pcapng")
    assert caught.value.kind is ErrorKind.PATH_REJECTED


def test_resolve_rejects_drive_relative_paths(store):
    with pytest.raises(ToolError) as caught:
        store.resolve("C:sneaky.pcapng")
    assert caught.value.kind is ErrorKind.PATH_REJECTED


def test_resolve_rejects_rooted_windows_path_outside_sandbox(store):
    """Allowed past the drive check, then rejected by the sandbox check."""
    with pytest.raises(ToolError) as caught:
        store.resolve(r"C:\Windows\System32\config\SAM")
    assert caught.value.kind is ErrorKind.PATH_REJECTED


def test_resolve_rejects_symlink_escaping_sandbox(store, tmp_path):
    outside = tmp_path / "outside.pcapng"
    outside.write_bytes(b"")
    link = store.captures_dir / "sneaky.pcapng"
    link.symlink_to(outside)
    with pytest.raises(ToolError) as caught:
        store.resolve("sneaky.pcapng")
    assert caught.value.kind is ErrorKind.PATH_REJECTED


def test_resolve_missing_file_is_not_found(store):
    with pytest.raises(ToolError) as caught:
        store.resolve("cap-nope.pcapng")
    assert caught.value.kind is ErrorKind.NOT_FOUND


def test_resolve_allows_configured_read_only_dir(tmp_path):
    ro = tmp_path / "ro"
    ro.mkdir()
    sample = ro / "sample.pcapng"
    sample.write_bytes(b"")
    store = CaptureStore(Config(workdir=tmp_path / "wd", read_only_dirs=(ro,)))
    assert store.resolve(str(sample)) == sample.resolve()


def test_list_captures_reports_metadata(store):
    _, path = store.new_capture_path()
    path.write_bytes(b"1234")
    entries = store.list_captures()
    assert len(entries) == 1
    assert entries[0]["size_bytes"] == 4


def test_audit_appends_a_line(store):
    store.audit("start_capture", {"interface": "en0"})
    store.audit("packet_summary", {"capture": "cap-x"})
    assert len(store.audit_log.read_text().strip().splitlines()) == 2
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_store.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'wireshark_mcp.store'`

- [ ] **Step 3: Write minimal implementation**

```python
# src/wireshark_mcp/store.py
"""The workdir and the path sandbox. Sole authority on which files may be touched."""

from __future__ import annotations

import json
import ntpath
import secrets
from datetime import datetime, timezone
from pathlib import Path

from .config import Config
from .errors import ErrorKind, ToolError


class CaptureStore:
    def __init__(self, config: Config) -> None:
        self.config = config
        self.captures_dir = config.workdir / "captures"
        self.captures_dir.mkdir(parents=True, exist_ok=True)
        self.audit_log = config.workdir / "audit.log"

    # -- allocation ---------------------------------------------------

    def new_capture_path(self) -> tuple[str, Path]:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
        capture_id = f"cap-{stamp}-{secrets.token_hex(3)}"
        return capture_id, self.captures_dir / f"{capture_id}.pcapng"

    # -- the sandbox --------------------------------------------------

    def _allowed_roots(self) -> list[Path]:
        return [self.captures_dir.resolve(), *(d.resolve() for d in self.config.read_only_dirs)]

    def _reject(self, ref: str, why: str) -> ToolError:
        return ToolError(
            ErrorKind.PATH_REJECTED,
            f"path {ref!r} is outside the allowed directories ({why})",
            hint="Use a capture id from list_captures, or a file in a configured read_only_dir.",
        )

    def resolve(self, capture_ref: str) -> Path:
        """Map a capture id, filename, or path to a real file inside the sandbox."""
        if not capture_ref or capture_ref.strip() != capture_ref:
            raise self._reject(capture_ref, "empty or padded reference")

        # UNC paths are always rejected. A drive-relative path ("C:foo", no
        # separator after the colon) is rejected too: it resolves against a
        # per-drive current directory, which is not a sandbox we control. A
        # rooted drive path ("C:\\dir\\file") is allowed through to the sandbox
        # check below, because on Windows every legitimate absolute path has one.
        if capture_ref.startswith("\\\\\\\\") or capture_ref.startswith("//"):
            raise self._reject(capture_ref, "UNC path")
        drive, rest = ntpath.splitdrive(capture_ref)
        if drive and not rest.startswith(("\\\\", "/")):
            raise self._reject(capture_ref, "drive-relative path")

        candidates = [Path(capture_ref)]
        if "/" not in capture_ref and "\\" not in capture_ref:
            candidates = [
                self.captures_dir / capture_ref,
                self.captures_dir / f"{capture_ref}.pcapng",
            ]

        roots = self._allowed_roots()
        for candidate in candidates:
            resolved = candidate.resolve()  # follows symlinks; escapes become visible
            if not any(resolved.is_relative_to(root) for root in roots):
                continue
            if resolved.is_file():
                return resolved

        # Distinguish "outside the sandbox" from "inside but absent".
        for candidate in candidates:
            resolved = candidate.resolve()
            if any(resolved.is_relative_to(root) for root in roots):
                raise ToolError(
                    ErrorKind.NOT_FOUND,
                    f"no capture named {capture_ref!r}",
                    hint="Call list_captures to see what exists.",
                )
        raise self._reject(capture_ref, "resolves outside the sandbox")

    # -- listing and audit --------------------------------------------

    def list_captures(self) -> list[dict]:
        entries = []
        for path in sorted(self.captures_dir.glob("*.pcapng")):
            stat = path.stat()
            entries.append(
                {
                    "id": path.stem,
                    "path": str(path),
                    "size_bytes": stat.st_size,
                    "created": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
                }
            )
        return entries

    def audit(self, tool: str, args: dict) -> None:
        record = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "tool": tool,
            "args": args,
        }
        with self.audit_log.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record) + "\n")
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_store.py -v`
Expected: 14 passed

- [ ] **Step 5: Commit**

```bash
git add src/wireshark_mcp/store.py tests/test_store.py
git commit -m "feat: capture store with path sandbox and audit log

Claude-Session: https://claude.ai/code/session_01VUC66Mkn8NR63wjmvVpiGd"
```

---

### Task 6: Subprocess runner

**Files:**
- Create: `src/wireshark_mcp/run.py`
- Test: `tests/test_run.py`

**Interfaces:**
- Consumes: `ErrorKind`, `ToolError`.
- Produces: `CommandResult` (frozen dataclass: `returncode: int`, `stdout: str`, `stderr: str`); `run_command(argv: list[str | Path], timeout_s: int) -> CommandResult` raising `ToolError` on timeout (`CAPTURE_FAILED`) and on a missing executable (`BINARY_MISSING`); `check(result: CommandResult, kind: ErrorKind, what: str) -> CommandResult` raising `ToolError(kind, ...)` when `returncode != 0`, mapping stderr containing "permission denied" or "you don't have permission" to `ErrorKind.PERMISSION_DENIED` regardless of the requested kind.

Every subprocess in this codebase goes through `run_command`. It is the only place `subprocess` is imported.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_run.py
import sys

import pytest

from wireshark_mcp.errors import ErrorKind, ToolError
from wireshark_mcp.run import check, run_command


def test_runs_and_captures_stdout():
    result = run_command([sys.executable, "-c", "print('hi')"], timeout_s=10)
    assert result.returncode == 0
    assert result.stdout.strip() == "hi"


def test_missing_executable_is_binary_missing():
    with pytest.raises(ToolError) as caught:
        run_command(["definitely-not-a-real-binary-xyz"], timeout_s=5)
    assert caught.value.kind is ErrorKind.BINARY_MISSING


def test_timeout_raises_capture_failed():
    with pytest.raises(ToolError) as caught:
        run_command([sys.executable, "-c", "import time; time.sleep(5)"], timeout_s=1)
    assert caught.value.kind is ErrorKind.CAPTURE_FAILED


def test_check_passes_a_zero_exit():
    result = run_command([sys.executable, "-c", "pass"], timeout_s=10)
    assert check(result, ErrorKind.CAPTURE_FAILED, "test") is result


def test_check_raises_requested_kind_on_nonzero():
    result = run_command([sys.executable, "-c", "raise SystemExit(3)"], timeout_s=10)
    with pytest.raises(ToolError) as caught:
        check(result, ErrorKind.BAD_FILTER, "filter check")
    assert caught.value.kind is ErrorKind.BAD_FILTER


def test_check_upgrades_permission_errors():
    result = run_command(
        [sys.executable, "-c", "import sys; sys.stderr.write('Permission denied'); raise SystemExit(2)"],
        timeout_s=10,
    )
    with pytest.raises(ToolError) as caught:
        check(result, ErrorKind.CAPTURE_FAILED, "capture")
    assert caught.value.kind is ErrorKind.PERMISSION_DENIED
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_run.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'wireshark_mcp.run'`

- [ ] **Step 3: Write minimal implementation**

```python
# src/wireshark_mcp/run.py
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
        completed = subprocess.run(  # noqa: S603 - argv built in code, never from the model
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_run.py -v`
Expected: 6 passed

- [ ] **Step 5: Commit**

```bash
git add src/wireshark_mcp/run.py tests/test_run.py
git commit -m "feat: single shell-free subprocess runner

Claude-Session: https://claude.ai/code/session_01VUC66Mkn8NR63wjmvVpiGd"
```

---

### Task 7: TsharkReader — argv builders

**Files:**
- Create: `src/wireshark_mcp/tshark.py`
- Test: `tests/test_tshark_argv.py`

**Interfaces:**
- Consumes: `find_binary`, `Config`, `run_command`, `check`, `ToolError`, `ErrorKind`. (Limit clamping belongs to the server layer, not here — do not import `clamp` in this module; ruff fails on unused imports.)
- Produces: `STAT_TYPES: frozenset[str]` = `{"tcp", "udp", "ip", "eth"}`; `FOLLOW_PROTOCOLS: frozenset[str]` = `{"tcp", "udp", "http"}`; pure argv builders `summary_argv`, `detail_argv`, `stats_argv`, `hierarchy_argv`, `io_stats_argv`, `expert_argv`, `follow_argv`, `filter_check_argv`; and class `TsharkReader` wrapping them with execution.

Signatures (all builders take `tshark: Path` first and return `list[str]`):
- `summary_argv(tshark, path: Path, display_filter: str | None, limit: int)` → `-r path [-Y filter] -c limit` (note: `-c` limits packets *read*, which is the intended bound)
- `detail_argv(tshark, path: Path, frame_no: int)` → `-r path -Y frame.number==N -V`
- `stats_argv(tshark, path: Path, kind: str, stat_type: str)` → `-r path -q -z <kind>,<stat_type>` where `kind` is `conv` or `endpoints`
- `hierarchy_argv(tshark, path)` → `-r path -q -z io,phs`
- `io_stats_argv(tshark, path, interval_s: int)` → `-r path -q -z io,stat,<interval_s>`
- `expert_argv(tshark, path)` → `-r path -q -z expert`
- `follow_argv(tshark, path, protocol: str, index: int)` → `-r path -q -z follow,<protocol>,ascii,<index>`
- `filter_check_argv(dftest: Path, display_filter: str)` → `[dftest, display_filter]`. Wireshark ships `dftest`, whose entire job is compiling a display filter and reporting whether it is valid. `tshark -r /dev/null` cannot be used for this: it fails on the empty file itself, so every filter would look invalid.

`stat_type` must be in `STAT_TYPES` and `protocol` in `FOLLOW_PROTOCOLS`, else `ToolError(ErrorKind.BAD_FILTER, ...)` — these are the only string values that reach argv other than the user's filters and the resolved path.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_tshark_argv.py
from pathlib import Path

import pytest

from wireshark_mcp.errors import ErrorKind, ToolError
from wireshark_mcp.tshark import (
    detail_argv,
    expert_argv,
    filter_check_argv,
    follow_argv,
    hierarchy_argv,
    io_stats_argv,
    stats_argv,
    summary_argv,
)

TSHARK = Path("/usr/bin/tshark")
CAP = Path("/tmp/x.pcapng")


def test_summary_without_filter():
    assert summary_argv(TSHARK, CAP, None, 50) == [
        "/usr/bin/tshark", "-r", str(CAP), "-c", "50",
    ]


def test_summary_with_filter_passes_it_as_one_argv_element():
    argv = summary_argv(TSHARK, CAP, "tcp.port == 443 && ip.addr == 1.2.3.4", 10)
    assert argv[argv.index("-Y") + 1] == "tcp.port == 443 && ip.addr == 1.2.3.4"


def test_filter_containing_shell_metacharacters_stays_one_element():
    hostile = "tcp; rm -rf / #"
    argv = summary_argv(TSHARK, CAP, hostile, 5)
    assert hostile in argv
    assert argv.count(hostile) == 1


def test_detail_targets_a_single_frame():
    argv = detail_argv(TSHARK, CAP, 42)
    assert "frame.number==42" in argv
    assert "-V" in argv


def test_stats_rejects_unknown_type():
    with pytest.raises(ToolError) as caught:
        stats_argv(TSHARK, CAP, "conv", "definitely-not-a-type")
    assert caught.value.kind is ErrorKind.BAD_FILTER


def test_stats_builds_conv_and_endpoints():
    assert "conv,tcp" in stats_argv(TSHARK, CAP, "conv", "tcp")
    assert "endpoints,ip" in stats_argv(TSHARK, CAP, "endpoints", "ip")


def test_hierarchy_and_expert_and_io_stats():
    assert "io,phs" in hierarchy_argv(TSHARK, CAP)
    assert "expert" in expert_argv(TSHARK, CAP)
    assert "io,stat,5" in io_stats_argv(TSHARK, CAP, 5)


def test_follow_rejects_unknown_protocol():
    with pytest.raises(ToolError):
        follow_argv(TSHARK, CAP, "smtp", 0)


def test_follow_builds_expected_z_argument():
    assert "follow,tcp,ascii,3" in follow_argv(TSHARK, CAP, "tcp", 3)


def test_filter_check_uses_dftest_with_the_filter_as_one_element():
    argv = filter_check_argv(Path("/usr/bin/dftest"), "tcp.port == 443")
    assert argv == ["/usr/bin/dftest", "tcp.port == 443"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_tshark_argv.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'wireshark_mcp.tshark'`

- [ ] **Step 3: Write minimal implementation**

```python
# src/wireshark_mcp/tshark.py
"""Reading and analyzing capture files with tshark.

Argv construction is pure and separately tested; execution is a thin wrapper.
"""

from __future__ import annotations

from pathlib import Path

from .config import Config
from .errors import ErrorKind, ToolError
from .platform import find_binary
from .run import CommandResult, check, run_command

STAT_TYPES = frozenset({"tcp", "udp", "ip", "eth"})
FOLLOW_PROTOCOLS = frozenset({"tcp", "udp", "http"})

READ_TIMEOUT_S = 120


def _validate(value: str, allowed: frozenset[str], name: str) -> str:
    if value not in allowed:
        raise ToolError(
            ErrorKind.BAD_FILTER,
            f"{name} must be one of {sorted(allowed)}, got {value!r}",
        )
    return value


def summary_argv(
    tshark: Path, path: Path, display_filter: str | None, limit: int
) -> list[str]:
    argv = [str(tshark), "-r", str(path)]
    if display_filter:
        argv += ["-Y", display_filter]
    argv += ["-c", str(limit)]
    return argv


def detail_argv(tshark: Path, path: Path, frame_no: int) -> list[str]:
    return [str(tshark), "-r", str(path), "-Y", f"frame.number=={frame_no}", "-V"]


def stats_argv(tshark: Path, path: Path, kind: str, stat_type: str) -> list[str]:
    _validate(kind, frozenset({"conv", "endpoints"}), "kind")
    _validate(stat_type, STAT_TYPES, "type")
    return [str(tshark), "-r", str(path), "-q", "-z", f"{kind},{stat_type}"]


def hierarchy_argv(tshark: Path, path: Path) -> list[str]:
    return [str(tshark), "-r", str(path), "-q", "-z", "io,phs"]


def io_stats_argv(tshark: Path, path: Path, interval_s: int) -> list[str]:
    return [str(tshark), "-r", str(path), "-q", "-z", f"io,stat,{int(interval_s)}"]


def expert_argv(tshark: Path, path: Path) -> list[str]:
    return [str(tshark), "-r", str(path), "-q", "-z", "expert"]


def follow_argv(tshark: Path, path: Path, protocol: str, index: int) -> list[str]:
    _validate(protocol, FOLLOW_PROTOCOLS, "protocol")
    return [
        str(tshark), "-r", str(path), "-q", "-z",
        f"follow,{protocol},ascii,{int(index)}",
    ]


def filter_check_argv(dftest: Path, display_filter: str) -> list[str]:
    """dftest compiles a display filter and reports whether it is valid."""
    return [str(dftest), display_filter]


class TsharkReader:
    def __init__(self, config: Config) -> None:
        self._config = config
        self._tshark: Path | None = None

    @property
    def tshark(self) -> Path:
        if self._tshark is None:
            self._tshark = find_binary("tshark", override=self._config.tshark_path)
        return self._tshark

    def _run(self, argv: list[str], what: str) -> str:
        result: CommandResult = run_command(argv, timeout_s=READ_TIMEOUT_S)
        return check(result, ErrorKind.CAPTURE_FAILED, what).stdout

    def validate_filter(self, display_filter: str) -> None:
        """Compile a display filter so a bad one fails here, not mid-analysis.

        Fails open: when dftest is not installed alongside tshark, validation is
        skipped and an invalid filter surfaces from the read itself.
        """
        try:
            dftest = find_binary("dftest")
        except ToolError:
            return
        result = run_command(filter_check_argv(dftest, display_filter), timeout_s=15)
        if result.returncode != 0:
            raise ToolError(
                ErrorKind.BAD_FILTER,
                f"invalid display filter: {result.stderr.strip()}",
                hint="Display filter syntax, e.g. 'tcp.port == 443', not BPF syntax.",
            )

    def summary(self, path: Path, display_filter: str | None, limit: int) -> str:
        if display_filter:
            self.validate_filter(display_filter)
        return self._run(summary_argv(self.tshark, path, display_filter, limit), "packet summary")

    def detail(self, path: Path, frame_no: int) -> str:
        return self._run(detail_argv(self.tshark, path, frame_no), "packet detail")

    def stats(self, path: Path, kind: str, stat_type: str) -> str:
        return self._run(stats_argv(self.tshark, path, kind, stat_type), f"{kind} statistics")

    def hierarchy(self, path: Path) -> str:
        return self._run(hierarchy_argv(self.tshark, path), "protocol hierarchy")

    def io_stats(self, path: Path, interval_s: int) -> str:
        return self._run(io_stats_argv(self.tshark, path, interval_s), "I/O statistics")

    def expert(self, path: Path) -> str:
        return self._run(expert_argv(self.tshark, path), "expert info")

    def follow(self, path: Path, protocol: str, index: int) -> str:
        return self._run(follow_argv(self.tshark, path, protocol, index), "follow stream")

    def info(self, path: Path) -> str:
        capinfos = find_binary("capinfos", override=self._config.capinfos_path)
        result = run_command([str(capinfos), str(path)], timeout_s=60)
        return check(result, ErrorKind.CAPTURE_FAILED, "capture info").stdout
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_tshark_argv.py -v`
Expected: 10 passed

- [ ] **Step 5: Commit**

```bash
git add src/wireshark_mcp/tshark.py tests/test_tshark_argv.py
git commit -m "feat: tshark argv builders and reader

Claude-Session: https://claude.ai/code/session_01VUC66Mkn8NR63wjmvVpiGd"
```

---

### Task 8: CaptureRunner — bounded live capture

**Files:**
- Create: `src/wireshark_mcp/capture.py`
- Test: `tests/test_capture.py`

**Interfaces:**
- Consumes: `find_binary`, `parse_interfaces`, `Interface`, `Config`, `clamp`, `MAX_DURATION_S`, `MAX_PACKETS`, `CaptureStore`, `run_command`, `check`.
- Produces: `capture_argv(dumpcap: Path, interface: str, out_path: Path, duration_s: int, max_packets: int, bpf_filter: str | None) -> list[str]`; `CaptureRunner` with `__init__(self, config: Config, store: CaptureStore)`, `.list_interfaces() -> list[Interface]`, `.capture(interface: str, duration_s: int, max_packets: int, bpf_filter: str | None) -> dict`.

`capture_argv` produces `dumpcap -i <iface> -w <out> -a duration:<n> -c <n> [-f <bpf>]`. `.capture` clamps both bounds, enforces the interface allowlist, and runs with a subprocess timeout of `duration_s + 15` so a wedged dumpcap cannot hang the server. This class is the seam where background jobs would later be added.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_capture.py
from pathlib import Path

import pytest

from wireshark_mcp.capture import CaptureRunner, capture_argv
from wireshark_mcp.config import Config
from wireshark_mcp.errors import ErrorKind, ToolError
from wireshark_mcp.store import CaptureStore

DUMPCAP = Path("/usr/bin/dumpcap")
OUT = Path("/tmp/out.pcapng")


def test_argv_has_both_bounds():
    argv = capture_argv(DUMPCAP, "en0", OUT, 30, 1000, None)
    assert "-a" in argv and "duration:30" in argv
    assert argv[argv.index("-c") + 1] == "1000"
    assert argv[argv.index("-i") + 1] == "en0"


def test_argv_omits_filter_when_absent():
    assert "-f" not in capture_argv(DUMPCAP, "en0", OUT, 5, 10, None)


def test_bpf_filter_is_one_argv_element():
    hostile = "port 80 or (host 1.2.3.4); echo pwned"
    argv = capture_argv(DUMPCAP, "en0", OUT, 5, 10, hostile)
    assert argv[argv.index("-f") + 1] == hostile


def test_windows_npf_interface_id_survives_unmangled():
    npf = r"\Device\NPF_{A1B2C3D4-0000-1111-2222-333344445555}"
    argv = capture_argv(DUMPCAP, npf, OUT, 5, 10, None)
    assert argv[argv.index("-i") + 1] == npf


def _runner(tmp_path, **cfg):
    config = Config(workdir=tmp_path, **cfg)
    return CaptureRunner(config, CaptureStore(config))


def test_duration_over_ceiling_rejected(tmp_path):
    with pytest.raises(ToolError) as caught:
        _runner(tmp_path).capture("en0", duration_s=99999, max_packets=10, bpf_filter=None)
    assert caught.value.kind is ErrorKind.LIMIT_EXCEEDED


def test_packet_cap_over_ceiling_rejected(tmp_path):
    with pytest.raises(ToolError) as caught:
        _runner(tmp_path).capture("en0", duration_s=5, max_packets=10**9, bpf_filter=None)
    assert caught.value.kind is ErrorKind.LIMIT_EXCEEDED


def test_interface_not_on_allowlist_rejected(tmp_path):
    runner = _runner(tmp_path, interface_allowlist=("lo0",))
    with pytest.raises(ToolError) as caught:
        runner.capture("en0", duration_s=5, max_packets=10, bpf_filter=None)
    assert caught.value.kind is ErrorKind.BAD_INTERFACE


@pytest.mark.requires_capture
def test_live_loopback_capture_produces_a_file(tmp_path):
    runner = _runner(tmp_path)
    loopbacks = [i for i in runner.list_interfaces() if i.loopback]
    if not loopbacks:
        pytest.skip("no loopback interface available")
    result = runner.capture(loopbacks[0].id, duration_s=2, max_packets=5, bpf_filter=None)
    assert Path(result["path"]).is_file()
    assert result["id"].startswith("cap-")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_capture.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'wireshark_mcp.capture'`

- [ ] **Step 3: Write minimal implementation**

```python
# src/wireshark_mcp/capture.py
"""Bounded live capture via dumpcap.

Synchronous by design: every capture carries a duration and a packet cap, so it
terminates on its own. CaptureRunner is the single seam where asynchronous
background jobs would be introduced later.
"""

from __future__ import annotations

from pathlib import Path

from .config import MAX_DURATION_S, MAX_PACKETS, Config, clamp
from .errors import ErrorKind, ToolError
from .platform import Interface, capture_permitted, find_binary, parse_interfaces
from .run import check, run_command
from .store import CaptureStore

TIMEOUT_MARGIN_S = 15


def capture_argv(
    dumpcap: Path,
    interface: str,
    out_path: Path,
    duration_s: int,
    max_packets: int,
    bpf_filter: str | None,
) -> list[str]:
    argv = [
        str(dumpcap),
        "-i", interface,
        "-w", str(out_path),
        "-a", f"duration:{int(duration_s)}",
        "-c", str(int(max_packets)),
    ]
    if bpf_filter:
        argv += ["-f", bpf_filter]
    return argv


class CaptureRunner:
    def __init__(self, config: Config, store: CaptureStore) -> None:
        self._config = config
        self._store = store
        self._dumpcap: Path | None = None

    @property
    def dumpcap(self) -> Path:
        if self._dumpcap is None:
            self._dumpcap = find_binary("dumpcap", override=self._config.dumpcap_path)
        return self._dumpcap

    def list_interfaces(self) -> list[Interface]:
        result = run_command([str(self.dumpcap), "-D"], timeout_s=30)
        return parse_interfaces(check(result, ErrorKind.BAD_INTERFACE, "list interfaces").stdout)

    def _check_allowlist(self, interface: str) -> None:
        allowed = self._config.interface_allowlist
        if allowed and interface not in allowed:
            raise ToolError(
                ErrorKind.BAD_INTERFACE,
                f"interface {interface!r} is not on the configured allowlist",
                hint=f"Allowed interfaces: {', '.join(allowed)}",
            )

    def capture(
        self,
        interface: str,
        duration_s: int,
        max_packets: int,
        bpf_filter: str | None,
    ) -> dict:
        duration_s = clamp(duration_s, MAX_DURATION_S, "duration_s")
        max_packets = clamp(max_packets, MAX_PACKETS, "max_packets")
        self._check_allowlist(interface)

        capture_id, out_path = self._store.new_capture_path()
        self._store.audit(
            "start_capture",
            {
                "interface": interface,
                "duration_s": duration_s,
                "max_packets": max_packets,
                "bpf_filter": bpf_filter,
                "capture_id": capture_id,
            },
        )

        argv = capture_argv(
            self.dumpcap, interface, out_path, duration_s, max_packets, bpf_filter
        )
        result = run_command(argv, timeout_s=duration_s + TIMEOUT_MARGIN_S)
        if result.returncode != 0 and not out_path.is_file():
            ok, why = capture_permitted()
            if not ok:
                raise ToolError(ErrorKind.PERMISSION_DENIED, why, hint=why)
            check(result, ErrorKind.CAPTURE_FAILED, "capture")

        return {
            "id": capture_id,
            "path": str(out_path),
            "size_bytes": out_path.stat().st_size if out_path.is_file() else 0,
            "interface": interface,
            "duration_s": duration_s,
            "max_packets": max_packets,
            "bpf_filter": bpf_filter or "",
        }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_capture.py -v`
Expected: 7 passed, 1 skipped (`requires_capture`) unless capture works on this host

- [ ] **Step 5: Commit**

```bash
git add src/wireshark_mcp/capture.py tests/test_capture.py
git commit -m "feat: bounded live capture via dumpcap

Claude-Session: https://claude.ai/code/session_01VUC66Mkn8NR63wjmvVpiGd"
```

---

### Task 9: MCP server — tools, resources, prompts

**Files:**
- Create: `src/wireshark_mcp/server.py`
- Test: `tests/test_server.py`

**Interfaces:**
- Consumes: everything from Tasks 1-8.
- Produces: `build_context(config: Config | None = None) -> Context` where `Context` is a frozen dataclass holding `config`, `store`, `reader`, `runner`; `tool_result(fn, *args, **kwargs)` wrapping a call so `ToolError` becomes `error_dict(...)`; the FastMCP instance `mcp`; and `main() -> None`, the console-script entry point that runs the stdio server.

Tools registered: `list_interfaces`, `start_capture`, `list_captures`, `packet_summary`, `packet_detail`, `capture_info`, `protocol_hierarchy`, `conversations`, `endpoints`, `io_stats`, `expert_info`, `follow_stream`. Resource: `capture://{capture_id}`. Prompts: `triage_capture`, `tls_failures`, `find_slow_requests`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_server.py
import pytest

from wireshark_mcp.config import Config
from wireshark_mcp.errors import ErrorKind, ToolError
from wireshark_mcp.server import EXPECTED_TOOLS, build_context, tool_result


def test_tool_result_passes_a_value_through():
    assert tool_result(lambda: {"ok": True}) == {"ok": True}


def test_tool_result_converts_tool_error_to_dict():
    def boom():
        raise ToolError(ErrorKind.NOT_FOUND, "nope", hint="try list_captures")

    assert tool_result(boom) == {"error": "nope", "kind": "not_found", "hint": "try list_captures"}


def test_tool_result_converts_unexpected_exception_to_dict():
    def boom():
        raise RuntimeError("kaboom")

    result = tool_result(boom)
    assert result["kind"] == "capture_failed"
    assert "kaboom" in result["error"]


def test_build_context_wires_components(tmp_path):
    ctx = build_context(Config(workdir=tmp_path))
    assert ctx.store.captures_dir.is_dir()
    assert ctx.runner is not None and ctx.reader is not None


def test_expected_tool_names_are_declared():
    assert "start_capture" in EXPECTED_TOOLS
    assert "follow_stream" in EXPECTED_TOOLS
    assert "run_tshark" not in EXPECTED_TOOLS
    assert len(EXPECTED_TOOLS) == 12
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_server.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'wireshark_mcp.server'`

- [ ] **Step 3: Write minimal implementation**

```python
# src/wireshark_mcp/server.py
"""MCP surface: tools, resources, and prompts over stdio."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from mcp.server.fastmcp import FastMCP

from .capture import CaptureRunner
from .config import MAX_LIMIT, Config, clamp, load_config
from .errors import ErrorKind, ToolError, error_dict
from .platform import capture_permitted
from .store import CaptureStore
from .tshark import TsharkReader

EXPECTED_TOOLS = (
    "list_interfaces",
    "start_capture",
    "list_captures",
    "packet_summary",
    "packet_detail",
    "capture_info",
    "protocol_hierarchy",
    "conversations",
    "endpoints",
    "io_stats",
    "expert_info",
    "follow_stream",
)


@dataclass(frozen=True)
class Context:
    config: Config
    store: CaptureStore
    reader: TsharkReader
    runner: CaptureRunner


def build_context(config: Config | None = None) -> Context:
    config = config or load_config()
    store = CaptureStore(config)
    return Context(
        config=config,
        store=store,
        reader=TsharkReader(config),
        runner=CaptureRunner(config, store),
    )


def tool_result(fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    """Run a tool body, converting any failure into a structured dict."""
    try:
        return fn(*args, **kwargs)
    except ToolError as exc:
        return error_dict(exc)
    except Exception as exc:  # never let an unexpected error kill the session
        return error_dict(ToolError(ErrorKind.CAPTURE_FAILED, f"unexpected error: {exc}"))


mcp = FastMCP("wireshark")
_ctx: Context | None = None


def ctx() -> Context:
    global _ctx
    if _ctx is None:
        _ctx = build_context()
    return _ctx


# -- tools ---------------------------------------------------------------


@mcp.tool()
def list_interfaces() -> Any:
    """List capture interfaces, with whether live capture is currently permitted."""

    def body():
        ok, why = capture_permitted()
        return {
            "capture_permitted": ok,
            "permission_note": why,
            "interfaces": [
                {"id": i.id, "description": i.description, "loopback": i.loopback}
                for i in ctx().runner.list_interfaces()
            ],
        }

    return tool_result(body)


@mcp.tool()
def start_capture(
    interface: str,
    duration_s: int = 10,
    max_packets: int = 1000,
    bpf_filter: str = "",
) -> Any:
    """Capture live packets on an interface. Always bounded by BOTH duration_s and max_packets."""
    return tool_result(
        ctx().runner.capture, interface, duration_s, max_packets, bpf_filter or None
    )


@mcp.tool()
def list_captures() -> Any:
    """List capture files this server has stored."""
    return tool_result(ctx().store.list_captures)


@mcp.tool()
def packet_summary(capture: str, display_filter: str = "", limit: int = 100) -> Any:
    """One line per packet, optionally narrowed by a Wireshark display filter."""

    def body():
        path = ctx().store.resolve(capture)
        capped = clamp(limit, MAX_LIMIT, "limit")
        ctx().store.audit("packet_summary", {"capture": capture, "filter": display_filter})
        return {"output": ctx().reader.summary(path, display_filter or None, capped)}

    return tool_result(body)


@mcp.tool()
def packet_detail(capture: str, frame_no: int) -> Any:
    """Full decoded protocol tree for a single frame."""

    def body():
        path = ctx().store.resolve(capture)
        return {"output": ctx().reader.detail(path, frame_no)}

    return tool_result(body)


@mcp.tool()
def capture_info(capture: str) -> Any:
    """capinfos summary: packet count, duration, byte totals, encapsulation."""

    def body():
        return {"output": ctx().reader.info(ctx().store.resolve(capture))}

    return tool_result(body)


@mcp.tool()
def protocol_hierarchy(capture: str) -> Any:
    """Protocol hierarchy statistics for the whole capture."""

    def body():
        return {"output": ctx().reader.hierarchy(ctx().store.resolve(capture))}

    return tool_result(body)


@mcp.tool()
def conversations(capture: str, type: str = "tcp") -> Any:
    """Conversation statistics. type is one of tcp, udp, ip, eth."""

    def body():
        return {"output": ctx().reader.stats(ctx().store.resolve(capture), "conv", type)}

    return tool_result(body)


@mcp.tool()
def endpoints(capture: str, type: str = "ip") -> Any:
    """Endpoint statistics. type is one of tcp, udp, ip, eth."""

    def body():
        return {"output": ctx().reader.stats(ctx().store.resolve(capture), "endpoints", type)}

    return tool_result(body)


@mcp.tool()
def io_stats(capture: str, interval_s: int = 1) -> Any:
    """Traffic volume over time, bucketed by interval_s seconds."""

    def body():
        return {"output": ctx().reader.io_stats(ctx().store.resolve(capture), interval_s)}

    return tool_result(body)


@mcp.tool()
def expert_info(capture: str) -> Any:
    """Wireshark expert info: retransmissions, resets, malformed packets, warnings."""

    def body():
        return {"output": ctx().reader.expert(ctx().store.resolve(capture))}

    return tool_result(body)


@mcp.tool()
def follow_stream(capture: str, protocol: str = "tcp", index: int = 0) -> Any:
    """Reassemble one stream as ASCII. protocol is one of tcp, udp, http."""

    def body():
        return {"output": ctx().reader.follow(ctx().store.resolve(capture), protocol, index)}

    return tool_result(body)


# -- resources -----------------------------------------------------------


@mcp.resource("capture://{capture_id}")
def capture_resource(capture_id: str) -> str:
    """Metadata for one stored capture."""
    result = tool_result(lambda: ctx().reader.info(ctx().store.resolve(capture_id)))
    return result if isinstance(result, str) else str(result)


# -- prompts -------------------------------------------------------------


@mcp.prompt()
def triage_capture(capture: str) -> str:
    return (
        f"Triage the capture {capture}. Start with capture_info and protocol_hierarchy, "
        "then expert_info. Report what protocols dominate, any errors or retransmissions, "
        "and the top talkers from conversations. Do not dump raw packets unless something "
        "specific needs a closer look."
    )


@mcp.prompt()
def tls_failures(capture: str) -> str:
    return (
        f"In capture {capture}, find failed or unusual TLS handshakes. Use packet_summary "
        "with display filters such as 'tls.handshake.type == 1', 'tls.alert_message', and "
        "'tcp.flags.reset == 1'. For each failure report client, server, SNI if present, and "
        "the alert or reset that ended it."
    )


@mcp.prompt()
def find_slow_requests(capture: str) -> str:
    return (
        f"In capture {capture}, find slow request/response pairs. Use io_stats for an overview, "
        "then packet_summary with 'http.time > 1' or 'tcp.analysis.ack_rtt > 1'. Report the "
        "slowest exchanges with their endpoints and elapsed time."
    )


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run the whole suite**

Run: `uv run pytest -v`
Expected: all tests pass; `requires_tshark` / `requires_capture` tests skip when unavailable

- [ ] **Step 5: Commit**

```bash
git add src/wireshark_mcp/server.py tests/test_server.py
git commit -m "feat: MCP tool, resource, and prompt surface

Claude-Session: https://claude.ai/code/session_01VUC66Mkn8NR63wjmvVpiGd"
```

---

### Task 10: Integration tests against a real capture file

**Files:**
- Create: `tests/conftest.py`
- Create: `tests/test_integration.py`
- Create: `tests/fixtures/.gitkeep`

**Interfaces:**
- Consumes: `TsharkReader`, `CaptureStore`, `Config`, `find_binary`.
- Produces: pytest fixtures `tshark_available` (session-scoped bool) and `sample_capture` (a real `.pcapng` generated once at session start by capturing 1 second of loopback traffic, or skipping when that is not possible).

These tests are the only ones that need Wireshark installed. They must skip cleanly, not fail, when it is absent — CI on a runner without Wireshark stays green.

- [ ] **Step 1: Write the failing test**

```python
# tests/conftest.py
import pytest

from wireshark_mcp.config import Config
from wireshark_mcp.errors import ToolError
from wireshark_mcp.platform import capture_permitted, find_binary
from wireshark_mcp.store import CaptureStore


@pytest.fixture(scope="session")
def tshark_available() -> bool:
    try:
        find_binary("tshark")
    except ToolError:
        return False
    return True


@pytest.fixture
def sample_capture(tmp_path, tshark_available):
    """A real pcapng, captured from loopback. Skips when that is not possible."""
    if not tshark_available:
        pytest.skip("tshark is not installed")
    ok, why = capture_permitted()
    if not ok:
        pytest.skip(f"live capture unavailable: {why}")

    from wireshark_mcp.capture import CaptureRunner

    config = Config(workdir=tmp_path)
    runner = CaptureRunner(config, CaptureStore(config))
    loopbacks = [i for i in runner.list_interfaces() if i.loopback]
    if not loopbacks:
        pytest.skip("no loopback interface")
    result = runner.capture(loopbacks[0].id, duration_s=2, max_packets=20, bpf_filter=None)
    return result["id"], config
```

```python
# tests/test_integration.py
import pytest

from wireshark_mcp.errors import ToolError
from wireshark_mcp.store import CaptureStore
from wireshark_mcp.tshark import TsharkReader

pytestmark = pytest.mark.requires_tshark


def test_capture_info_runs_on_a_real_file(sample_capture):
    capture_id, config = sample_capture
    store, reader = CaptureStore(config), TsharkReader(config)
    assert "File name" in reader.info(store.resolve(capture_id))


def test_protocol_hierarchy_runs_on_a_real_file(sample_capture):
    capture_id, config = sample_capture
    store, reader = CaptureStore(config), TsharkReader(config)
    assert reader.hierarchy(store.resolve(capture_id)) is not None


def test_summary_with_a_valid_filter_runs(sample_capture):
    capture_id, config = sample_capture
    store, reader = CaptureStore(config), TsharkReader(config)
    assert reader.summary(store.resolve(capture_id), "ip", 10) is not None


def test_invalid_display_filter_is_rejected_before_reading(sample_capture):
    _, config = sample_capture
    with pytest.raises(ToolError) as caught:
        TsharkReader(config).validate_filter("this is not a filter (((")
    assert caught.value.kind == "bad_filter"
```

- [ ] **Step 2: Run test to verify it fails or skips honestly**

Run: `uv run pytest tests/test_integration.py -v`
Expected: 4 skipped when Wireshark is absent, 4 passed when installed with capture permission. A FAIL here means the skip logic is wrong.

- [ ] **Step 3: Install Wireshark locally and re-run**

macOS: `brew install --cask wireshark`, then run Wireshark's "Install ChmodBPF" component and log out and back in if `list_interfaces` reports capture is not permitted.

Re-run: `uv run pytest tests/test_integration.py -v`
Expected: 4 passed

- [ ] **Step 4: Run the whole suite**

Run: `uv run pytest -v`
Expected: all pass, nothing unexpectedly skipped

- [ ] **Step 5: Commit**

```bash
git add tests/conftest.py tests/test_integration.py tests/fixtures/.gitkeep
git commit -m "test: integration tests against a real capture

Claude-Session: https://claude.ai/code/session_01VUC66Mkn8NR63wjmvVpiGd"
```

---

### Task 11: README, sample config, CI

**Files:**
- Create: `README.md`
- Create: `examples/config.toml`
- Create: `.github/workflows/ci.yml`
- Modify: `project.md`

**Interfaces:**
- Consumes: the console script `wireshark-mcp` from Task 1.
- Produces: no code interfaces. Documentation and CI only.

- [ ] **Step 1: Write the CI workflow**

```yaml
# .github/workflows/ci.yml
name: ci

on:
  push:
    branches: [main]
  pull_request:

jobs:
  test:
    strategy:
      fail-fast: false
      matrix:
        os: [macos-latest, windows-latest]
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v5
      - run: uv sync --extra dev
      - run: uv run ruff check .
      - run: uv run pytest -v
```

The `requires_tshark` and `requires_capture` tiers skip on these runners; the platform, sandbox, argv, and error tests are what CI actually guards, and they are the tests that catch cross-platform regressions.

- [ ] **Step 2: Write the sample config**

```toml
# examples/config.toml
# Copy to ~/.wireshark-mcp/config.toml (macOS)
# or %LOCALAPPDATA%\wireshark-mcp\config.toml (Windows).
# Every setting is optional.

# workdir = "~/.wireshark-mcp"

# Directories of existing capture files the server may READ. Nothing outside
# the workdir and these directories can be opened.
read_only_dirs = []

# Interfaces live capture may use. Empty means every interface is allowed.
# macOS ids look like "en0"; Windows ids look like
# "\\Device\\NPF_{A1B2C3D4-0000-1111-2222-333344445555}".
interface_allowlist = []

[binaries]
# Set these only when Wireshark is installed somewhere unusual.
# tshark = "/opt/homebrew/bin/tshark"
# dumpcap = "/opt/homebrew/bin/dumpcap"
# capinfos = "/opt/homebrew/bin/capinfos"
```

- [ ] **Step 3: Write the README**

It must contain, in this order: what the server is; the security notice; install prerequisites per platform; the LM Studio `mcp.json` block; the tool table; the configuration section; and a development section.

The security notice is not optional and must say plainly:

```markdown
## Security

This server lets a local language model capture and read your network traffic.
That is its purpose, and you should install it only if you want that.

What it does to stay bounded:

- **No shell.** Every subprocess runs with `shell=False` and an argument list
  built in code. The model supplies typed values, never flags.
- **No arbitrary-command tool.** There is no `run_tshark`. The tool surface is fixed.
- **Path sandbox.** Capture files are read only from the server's own workdir and
  from directories you list in `read_only_dirs`. Traversal, symlink escapes, UNC
  paths, and drive-relative paths are rejected.
- **Bounded captures.** Every capture requires both a duration and a packet cap,
  ceilings 300 seconds and 100,000 packets. An unbounded capture cannot be requested.
- **Interface allowlist.** Set `interface_allowlist` to limit which interfaces
  can be captured on.
- **Audit log.** Every capture and every read is appended to `audit.log` in the workdir.

What it does not protect you from: captured packets contain whatever crossed the
wire, including credentials sent over cleartext protocols. Anything the model
reads from a capture is in the model's context.
```

The LM Studio wiring section:

````markdown
## Use with LM Studio

Add to LM Studio's `mcp.json` (Program → Install → Edit mcp.json):

```json
{
  "mcpServers": {
    "wireshark": {
      "command": "uvx",
      "args": ["--from", "git+https://github.com/MrDadpool/wireshark-mcp", "wireshark-mcp"]
    }
  }
}
```

On Windows, if Npcap was installed with "Restrict Npcap driver's access to
Administrators only", LM Studio must run elevated for live capture to work.
File analysis works either way.
````

- [ ] **Step 4: Verify the server actually starts and lints clean**

```bash
uv run ruff check .
uv run pytest -v
uv run python -c "from wireshark_mcp.server import mcp, EXPECTED_TOOLS; print(len(EXPECTED_TOOLS), 'tools')"
```

Expected: ruff clean, all tests pass, prints `12 tools`.

- [ ] **Step 5: Update project.md and commit**

Move the implementation items into Done, and set Now to "v0.1.0 complete; manual LM Studio verification pending."

```bash
git add README.md examples/config.toml .github/workflows/ci.yml project.md
git commit -m "docs: README, sample config, and CI matrix

Claude-Session: https://claude.ai/code/session_01VUC66Mkn8NR63wjmvVpiGd"
git push
```

---

### Task 12: Manual verification in LM Studio

**Files:**
- Modify: `project.md`
- Modify: `README.md` (only if a step below proves a documented instruction wrong)

**Interfaces:**
- Consumes: the installed console script.
- Produces: nothing in code. A recorded verification result.

- [ ] **Step 1: Confirm the server speaks MCP over stdio**

```bash
uv run python -c "
import json, subprocess, sys
proc = subprocess.Popen([sys.executable, '-m', 'wireshark_mcp.server'],
                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
req = {'jsonrpc':'2.0','id':1,'method':'initialize','params':{
    'protocolVersion':'2024-11-05','capabilities':{},
    'clientInfo':{'name':'smoke','version':'0'}}}
proc.stdin.write(json.dumps(req) + '\n'); proc.stdin.flush()
print(proc.stdout.readline()[:200])
proc.kill()
"
```

Expected: a JSON-RPC response naming the `wireshark` server. If it hangs, the stdio transport is misconfigured.

- [ ] **Step 2: Wire it into LM Studio**

Add the `mcp.json` block from the README, restart LM Studio, and confirm the `wireshark` server appears with 12 tools.

- [ ] **Step 3: Exercise it from a model**

Ask the model, in order: list the interfaces; capture 5 seconds on the Wi-Fi interface; show the protocol hierarchy; summarize the DNS packets. Each should return data, not an error dict.

- [ ] **Step 4: Verify the sandbox holds from the model's side**

Ask the model to read `/etc/passwd` (macOS) or `C:\Windows\System32\drivers\etc\hosts` (Windows) through `packet_summary`.
Expected: `{"kind": "path_rejected", ...}`. A success here is a security bug — stop and fix Task 5.

- [ ] **Step 5: Record the result and commit**

Update `project.md` with what was verified and on which platform. Note anything that only works on one OS.

```bash
git add project.md README.md
git commit -m "docs: record LM Studio verification

Claude-Session: https://claude.ai/code/session_01VUC66Mkn8NR63wjmvVpiGd"
git push
```
