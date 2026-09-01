"""The workdir and the path sandbox. Sole authority on which files may be touched."""

from __future__ import annotations

import json
import ntpath
import secrets
from datetime import UTC, datetime
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
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S")
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
        if capture_ref.startswith(("\\\\", "//")):
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
        found_outside = False
        found_inside_missing = False
        for candidate in candidates:
            resolved = candidate.resolve()  # follows symlinks; escapes become visible
            inside = any(resolved.is_relative_to(root) for root in roots)
            if resolved.is_file():
                if inside:
                    return resolved
                found_outside = True
            elif inside:
                found_inside_missing = True

        # An existing file that resolves outside the sandbox (e.g. a symlink
        # escape) is always a rejection, even if another candidate name is
        # merely absent inside the sandbox.
        if found_outside:
            raise self._reject(capture_ref, "resolves outside the sandbox")
        if found_inside_missing:
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
                    "created": datetime.fromtimestamp(stat.st_mtime, UTC).isoformat(),
                }
            )
        return entries

    def audit(self, tool: str, args: dict) -> None:
        record = {
            "ts": datetime.now(UTC).isoformat(),
            "tool": tool,
            "args": args,
        }
        with self.audit_log.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record) + "\n")
