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
