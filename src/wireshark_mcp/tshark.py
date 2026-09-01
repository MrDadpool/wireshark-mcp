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


def _as_int(value: object, name: str) -> int:
    """Coerce a model-supplied value to int, as a ToolError rather than a ValueError."""
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise ToolError(
            ErrorKind.BAD_FILTER,
            f"{name} must be an integer, got {value!r}",
        ) from exc


def summary_argv(
    tshark: Path, path: Path, display_filter: str | None, limit: int
) -> list[str]:
    argv = [str(tshark), "-r", str(path)]
    if display_filter:
        argv += ["-Y", display_filter]
    argv += ["-c", str(limit)]
    return argv


def detail_argv(tshark: Path, path: Path, frame_no: int) -> list[str]:
    frame_no = _as_int(frame_no, "frame_no")
    return [str(tshark), "-r", str(path), "-Y", f"frame.number=={frame_no}", "-V"]


def stats_argv(tshark: Path, path: Path, kind: str, stat_type: str) -> list[str]:
    _validate(kind, frozenset({"conv", "endpoints"}), "kind")
    _validate(stat_type, STAT_TYPES, "type")
    return [str(tshark), "-r", str(path), "-q", "-z", f"{kind},{stat_type}"]


def hierarchy_argv(tshark: Path, path: Path) -> list[str]:
    return [str(tshark), "-r", str(path), "-q", "-z", "io,phs"]


def io_stats_argv(tshark: Path, path: Path, interval_s: int) -> list[str]:
    interval_s = _as_int(interval_s, "interval_s")
    return [str(tshark), "-r", str(path), "-q", "-z", f"io,stat,{interval_s}"]


def expert_argv(tshark: Path, path: Path) -> list[str]:
    return [str(tshark), "-r", str(path), "-q", "-z", "expert"]


def follow_argv(tshark: Path, path: Path, protocol: str, index: int) -> list[str]:
    _validate(protocol, FOLLOW_PROTOCOLS, "protocol")
    index = _as_int(index, "index")
    return [
        str(tshark), "-r", str(path), "-q", "-z",
        f"follow,{protocol},ascii,{index}",
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
            dftest = find_binary("dftest", override=self._config.dftest_path)
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
