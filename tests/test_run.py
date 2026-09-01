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
