# tests/test_run.py
import shutil
import subprocess
import sys
import time

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


def test_check_does_not_upgrade_unrelated_errors():
    result = run_command(
        [sys.executable, "-c",
         "import sys; sys.stderr.write('syntax error in filter'); raise SystemExit(2)"],
        timeout_s=10,
    )
    with pytest.raises(ToolError) as caught:
        check(result, ErrorKind.BAD_FILTER, "filter check")
    assert caught.value.kind is ErrorKind.BAD_FILTER


@pytest.mark.skipif(shutil.which("pgrep") is None, reason="pgrep not available")
def test_timeout_kills_the_child_and_its_descendants(tmp_path):
    """The child spawns a grandchild; only a process-group kill reaps both."""
    marker = "wireshark-mcp-orphan-marker"
    script = tmp_path / "spawner.py"
    script.write_text(
        "import subprocess, sys, time\n"
        f"subprocess.Popen([sys.executable, '-c', \"# {marker}\\nimport time; time.sleep(30)\"])\n"
        "time.sleep(30)\n"
    )
    with pytest.raises(ToolError):
        run_command([sys.executable, str(script)], timeout_s=2)

    time.sleep(0.5)  # let the signal land
    survivors = subprocess.run(
        ["pgrep", "-f", marker], capture_output=True, text=True, check=False
    ).stdout.strip()
    if survivors:
        subprocess.run(["pkill", "-f", marker], check=False)  # never leak test processes
    assert survivors == "", f"grandchild survived the timeout: {survivors}"
