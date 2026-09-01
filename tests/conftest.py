import subprocess
import threading

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

    # Loopback can be idle; generate deliberate traffic during the capture
    # window so the pcapng is guaranteed non-empty.
    pinger = threading.Thread(
        target=lambda: subprocess.run(
            ["ping", "-c", "3", "127.0.0.1"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    )
    pinger.start()
    try:
        result = runner.capture(loopbacks[0].id, duration_s=2, max_packets=20, bpf_filter=None)
    finally:
        pinger.join()
    return result["id"], config
