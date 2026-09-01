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
