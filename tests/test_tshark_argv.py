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


def test_io_stats_rejects_non_integer_interval():
    with pytest.raises(ToolError) as caught:
        io_stats_argv(TSHARK, CAP, "notanint")
    assert caught.value.kind is ErrorKind.BAD_FILTER


def test_follow_rejects_non_integer_index():
    with pytest.raises(ToolError) as caught:
        follow_argv(TSHARK, CAP, "tcp", "notanint")
    assert caught.value.kind is ErrorKind.BAD_FILTER


def test_detail_rejects_non_integer_frame_number():
    with pytest.raises(ToolError) as caught:
        detail_argv(TSHARK, CAP, "notanint")
    assert caught.value.kind is ErrorKind.BAD_FILTER


def test_integer_like_strings_are_still_accepted():
    assert "frame.number==42" in detail_argv(TSHARK, CAP, "42")
    assert "io,stat,5" in io_stats_argv(TSHARK, CAP, "5")
