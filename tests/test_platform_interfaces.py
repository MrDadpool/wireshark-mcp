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
