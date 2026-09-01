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
