# tests/test_platform_binaries.py
import pytest

from wireshark_mcp.errors import ErrorKind, ToolError
from wireshark_mcp.platform import candidate_dirs, find_binary


def test_windows_candidates_include_program_files():
    dirs = [str(p) for p in candidate_dirs("Windows")]
    assert any("Wireshark" in d for d in dirs)


def test_darwin_candidates_include_app_bundle_and_homebrew():
    dirs = [str(p) for p in candidate_dirs("Darwin")]
    assert any("Wireshark.app/Contents/MacOS" in d for d in dirs)
    assert any("homebrew" in d or "/usr/local/bin" in d for d in dirs)


def test_override_wins(tmp_path):
    exe = tmp_path / "tshark"
    exe.write_text("")
    exe.chmod(0o755)
    assert find_binary("tshark", system="Darwin", override=str(exe)) == exe


def test_override_that_does_not_exist_is_an_error(tmp_path):
    with pytest.raises(ToolError) as caught:
        find_binary("tshark", system="Darwin", override=str(tmp_path / "nope"))
    assert caught.value.kind is ErrorKind.BINARY_MISSING


def test_found_on_path(tmp_path):
    exe = tmp_path / "tshark"
    exe.write_text("")
    exe.chmod(0o755)
    assert find_binary("tshark", system="Darwin", path_env=str(tmp_path)) == exe


def test_windows_appends_exe_suffix(tmp_path):
    exe = tmp_path / "tshark.exe"
    exe.write_text("")
    exe.chmod(0o755)
    found = find_binary("tshark", system="Windows", path_env=str(tmp_path))
    assert found.name == "tshark.exe"


def test_missing_binary_raises_with_install_hint(tmp_path, monkeypatch):
    monkeypatch.setattr("wireshark_mcp.platform.candidate_dirs", lambda system: [])
    with pytest.raises(ToolError) as caught:
        find_binary("tshark", system="Darwin", path_env=str(tmp_path))
    assert caught.value.kind is ErrorKind.BINARY_MISSING
    assert caught.value.hint


def test_found_in_candidate_dir_when_not_on_path(tmp_path, monkeypatch):
    install_dir = tmp_path / "install"
    install_dir.mkdir()
    empty_path_dir = tmp_path / "empty"
    empty_path_dir.mkdir()
    exe = install_dir / "tshark"
    exe.write_text("")
    exe.chmod(0o755)
    monkeypatch.setattr("wireshark_mcp.platform.candidate_dirs", lambda system: [install_dir])
    assert find_binary("tshark", system="Darwin", path_env=str(empty_path_dir)) == exe
