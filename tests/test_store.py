import json

import pytest

from wireshark_mcp.config import Config
from wireshark_mcp.errors import ErrorKind, ToolError
from wireshark_mcp.store import CaptureStore


@pytest.fixture
def store(tmp_path):
    return CaptureStore(Config(workdir=tmp_path))


def test_creates_captures_dir(store, tmp_path):
    assert store.captures_dir == tmp_path / "captures"
    assert store.captures_dir.is_dir()


def test_new_capture_path_is_unique_and_inside_sandbox(store):
    id_a, path_a = store.new_capture_path()
    id_b, _path_b = store.new_capture_path()
    assert id_a != id_b
    assert path_a.suffix == ".pcapng"
    assert path_a.parent == store.captures_dir


def test_resolve_accepts_bare_capture_id(store):
    capture_id, path = store.new_capture_path()
    path.write_bytes(b"")
    assert store.resolve(capture_id) == path


def test_resolve_accepts_bare_filename(store):
    _capture_id, path = store.new_capture_path()
    path.write_bytes(b"")
    assert store.resolve(path.name) == path


def test_resolve_rejects_traversal(store):
    with pytest.raises(ToolError) as caught:
        store.resolve("../../etc/passwd")
    assert caught.value.kind is ErrorKind.PATH_REJECTED


def test_resolve_rejects_absolute_path_outside_sandbox(store):
    with pytest.raises(ToolError) as caught:
        store.resolve("/etc/passwd")
    assert caught.value.kind is ErrorKind.PATH_REJECTED


def test_resolve_rejects_unc_paths(store):
    with pytest.raises(ToolError) as caught:
        store.resolve(r"\\server\share\x.pcapng")
    assert caught.value.kind is ErrorKind.PATH_REJECTED
    assert "UNC" in caught.value.message


def test_resolve_rejects_forward_slash_unc_paths(store):
    with pytest.raises(ToolError) as caught:
        store.resolve("//server/share/x.pcapng")
    assert caught.value.kind is ErrorKind.PATH_REJECTED
    assert "UNC" in caught.value.message


def test_resolve_rejects_drive_relative_paths(store):
    with pytest.raises(ToolError) as caught:
        store.resolve("C:sneaky.pcapng")
    assert caught.value.kind is ErrorKind.PATH_REJECTED


def test_resolve_rejects_rooted_windows_path_outside_sandbox(store):
    """Allowed past the drive check, then rejected by the sandbox check."""
    with pytest.raises(ToolError) as caught:
        store.resolve(r"C:\Windows\System32\config\SAM")
    assert caught.value.kind is ErrorKind.PATH_REJECTED


def test_resolve_rejects_symlink_escaping_sandbox(store, tmp_path):
    outside = tmp_path / "outside.pcapng"
    outside.write_bytes(b"")
    link = store.captures_dir / "sneaky.pcapng"
    link.symlink_to(outside)
    with pytest.raises(ToolError) as caught:
        store.resolve("sneaky.pcapng")
    assert caught.value.kind is ErrorKind.PATH_REJECTED


def test_resolve_missing_file_is_not_found(store):
    with pytest.raises(ToolError) as caught:
        store.resolve("cap-nope.pcapng")
    assert caught.value.kind is ErrorKind.NOT_FOUND


def test_resolve_allows_configured_read_only_dir(tmp_path):
    ro = tmp_path / "ro"
    ro.mkdir()
    sample = ro / "sample.pcapng"
    sample.write_bytes(b"")
    store = CaptureStore(Config(workdir=tmp_path / "wd", read_only_dirs=(ro,)))
    assert store.resolve(str(sample)) == sample.resolve()


def test_list_captures_reports_metadata(store):
    _, path = store.new_capture_path()
    path.write_bytes(b"1234")
    entries = store.list_captures()
    assert len(entries) == 1
    assert entries[0]["size_bytes"] == 4


def test_audit_appends_a_line(store):
    store.audit("start_capture", {"interface": "en0"})
    store.audit("packet_summary", {"capture": "cap-x"})
    assert len(store.audit_log.read_text().strip().splitlines()) == 2


def test_resolve_success_writes_audit_record(store):
    capture_id, path = store.new_capture_path()
    path.write_bytes(b"")
    store.resolve(capture_id)
    lines = store.audit_log.read_text().strip().splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["tool"] == "resolve"
    assert record["args"]["ref"] == capture_id
    assert record["args"]["resolved"] == str(path)


def test_resolve_rejection_writes_audit_record_naming_reason(store):
    with pytest.raises(ToolError):
        store.resolve("../../etc/passwd")
    lines = store.audit_log.read_text().strip().splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["tool"] == "resolve_rejected"
    assert record["args"]["ref"] == "../../etc/passwd"
    assert record["args"]["reason"]


def test_audit_log_is_valid_json_lines(store):
    capture_id, path = store.new_capture_path()
    path.write_bytes(b"")
    store.resolve(capture_id)
    with pytest.raises(ToolError):
        store.resolve("/etc/passwd")
    lines = store.audit_log.read_text().strip().splitlines()
    assert len(lines) == 2
    for line in lines:
        record = json.loads(line)
        assert "ts" in record and "tool" in record and "args" in record


def test_resolve_rejects_embedded_nul_byte(store):
    with pytest.raises(ToolError) as caught:
        store.resolve("cap-\x00nope")
    assert caught.value.kind is ErrorKind.PATH_REJECTED
