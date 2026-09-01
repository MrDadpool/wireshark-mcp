import pytest

from wireshark_mcp.errors import ToolError
from wireshark_mcp.store import CaptureStore
from wireshark_mcp.tshark import TsharkReader

pytestmark = pytest.mark.requires_tshark


def test_capture_info_runs_on_a_real_file(sample_capture):
    capture_id, config = sample_capture
    store, reader = CaptureStore(config), TsharkReader(config)
    assert "File name" in reader.info(store.resolve(capture_id))


def test_protocol_hierarchy_runs_on_a_real_file(sample_capture):
    capture_id, config = sample_capture
    store, reader = CaptureStore(config), TsharkReader(config)
    assert reader.hierarchy(store.resolve(capture_id)) is not None


def test_summary_with_a_valid_filter_runs(sample_capture):
    capture_id, config = sample_capture
    store, reader = CaptureStore(config), TsharkReader(config)
    assert reader.summary(store.resolve(capture_id), "ip", 10) is not None


def test_invalid_display_filter_is_rejected_before_reading(sample_capture):
    _, config = sample_capture
    with pytest.raises(ToolError) as caught:
        TsharkReader(config).validate_filter("this is not a filter (((")
    assert caught.value.kind == "bad_filter"
