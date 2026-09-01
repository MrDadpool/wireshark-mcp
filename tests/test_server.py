import asyncio

import pytest

import wireshark_mcp.server as server_mod
from wireshark_mcp.config import Config
from wireshark_mcp.errors import ErrorKind, ToolError
from wireshark_mcp.server import (
    EXPECTED_TOOLS,
    Context,
    build_context,
    capture_info,
    follow_stream,
    list_captures,
    mcp,
    packet_detail,
    packet_summary,
    start_capture,
    tool_result,
)


def test_tool_result_passes_a_value_through():
    assert tool_result(lambda: {"ok": True}) == {"ok": True}


def test_tool_result_converts_tool_error_to_dict():
    def boom():
        raise ToolError(ErrorKind.NOT_FOUND, "nope", hint="try list_captures")

    assert tool_result(boom) == {"error": "nope", "kind": "not_found", "hint": "try list_captures"}


def test_tool_result_converts_unexpected_exception_to_dict():
    def boom():
        raise RuntimeError("kaboom")

    result = tool_result(boom)
    assert result["kind"] == "capture_failed"
    assert "kaboom" in result["error"]


def test_build_context_wires_components(tmp_path):
    ctx = build_context(Config(workdir=tmp_path))
    assert ctx.store.captures_dir.is_dir()
    assert ctx.runner is not None and ctx.reader is not None


def test_registered_tool_names_match_expected():
    tools = asyncio.run(mcp.list_tools())
    names = {t.name for t in tools}
    assert names == set(EXPECTED_TOOLS)
    assert "run_tshark" not in names


@pytest.fixture(autouse=True)
def _reset_ctx_cache():
    server_mod._ctx = None
    yield
    server_mod._ctx = None


def test_start_capture_returns_error_dict_when_context_build_fails(monkeypatch):
    def boom(config=None):
        raise RuntimeError("bad config.toml")

    monkeypatch.setattr(server_mod, "build_context", boom)
    result = start_capture("en0")
    assert "error" in result and "kind" in result


def test_list_captures_returns_error_dict_when_context_build_fails(monkeypatch):
    def boom(config=None):
        raise RuntimeError("unwritable workdir")

    monkeypatch.setattr(server_mod, "build_context", boom)
    result = list_captures()
    assert "error" in result and "kind" in result


class FakeReader:
    def __init__(self):
        self.calls = []

    def summary(self, path, display_filter, limit):
        self.calls.append(("summary", path, display_filter, limit))
        return "summary-output"

    def detail(self, path, frame_no):
        self.calls.append(("detail", path, frame_no))
        return "detail-output"

    def info(self, path):
        self.calls.append(("info", path))
        return "info-output"

    def follow(self, path, protocol, index):
        self.calls.append(("follow", path, protocol, index))
        return "follow-output"


class BoomReader:
    def summary(self, *a, **k):
        raise ToolError(ErrorKind.CAPTURE_FAILED, "summary boom")

    def detail(self, *a, **k):
        raise ToolError(ErrorKind.CAPTURE_FAILED, "detail boom")

    def info(self, *a, **k):
        raise ToolError(ErrorKind.CAPTURE_FAILED, "info boom")

    def follow(self, *a, **k):
        raise ToolError(ErrorKind.CAPTURE_FAILED, "follow boom")


def _fake_ctx(tmp_path, reader):
    from wireshark_mcp.store import CaptureStore

    store = CaptureStore(Config(workdir=tmp_path))
    return Context(config=Config(workdir=tmp_path), store=store, reader=reader, runner=None)


def _touch_capture(ctx):
    capture_id, path = ctx.store.new_capture_path()
    path.write_bytes(b"")
    return capture_id


def test_packet_summary_returns_reader_output_on_success(tmp_path, monkeypatch):
    ctx = _fake_ctx(tmp_path, FakeReader())
    capture_id = _touch_capture(ctx)
    monkeypatch.setattr(server_mod, "_ctx", ctx)
    result = packet_summary(capture_id)
    assert result == {"output": "summary-output"}


def test_packet_summary_returns_error_dict_on_tool_error(tmp_path, monkeypatch):
    ctx = _fake_ctx(tmp_path, BoomReader())
    capture_id = _touch_capture(ctx)
    monkeypatch.setattr(server_mod, "_ctx", ctx)
    result = packet_summary(capture_id)
    assert result["kind"] == "capture_failed" and "summary boom" in result["error"]


def test_packet_detail_returns_reader_output_on_success(tmp_path, monkeypatch):
    ctx = _fake_ctx(tmp_path, FakeReader())
    capture_id = _touch_capture(ctx)
    monkeypatch.setattr(server_mod, "_ctx", ctx)
    result = packet_detail(capture_id, 1)
    assert result == {"output": "detail-output"}


def test_packet_detail_returns_error_dict_on_tool_error(tmp_path, monkeypatch):
    ctx = _fake_ctx(tmp_path, BoomReader())
    capture_id = _touch_capture(ctx)
    monkeypatch.setattr(server_mod, "_ctx", ctx)
    result = packet_detail(capture_id, 1)
    assert result["kind"] == "capture_failed" and "detail boom" in result["error"]


def test_capture_info_returns_reader_output_on_success(tmp_path, monkeypatch):
    ctx = _fake_ctx(tmp_path, FakeReader())
    capture_id = _touch_capture(ctx)
    monkeypatch.setattr(server_mod, "_ctx", ctx)
    result = capture_info(capture_id)
    assert result == {"output": "info-output"}


def test_capture_info_returns_error_dict_on_tool_error(tmp_path, monkeypatch):
    ctx = _fake_ctx(tmp_path, BoomReader())
    capture_id = _touch_capture(ctx)
    monkeypatch.setattr(server_mod, "_ctx", ctx)
    result = capture_info(capture_id)
    assert result["kind"] == "capture_failed" and "info boom" in result["error"]


def test_follow_stream_returns_reader_output_on_success(tmp_path, monkeypatch):
    ctx = _fake_ctx(tmp_path, FakeReader())
    capture_id = _touch_capture(ctx)
    monkeypatch.setattr(server_mod, "_ctx", ctx)
    result = follow_stream(capture_id)
    assert result == {"output": "follow-output"}


def test_follow_stream_returns_error_dict_on_tool_error(tmp_path, monkeypatch):
    ctx = _fake_ctx(tmp_path, BoomReader())
    capture_id = _touch_capture(ctx)
    monkeypatch.setattr(server_mod, "_ctx", ctx)
    result = follow_stream(capture_id)
    assert result["kind"] == "capture_failed" and "follow boom" in result["error"]
