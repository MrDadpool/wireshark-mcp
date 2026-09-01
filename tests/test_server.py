from wireshark_mcp.config import Config
from wireshark_mcp.errors import ErrorKind, ToolError
from wireshark_mcp.server import EXPECTED_TOOLS, build_context, tool_result


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


def test_expected_tool_names_are_declared():
    assert "start_capture" in EXPECTED_TOOLS
    assert "follow_stream" in EXPECTED_TOOLS
    assert "run_tshark" not in EXPECTED_TOOLS
    assert len(EXPECTED_TOOLS) == 12
