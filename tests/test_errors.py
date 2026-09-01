import pytest

from wireshark_mcp.errors import ErrorKind, ToolError, error_dict


def test_error_kind_values_are_lowercase_strings():
    assert ErrorKind.BINARY_MISSING == "binary_missing"
    assert ErrorKind.PATH_REJECTED == "path_rejected"


def test_error_dict_shape():
    exc = ToolError(ErrorKind.BAD_FILTER, "bad display filter", hint="check syntax")
    assert error_dict(exc) == {
        "error": "bad display filter",
        "kind": "bad_filter",
        "hint": "check syntax",
    }


def test_error_dict_hint_defaults_to_empty():
    exc = ToolError(ErrorKind.NOT_FOUND, "no such capture")
    assert error_dict(exc)["hint"] == ""


def test_tool_error_is_raisable_and_carries_kind():
    with pytest.raises(ToolError) as caught:
        raise ToolError(ErrorKind.LIMIT_EXCEEDED, "too many packets")
    assert caught.value.kind is ErrorKind.LIMIT_EXCEEDED
