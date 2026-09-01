"""Structured errors. Tools return these as dicts; they never raise at the MCP boundary."""

from __future__ import annotations

from enum import StrEnum


class ErrorKind(StrEnum):
    BINARY_MISSING = "binary_missing"
    PERMISSION_DENIED = "permission_denied"
    BAD_INTERFACE = "bad_interface"
    BAD_FILTER = "bad_filter"
    PATH_REJECTED = "path_rejected"
    LIMIT_EXCEEDED = "limit_exceeded"
    CAPTURE_FAILED = "capture_failed"
    NOT_FOUND = "not_found"


class ToolError(Exception):
    """An error a tool can report to the model without crashing the server."""

    def __init__(self, kind: ErrorKind, message: str, hint: str = "") -> None:
        super().__init__(message)
        self.kind = kind
        self.message = message
        self.hint = hint


def error_dict(exc: ToolError) -> dict[str, str]:
    return {"error": exc.message, "kind": str(exc.kind), "hint": exc.hint}
