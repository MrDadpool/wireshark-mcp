"""MCP surface: tools, resources, and prompts over stdio."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from mcp.server.mcpserver import MCPServer

from .capture import CaptureRunner
from .config import MAX_LIMIT, Config, clamp, load_config
from .errors import ErrorKind, ToolError, error_dict
from .platform import capture_permitted
from .store import CaptureStore
from .tshark import TsharkReader

EXPECTED_TOOLS = (
    "list_interfaces",
    "start_capture",
    "list_captures",
    "packet_summary",
    "packet_detail",
    "capture_info",
    "protocol_hierarchy",
    "conversations",
    "endpoints",
    "io_stats",
    "expert_info",
    "follow_stream",
)


@dataclass(frozen=True)
class Context:
    config: Config
    store: CaptureStore
    reader: TsharkReader
    runner: CaptureRunner


def build_context(config: Config | None = None) -> Context:
    config = config or load_config()
    store = CaptureStore(config)
    return Context(
        config=config,
        store=store,
        reader=TsharkReader(config),
        runner=CaptureRunner(config, store),
    )


def tool_result(fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    """Run a tool body, converting any failure into a structured dict."""
    try:
        return fn(*args, **kwargs)
    except ToolError as exc:
        return error_dict(exc)
    except Exception as exc:  # noqa: BLE001 - never let an unexpected error kill the session
        return error_dict(ToolError(ErrorKind.CAPTURE_FAILED, f"unexpected error: {exc}"))


mcp = MCPServer("wireshark")
_ctx: Context | None = None


def ctx() -> Context:
    global _ctx
    if _ctx is None:
        _ctx = build_context()
    return _ctx


# -- tools ---------------------------------------------------------------


@mcp.tool()
def list_interfaces() -> Any:
    """List capture interfaces, with whether live capture is currently permitted."""

    def body():
        ok, why = capture_permitted()
        return {
            "capture_permitted": ok,
            "permission_note": why,
            "interfaces": [
                {"id": i.id, "description": i.description, "loopback": i.loopback}
                for i in ctx().runner.list_interfaces()
            ],
        }

    return tool_result(body)


@mcp.tool()
def start_capture(
    interface: str,
    duration_s: int = 10,
    max_packets: int = 1000,
    bpf_filter: str = "",
) -> Any:
    """Capture live packets on an interface. Always bounded by BOTH duration_s and max_packets."""

    def body():
        return ctx().runner.capture(interface, duration_s, max_packets, bpf_filter or None)

    return tool_result(body)


@mcp.tool()
def list_captures() -> Any:
    """List capture files this server has stored."""

    def body():
        return ctx().store.list_captures()

    return tool_result(body)


@mcp.tool()
def packet_summary(capture: str, display_filter: str = "", limit: int = 100) -> Any:
    """One line per packet, optionally narrowed by a Wireshark display filter."""

    def body():
        path = ctx().store.resolve(capture)
        capped = clamp(limit, MAX_LIMIT, "limit")
        return {"output": ctx().reader.summary(path, display_filter or None, capped)}

    return tool_result(body)


@mcp.tool()
def packet_detail(capture: str, frame_no: int) -> Any:
    """Full decoded protocol tree for a single frame."""

    def body():
        path = ctx().store.resolve(capture)
        return {"output": ctx().reader.detail(path, frame_no)}

    return tool_result(body)


@mcp.tool()
def capture_info(capture: str) -> Any:
    """capinfos summary: packet count, duration, byte totals, encapsulation."""

    def body():
        return {"output": ctx().reader.info(ctx().store.resolve(capture))}

    return tool_result(body)


@mcp.tool()
def protocol_hierarchy(capture: str) -> Any:
    """Protocol hierarchy statistics for the whole capture."""

    def body():
        return {"output": ctx().reader.hierarchy(ctx().store.resolve(capture))}

    return tool_result(body)


@mcp.tool()
def conversations(capture: str, type: str = "tcp") -> Any:
    """Conversation statistics. type is one of tcp, udp, ip, eth."""

    def body():
        return {"output": ctx().reader.stats(ctx().store.resolve(capture), "conv", type)}

    return tool_result(body)


@mcp.tool()
def endpoints(capture: str, type: str = "ip") -> Any:
    """Endpoint statistics. type is one of tcp, udp, ip, eth."""

    def body():
        return {"output": ctx().reader.stats(ctx().store.resolve(capture), "endpoints", type)}

    return tool_result(body)


@mcp.tool()
def io_stats(capture: str, interval_s: int = 1) -> Any:
    """Traffic volume over time, bucketed by interval_s seconds."""

    def body():
        return {"output": ctx().reader.io_stats(ctx().store.resolve(capture), interval_s)}

    return tool_result(body)


@mcp.tool()
def expert_info(capture: str) -> Any:
    """Wireshark expert info: retransmissions, resets, malformed packets, warnings."""

    def body():
        return {"output": ctx().reader.expert(ctx().store.resolve(capture))}

    return tool_result(body)


@mcp.tool()
def follow_stream(capture: str, protocol: str = "tcp", index: int = 0) -> Any:
    """Reassemble one stream as ASCII. protocol is one of tcp, udp, http."""

    def body():
        return {"output": ctx().reader.follow(ctx().store.resolve(capture), protocol, index)}

    return tool_result(body)


# -- resources -----------------------------------------------------------


@mcp.resource("capture://{capture_id}")
def capture_resource(capture_id: str) -> str:
    """Metadata for one stored capture."""
    result = tool_result(lambda: ctx().reader.info(ctx().store.resolve(capture_id)))
    return result if isinstance(result, str) else json.dumps(result)


# -- prompts -------------------------------------------------------------


@mcp.prompt()
def triage_capture(capture: str) -> str:
    return (
        f"Triage the capture {capture}. Start with capture_info and protocol_hierarchy, "
        "then expert_info. Report what protocols dominate, any errors or retransmissions, "
        "and the top talkers from conversations. Do not dump raw packets unless something "
        "specific needs a closer look."
    )


@mcp.prompt()
def tls_failures(capture: str) -> str:
    return (
        f"In capture {capture}, find failed or unusual TLS handshakes. Use packet_summary "
        "with display filters such as 'tls.handshake.type == 1', 'tls.alert_message', and "
        "'tcp.flags.reset == 1'. For each failure report client, server, SNI if present, and "
        "the alert or reset that ended it."
    )


@mcp.prompt()
def find_slow_requests(capture: str) -> str:
    return (
        f"In capture {capture}, find slow request/response pairs. Use io_stats for an overview, "
        "then packet_summary with 'http.time > 1' or 'tcp.analysis.ack_rtt > 1'. Report the "
        "slowest exchanges with their endpoints and elapsed time."
    )


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
