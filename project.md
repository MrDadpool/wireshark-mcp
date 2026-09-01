# wireshark-mcp — Project Tracking

Last updated: 2026-09-01

## Now
- v0.1.0 complete and verified end to end. Registered in ~/.lmstudio/mcp.json;
  12 tools reachable over stdio, live loopback capture and analysis confirmed,
  path sandbox and capture ceilings confirmed to hold through real MCP calls.

## Next up
- Manually verify the server against LM Studio on macOS (and Windows, if available).
- Consider tagging a v0.1.0 release once manual verification passes.

## Done
- Requirements brainstormed: tshark CLI backend, live capture + file analysis,
  Python + official MCP SDK, core + analysis tools + resources/prompts,
  no arbitrary-argument escape hatch.
- Approach A chosen: synchronous bounded capture, with CaptureRunner as the seam
  for later background jobs.
- macOS + Windows both confirmed as first-class targets.
- Repo target: MrDadpool/wireshark-mcp (public).
- Design spec written.
- Implemented: platform.py, CaptureStore, TsharkReader, CaptureRunner, and the
  12-tool MCP server surface (list_interfaces, start_capture, list_captures,
  packet_summary, packet_detail, capture_info, protocol_hierarchy,
  conversations, endpoints, io_stats, expert_info, follow_stream).
- Adapted to the mcp 2.1.1 SDK (`FastMCP` renamed to `MCPServer`), and tightened
  the `mcp` dependency constraint to `>=2.0` to prevent installing an
  incompatible v1 SDK.
- Full test suite: 85 tests passing (81 unit + 4 integration, Wireshark
  installed locally), ruff clean.
- README, sample config (`examples/config.toml`), and CI workflow
  (`.github/workflows/ci.yml`, macos-latest + windows-latest) written.
