# wireshark-mcp — Project Tracking

Last updated: 2026-09-01

## Now
- Design spec approved in chat; awaiting user review of the written spec at
  `docs/superpowers/specs/2026-09-01-wireshark-mcp-design.md`.

## Next up
- User reviews spec.
- Write implementation plan (superpowers:writing-plans).
- Install Wireshark CLI tools locally (not yet present on this Mac).
- Implement: platform.py → CaptureStore → TsharkReader → CaptureRunner → tool layer.

## Done
- Requirements brainstormed: tshark CLI backend, live capture + file analysis,
  Python + official MCP SDK, core + analysis tools + resources/prompts,
  no arbitrary-argument escape hatch.
- Approach A chosen: synchronous bounded capture, with CaptureRunner as the seam
  for later background jobs.
- macOS + Windows both confirmed as first-class targets.
- Repo target: MrDadpool/wireshark-mcp (public).
- Design spec written.
