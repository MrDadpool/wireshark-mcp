# wireshark-mcp

An MCP server that exposes Wireshark's CLI tools (`tshark`, `dumpcap`,
`capinfos`) to a local LLM client. It lets a model start bounded live
captures and analyze existing capture files — packet summaries, protocol
hierarchies, conversations, endpoints, expert info, stream reassembly —
without ever handing it a shell.

## Security

This server lets a local language model capture and read your network traffic.
That is its purpose, and you should install it only if you want that.

What it does to stay bounded:

- **No shell.** Every subprocess runs with `shell=False` and an argument list
  built in code. The model supplies typed values, never flags.
- **No arbitrary-command tool.** There is no `run_tshark`. The tool surface is fixed.
- **Path sandbox.** Capture files are read only from the server's own workdir and
  from directories you list in `read_only_dirs`. Traversal, symlink escapes, UNC
  paths, and drive-relative paths are rejected.
- **Bounded captures.** Every capture requires both a duration and a packet cap,
  ceilings 300 seconds and 100,000 packets. An unbounded capture cannot be requested.
- **Interface allowlist.** Set `interface_allowlist` to limit which interfaces
  can be captured on.
- **Audit log.** Every capture and every read is appended to `audit.log` in the workdir.

What it does not protect you from: captured packets contain whatever crossed the
wire, including credentials sent over cleartext protocols. Anything the model
reads from a capture is in the model's context.

## Prerequisites

Wireshark (which bundles `tshark`, `dumpcap`, and `capinfos`) must be
installed and on `PATH`, or pointed to explicitly in `config.toml`.

Supported platforms: **macOS** and **Windows**. Linux is expected to work but
is untested and is not a release target.

**macOS**

- Install Wireshark (e.g. `brew install --cask wireshark`).
- For non-root live capture, install ChmodBPF (bundled with the Wireshark
  installer/cask) so your user can open `/dev/bpf*`. Without it, live
  capture requires running as root; file analysis works regardless.

**Windows**

- Install Wireshark, which offers to install **Npcap** — required for live
  capture.
- If Npcap was installed with "Restrict Npcap driver's access to
  Administrators only", the MCP client (e.g. LM Studio) must run elevated
  for live capture to work. File analysis works either way.

## Install and run

```bash
uvx --from git+https://github.com/MrDadpool/wireshark-mcp wireshark-mcp
```

This runs the `wireshark-mcp` console script (`wireshark_mcp.server:main`)
over stdio, for use by any MCP-speaking client.

## Use with LM Studio

Add to LM Studio's `mcp.json` (Program → Install → Edit mcp.json):

```json
{
  "mcpServers": {
    "wireshark": {
      "command": "uvx",
      "args": ["--from", "git+https://github.com/MrDadpool/wireshark-mcp", "wireshark-mcp"]
    }
  }
}
```

On Windows, if Npcap was installed with "Restrict Npcap driver's access to
Administrators only", LM Studio must run elevated for live capture to work.
File analysis works either way.

## Tools

There are 12 tools. Ceilings: `duration_s` <= 300, `max_packets` <= 100,000,
`limit` <= 500.

| Tool | Parameters | Description |
| --- | --- | --- |
| `list_interfaces` | — | List capture interfaces, with whether live capture is currently permitted. |
| `start_capture` | `interface`, `duration_s=10`, `max_packets=1000`, `bpf_filter=""` | Capture live packets on an interface. Always bounded by both duration and packet count. |
| `list_captures` | — | List capture files this server has stored. |
| `packet_summary` | `capture`, `display_filter=""`, `limit=100` | One line per packet, optionally narrowed by a Wireshark display filter. |
| `packet_detail` | `capture`, `frame_no` | Full decoded protocol tree for a single frame. |
| `capture_info` | `capture` | `capinfos` summary: packet count, duration, byte totals, encapsulation. |
| `protocol_hierarchy` | `capture` | Protocol hierarchy statistics for the whole capture. |
| `conversations` | `capture`, `type="tcp"` | Conversation statistics. `type` is one of `tcp`, `udp`, `ip`, `eth`. |
| `endpoints` | `capture`, `type="ip"` | Endpoint statistics. `type` is one of `tcp`, `udp`, `ip`, `eth`. |
| `io_stats` | `capture`, `interval_s=1` | Traffic volume over time, bucketed by `interval_s` seconds. |
| `expert_info` | `capture` | Wireshark expert info: retransmissions, resets, malformed packets, warnings. |
| `follow_stream` | `capture`, `protocol="tcp"`, `index=0` | Reassemble one stream as ASCII. `protocol` is one of `tcp`, `udp`, `http`. |

There is deliberately no `run_tshark` or other arbitrary-command tool.

## Configuration

The server reads an optional TOML file from its workdir:

- macOS: `~/.wireshark-mcp/config.toml`
- Windows: `%LOCALAPPDATA%\wireshark-mcp\config.toml`

See [`examples/config.toml`](examples/config.toml) for every available
setting (`workdir`, `read_only_dirs`, `interface_allowlist`, and
`[binaries]` overrides for `tshark`/`dumpcap`/`capinfos`). Every setting is
optional; a missing file is not an error.

## Development

```bash
uv sync --extra dev
uv run ruff check .
uv run pytest -v
```

Tests are split into unit tests (always run) and two markers that require
local capabilities not present on CI runners:

- `requires_tshark` — needs a resolvable `tshark` binary.
- `requires_capture` — needs live capture permission on the host.

CI (`.github/workflows/ci.yml`) runs on `macos-latest` and `windows-latest`,
where Wireshark is not installed, so those two tiers skip there; that is
expected. The platform, sandbox, argv, and error tests are what CI actually
guards, and they are the tests that catch cross-platform regressions.
