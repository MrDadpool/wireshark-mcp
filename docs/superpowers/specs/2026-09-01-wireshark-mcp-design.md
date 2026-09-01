# wireshark-mcp — Design

Date: 2026-09-01
Status: Approved (design). Implementation plan pending.
Repo: https://github.com/MrDadpool/wireshark-mcp (public)
Local path: /Users/davidmartinez/wireshark-mcp

## Purpose

An MCP server that lets a local LLM (primary client: LM Studio) drive Wireshark's
command-line tooling — enumerate interfaces, run bounded live captures, and read,
filter, and summarize capture files — without ever executing an arbitrary command
the model composed.

Non-goal: controlling the Wireshark GUI. Non-goal: an arbitrary `run_tshark`
escape hatch.

## Platforms

macOS and Windows are both first-class. Linux is expected to work but is not a
release target and is untested.

| Concern | macOS | Windows |
| --- | --- | --- |
| Capture driver | BPF devices (`/dev/bpf*`) | Npcap |
| Binaries | `/Applications/Wireshark.app/Contents/MacOS/{tshark,dumpcap,capinfos}`, or Homebrew `$(brew --prefix)/bin` | `C:\Program Files\Wireshark\{tshark,dumpcap,capinfos}.exe` |
| Privilege for live capture | membership in `access_bpf` (installed by Wireshark's ChmodBPF) | Npcap installed **without** "restrict to administrators", else the process must be elevated |
| Interface identifiers | short names (`en0`, `lo0`) | NPF GUID paths (`\Device\NPF_{GUID}`) with a separate human-readable description |
| Loopback capture | `lo0` | requires Npcap's "Npcap Loopback Adapter" |

A `platform.py` module resolves binaries and normalizes interfaces so the rest of
the codebase is platform-agnostic. Interface identity is always the opaque string
`dumpcap -D` reports; the human-readable description is carried alongside it for
the model's benefit and is never used as an argument.

Binary resolution order, both platforms: explicit config path → `PATH` → known
install locations for that OS. If nothing resolves, every tool returns a
structured error naming the platform's install command rather than failing at the
subprocess layer.

## Architecture

```
LM Studio ──stdio (JSON-RPC)──► wireshark-mcp (Python, uv)
                                   │
                                   ├─ platform.py    → binary + interface resolution
                                   ├─ CaptureRunner  → dumpcap (live, bounded)
                                   ├─ TsharkReader   → tshark -r (read/filter/stats)
                                   └─ CaptureStore   → <workdir>/captures/*.pcapng
```

Single process, stdio transport, launched by the client from its MCP config.
Python with the official `mcp` SDK (FastMCP), run via `uv`.

### Component contracts

**`platform.py`** — resolves `tshark`, `dumpcap`, `capinfos` paths; reports OS
capture-permission status; parses `dumpcap -D` into `{id, description, loopback}`
records. Depends on: nothing but stdlib.

**`CaptureStore`** — owns the workdir (`~/.wireshark-mcp` on macOS,
`%LOCALAPPDATA%\wireshark-mcp` on Windows). Allocates capture ids, resolves any
caller-supplied path, and rejects anything that does not resolve inside the
workdir or a configured read-only directory. Sole authority on paths.

**`CaptureRunner`** — takes a validated capture request, builds a `dumpcap` argv,
runs it to completion under a hard timeout, returns a capture id. This class is
the single seam where background/async capture jobs would later be added without
touching the tool layer.

**`TsharkReader`** — builds `tshark -r` argv for reads and `-z` statistics, runs
them, parses JSON or text output. Pure argv construction is separated from
execution so it can be unit-tested with no Wireshark installed.

## Tool surface

Core
- `list_interfaces()` → id, description, loopback flag, whether capture is currently permitted
- `start_capture(interface, bpf_filter?, duration_s, max_packets)` → capture id + summary
- `list_captures()` → ids, sizes, packet counts, creation times
- `packet_summary(capture, display_filter?, limit)` → one line per packet
- `packet_detail(capture, frame_no)` → full decoded tree for one frame
- `capture_info(capture)` → `capinfos` output

Analysis (all `tshark -z` wrappers)
- `protocol_hierarchy(capture)`
- `conversations(capture, type)` / `endpoints(capture, type)` — type ∈ tcp, udp, ip, eth
- `io_stats(capture, interval_s)`
- `expert_info(capture)`
- `follow_stream(capture, protocol, index)` — protocol ∈ tcp, udp, http

Resources
- `capture://<id>` for each stored capture

Prompts
- `triage_capture`, `tls_failures`, `find_slow_requests`

## Safety rails

The threat model is a local LLM with the ability to observe network traffic and
to influence the arguments of a local subprocess. Both are addressed explicitly.

1. **No shell, ever.** Every subprocess is `subprocess.run(argv_list, shell=False)`
   with an argv assembled in code. The model supplies typed values that land in
   known argv positions; it never supplies a flag.
2. **No arbitrary-argument tool.** `run_tshark` is deliberately absent.
3. **Path sandbox.** All file arguments resolve through `CaptureStore`; anything
   outside the workdir or a configured read-only directory is rejected before a
   subprocess is spawned. Covers `..`, symlinks, absolute paths, and on Windows
   drive-relative paths and UNC paths.
4. **Hard ceilings**, enforced server-side and not raisable by the model:
   `duration_s ≤ 300`, `max_packets ≤ 100_000`, `limit ≤ 500`.
   Every capture supplies both a duration and a packet cap; unbounded captures
   cannot be expressed.
5. **Interface allowlist** in `config.toml`, shipped pre-populated with the host's
   real interfaces so it is opt-out rather than opt-in.
6. **Filter validation.** BPF and display filters are passed as single argv values
   and validated by a dry run against an empty file before use, so a malformed or
   hostile filter fails in validation rather than in a capture.
7. **Audit log.** Every capture start and every tool invocation is appended to
   `audit.log` in the workdir with timestamp, tool, and arguments.
8. **Stated plainly in the README:** installing this server lets a local model
   sniff the host's network traffic and read whatever those packets contain,
   including credentials in cleartext protocols. That is the intended function,
   and it is the user's decision to make knowingly.

## Error handling

Every tool returns a structured error rather than raising: `{error, kind, hint}`.
Kinds: `binary_missing`, `permission_denied`, `bad_interface`, `bad_filter`,
`path_rejected`, `limit_exceeded`, `capture_failed`, `not_found`. The `hint`
carries the platform-appropriate remedy (e.g. install command, ChmodBPF, Npcap
permission setting). A missing Wireshark install must never surface as a raw
`FileNotFoundError`.

## Testing

`pytest`.

- **No-Wireshark tests (the majority, always run):** argv builders, path sandbox
  including Windows-specific path forms, limit clamping, config parsing,
  `dumpcap -D` parsing against recorded macOS and Windows fixture output, error
  mapping.
- **`@pytest.mark.requires_tshark`:** parsing real `tshark -r` and `-z` output
  against a small checked-in `.pcapng` fixture. Skipped when no binary resolves.
- **`@pytest.mark.requires_capture`:** one live loopback capture with a 2-second
  ceiling. Skipped when capture permission is unavailable, which keeps CI green.
- CI runs the no-Wireshark tier on both `macos-latest` and `windows-latest`, and
  the `requires_tshark` tier on runners where Wireshark is installable.

## Install & client wiring

`uvx --from git+https://github.com/MrDadpool/wireshark-mcp wireshark-mcp`

LM Studio `mcp.json`:

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

Prerequisite, stated per platform in the README: Wireshark's CLI tools must be
installed — `brew install --cask wireshark` on macOS (which also installs
ChmodBPF, required for non-root capture), and the Wireshark installer with Npcap
on Windows.

## Deferred (YAGNI)

Background/async capture jobs, remote HTTP transport, Wireshark GUI control,
Lua plugin integration, ring-buffer and rotating captures, Linux as a supported
target.
