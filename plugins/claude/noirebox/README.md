# NoireBox for Claude Code

The tamper-evident journal inside Claude Code: every tool action and the
whole session transcript are sealed into a per-project hash-chained,
Ed25519-signed journal — and the session's flight recorder becomes
third-party-verifiable evidence (RFC 3161 / OpenTimestamps anchoring
available at the instance level).

## What it does

| Component | Role |
|---|---|
| Hook `PostToolUse` (Write/Edit/Bash) | Seals each agent tool action (type `agent_tool_use`) — tool name + truncated input preview only |
| Hook `SessionEnd` | Seals the session transcript (type `model_trajectory`, ADR 012/013) — digests only, the conversation text never enters the journal |
| MCP server `noirebox` | 4 tools: `noirebox_scan`, `noirebox_log_event`, `noirebox_verify`, `noirebox_attestation` |
| Commands `/noirebox-seal`, `/noirebox-verify`, `/noirebox-attest` | The three gestures, one keystroke away |
| Skill `noirebox-journal` | Teaches the agent the sealing/verification vocabulary and the honesty rules |

Hooks, MCP server and CLI all write the **same journal** (same SQLite file,
same Ed25519 key): the chain is one.

## Install

1. Install the engine once (anything that puts the entrypoints on `PATH`):
   ```bash
   pip install noirebox        # or: pipx install noirebox / uv tool install noirebox
   ```
2. Add the marketplace and install the plugin (inside Claude Code):
   ```
   /plugin marketplace add noirebox/noirebox
   /plugin install noirebox@noirebox
   ```
   (From a local clone of this repository, point the marketplace at the
   checkout path instead — the manifest lives at the repository root,
   `.claude-plugin/marketplace.json`.)
3. That is it. The journal appears at `.noirebox/journal.db` inside the
   project on the first seal — add `.noirebox/` to your `.gitignore`
   (or commit it deliberately, which is evidence publication and your call).

## Configuration

- `NOIREBOX_DB` — explicit journal path, wins over everything.
- Journal discovery (no env): the nearest ancestor directory holding a
  `.noirebox/` directory owns the journal; otherwise one is created in the
  working directory. One project = one journal.
- `NOIREBOX_HOOK_DISABLE=1` — pauses automatic sealing. Semantics are
  deliberate: OFF is a pause, past seals stay. There is no unseal — the
  journal is append-only, that is the product.
- `NOIREBOX_TSA_*` — RFC 3161 / OpenTimestamps anchoring profiles
  (see `docs/ADRs.md` ADR 008/009) on a running instance.

## Verify without trusting anyone

```bash
noirebox verify            # exit 0 = valid, exit 1 = tampered (first anomaly printed)
noirebox locate            # which journal am I writing to?
```

A third party verifies an export with the public key alone —
`verifier/verifier.py`, no NoireBox installation needed on their side.
