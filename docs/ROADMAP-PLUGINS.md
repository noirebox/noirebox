# Plugin roadmap — NoireBox across the agent ecosystem

*Where NoireBox integrates, in what order, and what each agent can honestly
give us. Companion to ADR 013 (transcript-agnostic sealing, per-project
journals, generic hook handlers).*

---

## The one rule that orders everything

The core stays single. `trajectory.py` / `transcripts.py` / `trajseal.py` /
`hookcli.py` / the MCP server are shared by every integration; a plugin is
ONLY glue — a manifest, a hook JSON file, command docs, a README. If an
integration needs a core change, the core changes once, for everyone.

And the honesty rule that bounds the ambition: an agent that exposes
neither hooks, nor MCP, nor a per-call log **cannot be flight-recorded**.
For those, NoireBox is the on-demand custody layer (seal / verify / attest
via MCP) — we never claim automatic sealing where the app gives us nothing.

## Integration matrix

| App | Auto-sealing available | Surface | Status |
|---|---|---|---|
| Claude Code | ✅ hooks (`PostToolUse`, `SessionEnd`) + session transcripts | plugin + MCP | **shipped** (`plugins/claude/`) |
| Hook-native agents (per-call JSONL + hooks) | ✅ `noirebox hook` + `seal-trajectory --rollout` | plugin | shipped (first agent plugin) |
| MCP-capable agents (Cursor, Windsurf, Gemini CLI, Cline, Continue…) | ➖ on-demand custody (scan, seal, verify, attest) | MCP config snippet | docs (P3) |
| VSCode + Copilot (agent mode) | ✅ glue commands over the CLI (source) | MCP + VSIX extension | P2 shipped |
| Anything else with a JSONL log | ✅ `seal-trajectory --format auto` | one CLI call | shipped |

## Phases

### P0 — the portable core (shipped, ADR 013)
- Entry points from any install: `noirebox`, `noirebox-mcp` (`pip install
  noirebox`, pipx, uv) — no repository checkout required by integrations.
- Per-project journals: `NOIREBOX_DB` > nearest ancestor `.noirebox/` >
  create `./.noirebox/` (0700). One project = one journal.
- Shape-not-product log formats (`model-io`, `session-transcript`,
  `generic-jsonl`) behind one reader, one event type, one digest chain.
- Generic hook handlers: `noirebox hook tool-use | session-end`.
- CLI completed for integrations: `seal`, `verify`, `locate`.

### P1 — Claude Code plugin (shipped)
Hooks (`PostToolUse` tool actions, `SessionEnd` transcript), MCP server,
`/noirebox-seal` `/noirebox-verify` `/noirebox-attest` commands, the
`noirebox-journal` skill, marketplace manifest at the repository root.

### P2 — VSCode extension (source shipped, 0.9.0)
Sidebar: journal activity, recent seals, verify button. Commands: seal a
decision, verify, export the attestation (JSON/PDF). Auto-configures the
NoireBox MCP server for Copilot agent mode. Sold honestly: in editors that
do not expose per-call logs, NoireBox is the custody and attestation layer.

### P3 — the docs matrix (multiplicator, near-zero code)
One README section per MCP-capable client (Cursor, Windsurf, Gemini CLI,
Cline, Continue, any MCP host): the config snippet, what gets sealed, what
does not. Plus the CI story: the `noirebox-verify` GitHub Action already
attests a journal in CI.

### Later — evaluated on demand
- Native integrations proposed upstream to agent vendors, one by one,
  only when the repository shows a stable, documented convention.
- Sealing conventions for CI-run agents (scheduled agents, GitHub Actions
  runs) — same handlers, runner-scoped journals.

## Maintenance rule

N manifests will drift; the core must not. Every plugin README states the
same toggles with the same semantics (`NOIREBOX_HOOK_DISABLE` pauses —
past seals stay; there is no unseal, by design). A change to hook semantics
lands in the core handlers and in every plugin's glue in the same PR.
