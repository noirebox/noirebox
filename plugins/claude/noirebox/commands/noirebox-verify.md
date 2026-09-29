---
description: Verify the NoireBox hash chain and report the journal's integrity status
allowed-tools: Bash, MCP(mcp__noirebox__noirebox_verify)
---

# NoireBox — verify the journal

Verify the per-project journal (the nearest `.noirebox/` directory, or
`NOIREBOX_DB` if set) and report the result honestly — the verdict is
whatever the verifier says, never softened.

1. Run the verification:
   ```bash
   noirebox verify --db "$(noirebox locate 2>/dev/null || echo .noirebox/journal.db)"
   ```
   If the MCP server is connected, prefer the `noirebox_verify` tool.
2. Report: valid or not, number of events checked, and where the chain
   breaks (if it does). A failed verification is an incident — say it
   plainly and stop; do not attempt to "fix" the journal.
