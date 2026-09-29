---
description: Seal a decision, output, or provenance claim into the NoireBox tamper-evident journal
allowed-tools: Bash
---

# NoireBox — seal into the journal

Seal the requested fact into the per-project NoireBox journal (the nearest
`.noirebox/` directory, or `NOIREBOX_DB` if set). Digests and short facts
only — never raw conversation content, never file dumps.

User request: $ARGUMENTS

1. Choose the event type:
   - a decision or its justification → `decision` with `{"what": "...", "why": "..."}`
   - a content-provenance claim (ADR 011) → `content_provenance`
     with `{"origin": "human"|"ai-agent"|"ai-assisted", "content_hash": "<sha256>"}`
   - a generic fact → `note` with `{"fact": "..."}` (keep it under 200 chars)
2. Seal it:
   ```bash
   noirebox seal <type> '<json payload>'
   ```
   (If `noirebox` is not on PATH: `uvx --from noirebox noirebox seal <type> '<json>'`.)
3. Report the sealed event number and hash to the user, one line.
