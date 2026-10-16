---
name: noirebox-journal
description: Seal agent decisions and outputs into the per-project tamper-evident journal, verify the chain, export signed attestations. Use when the user asks to journal, seal, keep proof of a decision, verify the chain, or produce an attestation.
---

# NoireBox journal

The per-project journal lives in `.noirebox/journal.db` (nearest ancestor
directory that has one; `NOIREBOX_DB` overrides). Same SQLite file, same
Ed25519 key, same chain for everything: hooks, MCP server, CLI.

## The four gestures

1. **Seal a fact** — `noirebox seal <type> '<json>'` (types: `note`,
   `decision`, or a documented convention such as `content_provenance`).
   Digests and short facts only; never raw conversation content, never
   credentials, never file dumps.
2. **Verify** — `noirebox verify`. Exit 0 = valid, exit 1 = tampered
   (with the seq and reason of the first anomaly). Never soften the verdict.
3. **Seal a session transcript** — happens automatically at SessionEnd via
   the plugin hook (event type `model_trajectory`, digests only). To seal
   one manually: `noirebox seal-trajectory <file> --format auto`.
4. **Attest** — the MCP tool `noirebox_attestation` (JSON; PDF via a
   running instance at `GET /api/v1/attestation.pdf`).

## Honesty rules

- A seal proves existence and integrity, not correctness.
- Pausing is allowed (`NOIREBOX_HOOK_DISABLE=1`); unsealing is not — the
  journal is append-only by design. Say so plainly when asked.
- Never report a tool result you did not run.
