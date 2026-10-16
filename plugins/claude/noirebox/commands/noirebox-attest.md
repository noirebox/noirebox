---
description: Export a signed attestation of the journal (JSON and PDF for compliance files)
allowed-tools: MCP(mcp__noirebox__noirebox_attestation)
---

# NoireBox — export an attestation

Produce the signed attestation of the per-project journal. The MCP server
signs the export with the instance's Ed25519 key; a third party verifies it
with the public key alone (no trust required).

1. Call the `noirebox_attestation` MCP tool. If the MCP server is not
   connected, tell the user to start it (`noirebox-mcp`) instead of
   improvising an export.
2. Hand over the JSON export path, and mention the PDF variant
   (`GET /api/v1/attestation.pdf` on a running instance) for compliance
   files that need a human-readable page.
3. One line of caution: the attestation proves the journal's integrity,
   not the correctness of what was journaled.
