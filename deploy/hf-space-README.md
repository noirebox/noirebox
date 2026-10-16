---
title: NoireBox
emoji: ⬛
colorFrom: gray
colorTo: red
sdk: docker
app_port: 8768
pinned: false
---

⬛ **NoireBox** — the black box for AI agents: tamper-evident journal
(SHA-256 chained + Ed25519), regex guardrail + micro ML model (293 KB),
exportable attestation verifiable by a third party.

- API + interactive docs: `/docs`
- Scan a transcript: `POST /api/v1/transcripts/scan` (`engine: regex|ml`)
- Verify the chain: `GET /api/v1/verify`
- Auditable export: `GET /api/v1/export`

Source code: see the `noirebox` repository (full README, demos).
