# Changelog

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
versioning according to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- **OpenTimestamps witness (ADR 009)**: profile `{"name": "bitcoin", "kind": "ots"}`
  in `NOIREBOX_TSA_PROFILES` — a Bitcoin-anchored receipt rides in the same
  `anchor` event as RFC 3161 tokens; pending at stamping, confirmed at the next
  block, verified in ~30 µs of SHA-256 with no operator to trust. Manifest
  check is pure Python (tamper detection without the `ots` CLI); missing `ots`
  is reported, never hidden. Optional dep: `opentimestamps-client`.
- **Multi-TSA anchoring with pinned roots (ADR 008)**: `NOIREBOX_TSA_PROFILES`
  puts several independent witnesses behind one `anchor` event — at least one
  qualified eIDAS TSA for legal presumption (eIDAS art. 41), plus rotating
  public TSAs (DigiCert, FreeTSA — endpoints live-validated). Legacy
  `NOIREBOX_TSA_URL` unchanged; single-profile payloads keep the exact
  v0.3.0 flat shape (old verifiers still verify the primary token).
- **Auditor-side root pinning**: `verifier/tsa_roots/<profile>.pem` — tokens
  verified against the auditor's pinned root instead of the operator-shipped
  certificate (TOFU fallback, reported). Roots `digicert.pem` and
  `freetsa.pem` shipped; append-only policy (retired roots keep verifying
  past anchors). `NOIREBOX_TSA_ROOTS_DIR` overrides for tests.
- **TSA egress control**: `NOIREBOX_TSA_ALLOWED_HOSTS` (default: loopback for
  `make tsa`) — fail-closed allowlist, link-local (cloud-metadata) refused
  after DNS resolution, redirects never followed (shared no-redirect client).
- **EU compliance dossier**: `docs/COMPLIANCE-EU.md` — AI Act art. 12/19/26/55
  mapping (post–Digital Omnibus calendar, Reg. (EU) 2026/1744), GDPR art. 5.2,
  eIDAS art. 41, CNIL angle, market whitespace, product plan (ADR 009 OTS,
  ADR 010 ai-act event vocabulary).

### Changed
- Anchors now carry the TSA profile name (`tsa` payload key) so pinning works
  for single-witness journals too; old verifiers ignore the extra key.

### Planned
- Local judge model (`llama-guard3:1b` via Ollama) for ambiguous cases — ADR 001 stage 2
- OpenTimestamps profile type — compute-grade witness (ADR 009)
- `ai-act` event vocabulary + `--audit-pack` export (ADR 010)
- Prometheus + Grafana metrics
- HSM/KMS migration for the private key

## [0.4.0] - 2026-09-24

### Added
- **Reconciliation plugin v0** (issue #3, community request): `noirebox/reconcile.py` —
  business invariants over the journal (decision ↔ outcome pairing by
  correlation key, `within` windows), findings sealed as `reconciliation`
  events; JSON config ([`reconciliation.example.json`](reconciliation.example.json));
  CLI: `noirebox reconcile --config … [--journal-report] [--fail-on-findings]`
- **Payout use-case demo**: `demo/demo_payout.py` (`make demo-payout`) —
  an agent decides, a simulated provider responds, the two failure cases
  (crash gap, orphan outcome) and the reconciliation report on a real chain
- **Supervision dashboard**: `GET /dashboard` — read-only HTML view (badge
  INTACT/TAMPERING, counters, reconciliation panel, event table), zero
  dependencies, auto-refresh

### Changed
- **The PDF attestation becomes an optional extra**: reportlab is no longer
  a core dependency — `pip install noirebox[pdf]`. Without it, the
  attestation.pdf route answers 501 with the install hint
- SDK default timeout raised 5s → 15s (cold-start ML load on fresh
  environments, found by the stranger simulation)

## [0.3.0] - 2026-09-20

### Added
- **RFC 3161 anchoring** ([ADR 006](docs/ADRs.md)): `POST /api/v1/anchors`
  seals the current chain head with a TSA (only the hash leaves — zero data);
  token + certificate are journaled as an `anchor` event; the third-party
  verifier checks the anchors (`openssl ts -verify`) and reports
  `anchors_checked` — the threat model gap for the “insider with the key” is closed
- **Self-hosted TSA** ([ADR 007](docs/ADRs.md)): `make tsa` (OpenSSL,
  root + leaf certificate chain, port 3318, free, offline); external/qualified
  TSA via `NOIREBOX_TSA_URL`
- **Fleet Merkle anchoring**: `noirebox/merkle.py` — one TSA seal covers N journals
  (Certificate Transparency pattern); inclusion proofs are ~log2(N) hashes and are
  verifiable offline; the full tree is journaled as a `fleet_anchor` event (the hub
  is itself a NoireBox) — `make demo-fleet` (3 boxes, 1 seal, 1 falsification)
- Full simplified explainer in `docs/VULGARISATION.md §9` (“dry paint” / “final layer”) — ready for infographics

## [0.2.0] - 2026-09-20

### Added
- **OAuth2 (JWT bearer) + rate limiting** ([ADR 004](docs/ADRs.md)):
  `POST /api/v1/token` (client-credentials, constant-time secret comparison),
  1-hour HS256 JWT, protection for writes and exports — verification routes remain open by design;
  sliding window 60 req/min/client; explicitly enabled via `NOIREBOX_CLIENTS`
- **PDF attestation** ([ADR 005](docs/ADRs.md)): `GET /api/v1/attestation.pdf`,
  A4 DPO-ready page with chain state, keys, and verification instructions

## [0.1.0] - 2026-09-19

### Added
- **Tamper-evident journal**: chained SHA-256 hash chain + Ed25519 signatures,
  append-only SQLite storage, local verification and full export
  (`GET /api/v1/export`) — standalone third-party verifier (`verifier/verifier.py`,
  exit 0/1 with exact falsification location)
- **Signed attestation** of the current chain state (`GET /api/v1/attestation`)
- **Dual-engine guardrail**: regex heuristics for FR (4 attack families)
  and trained ML micro-model (TF-IDF + logistic regression, 293 KB,
  FR dataset of 5,400 versioned examples, `make train`) — selected via
  `engine: regex|ml`
- **Real LLM scene** (`make demo-llm`): qwen2.5:0.5b via local Ollama,
  attack succeeds without protection and fails with it — zero simulation
- **MCP server** (JSON-RPC stdio, no SDK): 4 agent tools
  (`noirebox_scan`, `noirebox_log_event`, `noirebox_verify`, `noirebox_attestation`)
- **Client SDK** (`noirebox/client.py`) tested against a real uvicorn server
- One-shot demos: `make demo` (model → journal → auditor → attacker),
  `make demo-mcp`
- **GitHub Actions CI**: retraining of the micro-model + 56 tests on every push
- Documentation: formal spec (`docs/SPECS.md`), threat model
  (`docs/THREAT-MODEL.md`), ADRs (`docs/ADRs.md`), full vulgarization
  (`docs/VULGARISATION.md`)

### Decisions
- ADR 001: staged guardrail (regex → ML → LLM judge as last resort)
- ADR 002: Llama Prompt Guard 2 (Meta) evaluated and rejected (language, binary output,
  gated licensing, dependencies)
