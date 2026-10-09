# Changelog

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
versioning according to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- **Calibration: an a-priori bound, never observed spread (issue #42 —
  pm25coder)** — a negative control's known value is a RANGE declared BEFORE
  the run (`calibration/0.1`: value AND width predate it, `derivation` and
  `declared_by` required); a range fitted from the enumerated constructions
  is itself a finding (`calibration_fitted_in_sample` — the first correct
  construction the checker has never met reads as a failure), and the
  observed spread travels with the witness as calibration HISTORY
  (`calibration_observation`), never re-fitting the bound. The run is graded
  against the bound (`control_out_of_range`); the report carries the
  calibration results the way it carries probe results.
- **The channel rung: expectation admissibility upstream of delivery
  (issue #43 — david_ilands)** — sent/accepted/delivered presuppose a
  counterparty already reachable in the space where the answer is visible.
  The expectation MAY declare `channel: {kind, reachability:
  "demonstrated"|"assumed"}` and every expectation row grades it:
  demonstrated (silence measures the exchange), assumed (cold — silence
  measures the SENDER's channel choice, not the recipient), undeclared (no
  admissibility story on record). Convention, not enforcement.
- **The AI Act art. 12 position paper** (`docs/ART12-MAPPING.md`) — every
  article 12 requirement mapped to the exact NoireBox mechanism and its
  verification command, plus the five asks for the JTC 21 drafting
  committee (externally testable integrity, the digest pattern, writer
  identity as cryptography, the denominator, disclosed proof grades).
  A working reference implementation is worth more to a drafting committee
  than another position paragraph.
- **The C2PA bridge (`c2pa.py`)** — C2PA 2.4-shaped claim documents built
  from journal facts: our event vocabulary maps to C2PA actions
  (`c2pa.created`/`edited`, and the `noirebox.*` namespace for what C2PA
  has no word for), chain coordinates ride in every action, and the
  verification assertion names the offline recomputation path. Agentic
  provenance is C2PA's acknowledged gap; it is what this journal seals.
- **SIEM export (`siem.py`, `noirebox export-siem`)** — CEF (ArcSight,
  escaped by the book: a pipe in a payload must not split one event into
  two lies) and OTLP/JSON (OpenTelemetry collectors), chain coordinates on
  every record so alerts trace back to the exact sealed event.
- **Replay (`replay.py`, `noirebox replay <meeting-id>`)** — the decision
  timeline rebuilt from sealed evidence in chain order: belief → attempt →
  call → output → witness. It verifies the chain FIRST (a replay over a
  tampered chain is theater) and re-derives, never re-runs.
- **The five Oct-8 gaps shipped as code** — the precedence policy sealed
  before the incident (`seal_policy`, `reconciliation_policy/0.1`, winner
  enum + decided_by required, issue #35); per-parameter negative controls
  on lookups (`check_lookup_control`, `lookup_silently_unfiltered` — the
  operation stays Unknown, issue #36); the outbound half of the denominator
  (`witnessed_expectations` + `unwitnessed_expectation`: anchored or
  co-signed, else a wish with a hash, issue #37); the legitimate
  transformation convention (`transformation_payload`,
  `content-transformation/0.1`, issue #38); witness ≠ author enforced at
  seal time and serve time (`ensure_witness_distinct`, issue #39).
- **ADR 024 — cross-chain reconciliation**: consumption edges as sealable
  events (the producer's chain head as observed, journaled on BOTH sides),
  the contract as a PARTIAL ORDER (edge admissibility, never a global
  timeline), edge invariants derived from anchors (ancestor check, anchor
  interval, temporal inversion as a cross-chain finding), no self-declared
  epoch (rejected alternative, recorded), and fan-in propagation — the
  blast radius of a superseded head is a precise path set, not "everything
  downstream, maybe". Lineage credited: sinarezaei, james/arhancanli,
  david_ilands.
- **Receipt v0.2.1** — `state_binding: {resource, resource_version}` (the
  TOCTOU field: the executor applies the sealed version as a precondition —
  a 409 on state move — and divergence becomes the sealed
  `receipt_expired_by_state_change` event, never silent reuse);
  `spec_hash` inside the `check_id` canonical form (one check_version can
  no longer validate two semantics under one id — sunnydachs's "step I had
  not taken"); the single-key refusal written into ADR 019 (label = schema,
  refuse = gate, both shipped); the executor-verifies-the-signature line in
  the deployment docs.

### Added
- **reconcile v0.2 (ADRs 019/020)** — the reconciliation layer implements the
  community-feedback schema: the report is sealed EVEN on a clean pass (with
  the examined counts — sum-to-n evidence), **negative probes** inject
  deliberately-broken fixtures that must bite (a checker that never says
  false is itself a finding), **attempt-first support** (`attempt_type` +
  `unlogged_attempt`: an outcome with no earlier attempt is the lie by
  omission, surfaced), and **two-key pairing** (`require_two_key` + the
  known-writer set: receipt and check-name under the same key is the
  finding, resolved by signature — a name, not a role).
- **The normalized witness (`witness.py`, ADR 019 §8)** — exit code, byte
  counts of stdout/stderr, file-tree SHA-256 before/after, container digest;
  canonicalize-then-hash, no wall-clock — and the guard that refuses to seal
  a witness carrying raw streams. Wired into the GuardedAgent (every run
  seals a `run_witness`) and into the reconciliation report.
- **The receipt builders (`receipt.py`, ADR 019)** — `check_id` (predicate +
  declared inputs + version, hashed), `evaluator_sha256`, `build_receipt`
  with the validated schema (`schema: "receipt/0.2"`, pairing grade
  `two-key`/`single-key`, base_commit).
- **The independence bench (`independence.py`, ADR 021)** — the
  shared-dependency test as a runnable assertion: store, key, endpoints,
  anchor cadence; an empty list means the audit flow and the truth flow
  share nothing.
- **Belief capture (ADR 023)** — the GuardedAgent seals `decision_belief`
  (resolved view, self-report grade) BEFORE the attempt and the call: the
  ordering in the chain is the proof.
- **The install gate demo** (`demo/demo_install_gate.py`, `make
  demo-install-gate`) — claim/verify/decision under two keys, the
  slopsquatting-thread pattern: an agent that can install is an agent that
  must journal.
- **The deployment custody map and the reconciliation cost note** (ADR 022,
  issue #33) — every consequential action mapped to its trust boundary, and
  the real bill of multi-flow custody, named.
- **`noirebox fleet-watch`** — the fleet console in service form: members
  checked against the hub's latest seal on a wall-clock cadence, the alarm
  fires ONCE per drift transition (to the terminal or POSTed to a webhook),
  and `--reanchor` re-seals the fleet whenever the check is healthy — the
  falsifiable window shrinks to the interval itself. The last item of the
  fleet-hub roadmap's operational layer.

## [0.10.0] - 2026-10-04

### Removed
- **The per-editor integration plugin and its strict single-format reader are
  removed** — the generic transcript machinery (ADR 013, formats named by
  SHAPE) covers every log the strict reader sealed: same event type, same
  digest chain, same corruption policy. `seal-trajectory` and the rollout
  scanner now ride the generic reader. Integrations stay glue over the
  CLI/MCP/handlers; editor-specific surfaces belong to distribution, not to
  the core. This release is built from an editor-agnostic history.

## [0.9.0] - 2026-10-04

### Added
- **The tiered scan (ADR 016)** — `engine: "tiered"`: the full ADR 001 pipeline,
  regex → ML → judge, where the judge pays only for doubt. Lines the cheap
  engines leave unflagged while the ML scored them in the doubt band
  `[0.20, 0.50)` are arbitrated by the local judge; a regex-covered line is
  never double-counted; if the judge is unavailable the sealed payload
  records `judge_skipped: n` — how much doubt went unanswered. The tiering
  split travels in the incident payload as evidence.
- **The fleet hub, v0 (ADR 017)** — `noirebox fleet-anchor journal1 journal2 …`
  seals ONE Merkle root over N journals' heads through the configured TSA
  profiles (the CT shape of ADR 008, now product instead of demo);
  `noirebox fleet-verify journal` recomputes a member's inclusion proof
  locally — a regenerated journal is a head the seal never committed to.
  Refuses to seal without a witness unless `--allow-local` says
  `witness: "local"` in the payload.
- **The tier-2 LLM judge retargeted by real-model evaluation (ADR 015
  amendment)** — llama-guard3:1b was evaluated on the FR attack corpus and
  rejected (does not follow custom policies, 3 of 4 attacks scored "safe");
  the default judge is `qwen2.5-coder:3b` with the few-shot house-taxonomy
  JSON prompt: 4/4 detections, correct categories, zero false positives on
  that evaluation. `make judge-pull` pulls the validated model.

- **Prometheus + Grafana metrics** — `GET /metrics` (text format 0.0.4, zero
  dependency): events by type, anchors, incidents, fleet seals, build info,
  and `noirebox_head_intact` — a light custody gauge that recomputes the
  last event and deliberately does NOT claim full chain verification. Sample
  dashboard: `docs/grafana-dashboard.json`.
- **Fleet-status alerting** — `noirebox fleet-status member1 member2 --db
  hub [--json]`: cron/CI-friendly check of every member against the hub's
  latest seal (exit 0 covered, exit 1 alarm).
- **VSCode extension source (P2, ROADMAP-PLUGINS)** — seal-note, verify,
  audit-pack, locate: glue over the installed CLI, source-only by design.
- **The attestation PDF speaks French on demand** (`?lang=fr`, ADR 005's
  deferred consequence) — bilingual prose table, language-independent
  identifiers, enum enforced at the boundary.

### Changed
- **DNS rebinding closed at the transport level** (ADR 008 refinement done):
  anchors.py leaves httpx for a stdlib pinned transport — resolve once,
  link-local-check every address, connect to THAT address, TLS identity on
  the hostname, redirects refused at the transport. Proof tests included.
- The landing pages sell only what exists: the Cloud/Enterprise tiers are
  gone — self-hosted is the product, verification free forever.

### Fixed
- `ScanIn.lang` documents that the bilingual regex engine deliberately
  ignores it (was silently ignored).

## [0.8.0] - 2026-10-04

### Added
- **The tier-2 LLM judge (ADR 015)** — stage 2 of ADR 001's layered guardrail
  finally exists: `engine: "llm"` on `POST /api/v1/transcripts/scan` and the
  SDK. A local llama-guard3:1b via Ollama (`NOIREBOX_JUDGE_MODEL` to swap) is
  prompted with the house taxonomy (the journal's 4 attack families — not
  llama-guard's native policy list), JSON-pinned, temperature 0, line-number
  contract mapped back to exact text offsets. Binary verdicts (score 1.0)
  with a short `reason` in the incident dict (optional key, this engine
  only); unparsable output → 503, never a manufactured incident; verdicts
  outside the taxonomy are dropped. `Incident.reason` is additive — old
  engines' dicts unchanged. Demo: `make demo-judge` (install once with
  `make judge-pull`). Real-judge tests skip-gated like every Ollama path;
  the stub suite carries CI. The MCP scan tool keeps the regex engine in v1
  (documented in the ADR).
- **`NOIREBOX_METADATA_AUTH=1`** — the metadata routes (`/activity`,
  `/attestation`, `/attestation.pdf`) can move behind the bearer token. They
  expose aggregates and digests only — never payload content — and stay open
  by default for the third-party and DPO hand-over flows; verification routes
  (`/verify`, `/attestation/verify`) are never lockable (ADR 004 refinement).
- `GET /api/v1/events` pagination is SQL-side (`store.page`, LIMIT/OFFSET on
  the primary key) instead of loading and JSON-decoding the whole journal to
  slice in Python.

### Changed
- CI tests the declared floor: matrix Python 3.11 + 3.12 (`requires-python
  >=3.11` was never actually tested at 3.11), coverage reported
  informationally (`pytest-cov` in the dev extra), and the Docker publish
  smoke-tests the pushed image (`/health` must answer before the job is
  green).
- Honest security claims: the TSA egress check narrows (not closes) the DNS
  rebinding window — the check runs at request-build time while the HTTP
  client re-resolves at connect; documented in `anchors.py` and ADR 008.

### Fixed
- The third-party verifier can no longer read as a clean INTACT when zero
  witness tokens were cryptographically checked: the report now carries
  `anchors_in_journal` vs `anchors_checked`, and the CLI prints a distinct
  `[!] anchoring is UNPROVEN on this machine` warning plus the
  reported-not-verified count (missing openssl/ots stays reported, never
  hidden).
- The ADR 012/013 sealing machinery is deduplicated (`noirebox/digests.py`):
  one order-committed digest chain and one JSONL corruption policy instead of
  two verbatim copies; the per-shape metadata extraction and verify wording
  stay — they are the audit surface.

## [0.7.0] - 2026-10-04

### Added
- **Transcript-agnostic sealing + per-project journals (ADR 013)** — the
  integration layer for coding agents. Log formats are sealed by SHAPE,
  not by product: `model-io` (per-call), `session-transcript`
  (per-message), `generic-jsonl` (fallback) all ride the same
  `model_trajectory` event and digest chain, `origin` carries the shape,
  metadata extraction is envelope-only and tolerant (absent fields are
  omitted, schema drift degrades gracefully). Journal discovery:
  `NOIREBOX_DB`, then the nearest ancestor `.noirebox/` directory, then
  `./.noirebox/journal.db` created on demand (0700/0600) — one project =
  one journal. Generic hook handlers (`noirebox hook tool-use |
  session-end`): hook JSON on stdin, one event out, best-effort by
  contract (never blocks the agent, failures loud on stderr, nothing
  sealed from an unreadable payload). CLI completed for integrations:
  `seal <type> <json>`, `verify` (in-place verdict, exit 0/1), `locate`,
  `seal-trajectory --format auto`, and a `noirebox-mcp` entrypoint so any
  MCP client runs the server straight from the install.
- **Claude Code plugin** (`plugins/claude/`, 0.7.0): hooks `PostToolUse`
  (tool actions) and `SessionEnd` (session transcript, digests only) over
  the shared handlers, MCP server, `/noirebox-seal`, `/noirebox-verify`,
  `/noirebox-attest` commands, the `noirebox-journal` skill, and a
  marketplace manifest at the repository root. Integration = glue only:
  the core stays single (see `docs/ROADMAP-PLUGINS.md`).
- **The agent plugin seals the agent's own flight recorder** (plugin 0.7.0):
  the existing `PostToolUse` hook now also seals the agent's per-call
  `model-io-*.jsonl` files into the journal (ADR 012, `noirebox seal-trajectory
  --rollout`) — digests only, progressive (`truncated_tail` on a live
  session, complete log on the next pass), deduped by content digest with
  the journal as the only register. Toggles: `NOIREBOX_TRAJECTORY_SEAL=0`
  (pause future seals — past seals are immutable, there is no unseal),
  `NOIREBOX_TRAJECTORY_INTERVAL_MIN` (scan throttle, default 10),
  `NOIREBOX_ROLLOUT_DIR`. Containment enforced: a candidate must resolve
  inside the rollout dir (a planted symlink pulls nothing into the journal).
- **Model-trajectory sealing** (`noirebox seal-trajectory <model-io.jsonl>`,
  ADR 012): the agent's own flight recorder becomes evidence. A coding
  agent's per-call log (`model-io-*.jsonl` — request, response, tool calls,
  `querySource`) is sealed into the journal as digests only:
  `file_sha256`, an order-committed digest chain over per-record digests
  (`trajectory_digest` — same calls in a different order is a different
  behavior, and the seal accuses on reorder), record count, session ids,
  models, query sources and the period of use. The payload names its sealer
  (`source: {tool, version}` — first brick of sealer identity). Verification
  is recomputation (`verify_trajectory`: None = intact, otherwise the
  reason); an unparseable mid-file line is a hard error, an incomplete
  trailing write is reported (`truncated_tail`) and sealed as seen.
  Conversation text never enters the journal. Demo: `demo/demo_trajectory.py`.
- **Journal activity heatmap** on the Flight Deck (`/dashboard`): a
  contribution-graph view of the journal — one cell per day, red intensity
  for sealed-event volume — with Daily / Weekly / Cumulative modes and hover
  tooltips ("September 26, 2026 — 512 events · 1 anchor"). Backed by a new
  read-only aggregate endpoint `GET /api/v1/activity` (day → count, SQL
  `GROUP BY`, anchor events tallied separately): the browser receives no
  payload through it. Intensity thresholds are quartiles of the displayed
  series, so a quiet journal and a busy one both stay readable; the busiest
  day always sits at the top of the scale. Read-only, like the rest of the
  dashboard — it renders, the exported dossier attests.
- `tests/test_guarded_pipeline.py`: the guarded pipeline (scan → filter →
  journal → LLM → journal) is now covered without a running Ollama, via a
  stub inner agent standing in for the LLM only. The end-to-end tests
  previously skipped on CI; both engine paths (ML and regex) are exercised.
- **TRAFFIC — the journal as a live radar**: fourth Flight Deck view; one
  node per event type on the perimeter, one beam per real sealed event
  flowing into the chain head, an amber pulse when an RFC 3161 anchor seals
  the whole past. Tails the journal through a new `since_seq` cursor on
  `GET /api/v1/events` (`store.since`): one indexed lookup per poll instead
  of replaying the journal, and a cursor the sealer can never trick into
  skipping or re-delivering an event.
- `make bench` (`demo/bench.py`): reproducible benchmarks for the two hot
  paths — sealing (hash + Ed25519 signature + SQLite commit, 2,000 appends)
  and full verification of a fresh 100-event export (median of 7 runs,
  asserted `valid`). `docs/SPECS.md` §6 is refreshed from it.

### Changed
- **Repository moved to the `noirebox` organization**: all repository, GHCR
  and plugin references updated (`ghcr.io/noirebox/noirebox`; the Docker
  image name is now derived from `${{ github.repository }}`). The old
  `slabbdev/noirebox` URL redirects; the PyPI package name is unchanged.
  Creator attribution added to both READMEs. The PyPI trusted
  publisher was re-pointed to owner `noirebox` before this release ships
  (done 2026-10-04).
  The `noirebox-verify` GitHub Action repository moved to the org too —
  README examples now use `uses: noirebox/noirebox-verify@v1` and pin
  `noirebox-ref: v0.6.0` (was v0.5.0).
- **Threat model names the accuracy-at-source boundary**: new "Lying source"
  actor row (tamper-evidence ≠ accuracy-at-source — a lie sealed at write
  time verifies clean forever) and an "Outside v0 scope" entry; the partial
  mitigation (source separation + `noirebox reconcile`) is stated where it
  exists. Raised by Naveen Alavilli during the launch discussion.
- **`docs/SPECS.md` re-synced with the code**: benchmark table re-measured
  via `make bench`; `/api/v1/activity` and the `since_seq` cursor documented;
  the multi-TSA anchor payload (`tokens`) documented; version headers dropped
  from SPECS and the threat model (they track `noirebox.__version__` — the
  spec had drifted to v0.1.0 while the package is at 0.6.0, and its limits
  section still claimed "no authentication", shipped in v0.2.0).
- Tone pass on the demo scripts and README: removed gratuitous ALL-CAPS and
  "100% real"-style flourishes ("REAL scene" → "live scene", "Zero simulation"
  dropped, "never simulated" asides dropped). The "Honest …" positioning
  sections are unchanged; the demo claims stay factual. Also corrected the
  stale test count in the Tests section (119 → 126).
- Incident payload action value `bloque` → `blocked` in the guarded
  pipeline (consistency of the payload surface with the rest of the API).
- **Intent-first docstrings, consistent naming** (review pass): tutorial-style
  docstrings rewritten to document intent and constraints; French identifiers
  renamed to English across the public surface — `llm_agent.AgentResult.summary`
  (was `compte_rendu`), `GuardedResult.summary` / `.filtered_lines` (was
  `compte_rendu` / `lignes_filtrees`), demo helpers (`exfil_leak`, `clip`).
- **Journal payload keys renamed**: `llm_call` now seals `clean_transcript` +
  `filtered_lines` (was `transcript_nettoye` + `nb_lignes_filtrees`), `llm_output`
  seals `summary` (was `compte_rendu`). Verification is unaffected (payloads are
  opaque to the chain); journals written by older versions keep their original keys.
- **Single version source**: `noirebox.__version__` (package metadata) now feeds
  the FastAPI app, `/health`, the MCP `serverInfo` and `noirebox --version` —
  they previously reported 0.4.0 / 0.1.0 / 0.1.0 while pyproject was at 0.6.0.
- **Lint gate upgraded**: ruff now also runs bugbear (B), flake8-comprehensions
  (C4) and flake8-simplify (SIM); the six findings it surfaced are fixed
  (`strict=` on zips, explicit exception chaining, unused loop variable).
- Named constants for the WAL-switch retry in `store.py`
  (`_WAL_SWITCH_ATTEMPTS`, `_WAL_SWITCH_BACKOFF_S`); behavior unchanged.

### Removed
- Dead code: `KeyPair.verify_with_public_key()` (no caller, no test in the
  repository — the standalone verifier carries its own verification logic).

### Fixed
- **JWT secret derived from private material, never from public data
  (ADR 014)** — the zero-config fallback hashed the PUBLIC key, which ships in
  every export and is served openly at `/api/v1/attestation`: anyone could
  re-derive the HS256 secret and forge tokens, bypassing auth and the rate
  limiter. The fallback now hashes the private key's raw bytes;
  `NOIREBOX_JWT_SECRET` stays the override. Adversarial tests fence the
  regression (a token forged with the old derivation is rejected; per-instance
  scoping holds). Tokens issued by a pre-fix deployment are invalidated by the
  upgrade — the journal itself is untouched.
- **TRAFFIC landed for real** — the radar's code (PR #18) had never been merged
  while the CHANGELOG and SPECS already documented it: docs ≠ code, caught by
  the project-wide review. The TRAFFIC view and the `since_seq` cursor are now
  on main with their tests.
- **`noirebox audit-pack` works from pip installs** — the wheel now ships
  `verifier/` (with its pinned `tsa_roots/`); it previously failed with
  ModuleNotFoundError outside a repository checkout.
- **Analysis commands and seal/verify resolve the same journal** — `reconcile`,
  `audit-pack` and `seal-trajectory` followed a cwd-relative default and could
  silently create a second, empty journal beside the real one; they now share
  the ADR 013 discovery (`locate.resolve_existing_journal`: `NOIREBOX_DB`,
  nearest `.noirebox/`, repo layout — never creates).
- **Dashboard behind auth** — the Flight Deck carried no Authorization header,
  so on an auth-enabled instance every refresh died on the 401 JSON; it now
  degrades to a locked state with a token prompt (🔑, sessionStorage only)
  while the open-by-design verification routes keep the page alive.
- **Portable plugin resolution** — no developer path hardcoded: the hook's
  interpreter resolves NOIREBOX_HOME's venv, then a pip-installed noirebox,
  else exits quietly; the journal resolves NOIREBOX_DB > NOIREBOX_HOME's
  central journal > ADR 013 per-project discovery; `launch.sh` prefers the
  installed `noirebox-mcp` entrypoint.
- `ollama_available()` treats an HTTP error response as unavailable
  (`raise_for_status`) — a 500 is not a listening Ollama.
- The 501 no-reportlab answer is a proper `JSONResponse` (the hand-built
  f-string JSON broke on messages containing a quote).
- `KeyPair` creation race: the loser of the `O_EXCL` race loads the winner's
  PEM instead of crashing — one journal, one key.
- Dockerfile OCI source label follows the org migration (`slabbdev` → `noirebox`).

## [0.6.0] - 2026-09-26

### Added
- **Release alignment**: PyPI publish workflow (trusted publishing via OIDC —
  tags `v*` and manual dispatch; one-time setup on pypi.org, see the
  workflow header) and an `ots` extra (`opentimestamps-client`) so the
  ADR 009 witness installs as `pip install noirebox[ots]`. Agent plugin
  version aligned to 0.5.0 (portable `NOIREBOX_HOME` default still queued
  as the next plugin item).
- **AI-Act event vocabulary + audit-pack (ADR 010)**: `noirebox/aiact.py` —
  validated builders for the art. 12(3) fields (`ai_use` with use period /
  reference DB / sha256 input digest only, `ai_verification` with the art.
  14(5) human verifier, `ai_incident` per art. 55(1)(c)/73) and
  `noirebox audit-pack <dir>` writing `export.json` + `verifier_report.json`
  + a generated `ANNEXE-IV-2f.md` (logging characteristics, produced from
  the journal itself).
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

[Unreleased]: https://github.com/noirebox/noirebox/compare/v0.10.0...HEAD
[0.10.0]: https://github.com/noirebox/noirebox/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/noirebox/noirebox/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/noirebox/noirebox/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/noirebox/noirebox/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/noirebox/noirebox/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/noirebox/noirebox/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/noirebox/noirebox/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/noirebox/noirebox/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/noirebox/noirebox/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/noirebox/noirebox/commits/v0.1.0
