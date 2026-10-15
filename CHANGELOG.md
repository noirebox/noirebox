# Changelog

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
versioning according to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Security

The full external audit of 0.20.0 — ten findings, none breaking the
cryptography, several landing on the verification LOGIC the product
exists to enforce. Eight are closed here, each with its own named test
(350 → 378); two are assessed and deferred, stated below rather than
silently dropped.

- **NB-01 (high)** — a SET-but-unparseable `NOIREBOX_CLIENTS` silently
  fell back to the publicly-known `demo:demo-secret` while the operator
  believed their credentials were live. `load_clients` now refuses to
  build the app unless no valid pair remains at all (fail-closed). The
  JWT secret is derived once from the key the app actually loaded
  (`jwt_secret_from_key`, threaded through issue/verify): the token path
  no longer env-resolves — and `load_or_create`s — a key file behind the
  app's back, nor re-reads the PEM per request.
- **NB-02 (high)** — unverifiable witness tokens (missing `openssl`/`ots`,
  or a timeout) left the third-party verifier at exit 0 with
  `valid: True`: a CI gate in a slim container read a forged-token
  journal as INTACT, and ONE checked token among others silenced the
  zero-checked warning. An unproven anchoring now exits **2**, carries
  its own report field (`unverifiable_witnesses`), and exit 0 costs an
  explicit `--allow-unverified-witnesses`. The doctrine, applied to the
  tool that enforces it: undecidable is never clean.
- **NB-03 (high, two halves)** — `_newest_anchor`, the input of
  `custody_grade`/`check_custody_drift`, validated neither the cited
  head_hash nor the presence of a token: an anchor-shaped event with a
  fake hash walked the custody grade to 2 "disinterested custodian".
  Both are now required (`_anchored_upto` hardened symmetrically), and
  the §20 fixtures stopped sealing `hash-{seq}` fakes. AND the §23 VTA
  residue is closed: a non-terminal record of the terminal type can no
  longer overwrite the terminal it follows and swallow a proven
  `verdict_predates_terminal` race — it is surfaced as its own finding,
  `post_terminal_activity`. The permutation matrix's open question —
  whether a reopened run un-cancels a proven contradiction — is answered
  NO; the implementation now holds the theory the matrix pinned.
- **NB-04 (medium)** — the egress rule tested only `is_link_local`:
  `::ffff:169.254.169.254` (the cloud-metadata prize, IPv4-mapped)
  passed on python:3.12 — the shipped image — and an allowlisted
  external host resolving into RFC 1918 walked straight in. `_as_v4`
  unwraps the mapping before every range check, non-default hosts must
  resolve to GLOBAL addresses (loopback keeps serving `make tsa`), the
  pinned resolution applies the same rule, a TSA response read is capped
  at 1 MiB, and the fleet-watch webhook is held to the bar
  (`NOIREBOX_WEBHOOK_ALLOW_PRIVATE` opts in).
- **NB-06 (medium)** — `EventIn.payload` was the API's only unbounded
  body; it now carries a 256 KiB canonical-JSON seal budget (a payload
  is sealed forever). `/verify` — open ALWAYS per ADR 004, O(N) Ed25519
  per call — caches its verdict against the chain head (`store.head()`,
  O(1) through the PK); any append invalidates it. `build_attestation`
  stays uncached on purpose: `generated_at` is part of its signed
  payload.
- **NB-07 (medium)** — `POST /api/v1/token` was the one endpoint an
  unauthenticated peer could hammer: 10 attempts/min per
  (peer, client_id) now, `Retry-After` included; the `RateLimiter`
  sweeps expired buckets past 1000 identities instead of holding ghosts
  forever.
- **NB-09 (low)** — the container ran as root (no `USER`) and compose
  published 8768 on all interfaces with auth disabled: an open, root API
  by default. Dedicated uid 10001 owns `/srv`, the port binds 127.0.0.1,
  the journal moves to a named volume, and the compose file names the
  `NOIREBOX_CLIENTS` obligation in place.
- **NB-10 (low)** — the hook preview sealed up to 800 characters of raw
  `tool_input`: a `curl -H "Authorization: Bearer sk-…"` or a written
  `.env` became permanent, export-readable secret material, against the
  module's own data-minimization contract. Redaction runs BEFORE
  truncation (bearer/`sk-`/`ghp_`/AKIA shapes, `KEY=value` and
  `"key": "value"`, escaped quotes included), and
  `NOIREBOX_PREVIEW_MODE=hash` seals the digest alone.

**Assessed, deferred on purpose:**

- **NB-05 (medium)** — the Merkle tree lacks RFC 6962 domain separation
  and deduplicates leaves silently. No practical attack in the current
  threat model (fixed-width hash leaves, side-bound proofs), and the
  honest fix — prefixed node hashing — changes every root: sealed fleet
  anchors and their proofs would stop verifying. It wants a versioned
  tree format (`merkle/0.2` + dual verification), not a patch; decision
  deliberately left open.
- **NB-08 (medium)** — `joblib.load` without an integrity check is real,
  but the audit's fix (pinning three SHA-256 hashes) contradicts
  `make train`, which regenerates the models per machine. The right
  shape is a build-time manifest signed at package build — tracked, not
  patched ad hoc.

## [0.20.0] — 2026-10-14

### Added
- **The custody grade (v0.1 — §20, the rudratosh/fluffydesk thread)** —
  a witness is worth **min(authoring, retention)**: receipts authored
  grade-1 but retained in operator-controlled storage sit at grade 3,
  and retention is the only grade that is WRONG BY DRIFT — so it is
  monitored. Retention changes become sealed events
  (`seal_retention` → `retention/0.1`, action bounded to
  prune/migrate/policy-change/restore); `check_custody_drift` names the
  unanchored journal and the tail beyond the newest anchor (by count or
  wall-clock cadence — `custody_drift`); `custody_grade` discloses the
  grade as the TAIL's grade (2 while anchored within cadence, 3 the
  moment it drifts), sealed via
  `journal_report(custody_disclosure=...)`, never touching
  `clean_pass`. CLI: `noirebox seal-retention`, `noirebox custody-grade`.

## [0.19.0] — 2026-10-14

### Added
- **The derivation reads the code, never the sentence (receipt v0.3.0 —
  3hnok, the seventh premise)** — the re-probe found `uid_gate()`
  string-matching "not the allowed operator": the strongest token in the
  vocabulary had the interface's weakest derivation. Every daemon
  refusal now carries a machine-readable `error_code` beside the prose
  (the not-checkable refusal carrying the DAEMON's platform), the
  fourth token `undecidable(<reason>)` is the resting state (old daemon
  prose → `undecidable(unclassifiable-refusal)`, transport failure →
  `undecidable(unreachable)`, null = "not stated" only), and the wire
  handshake stays `noirebox-keyholder/0.2` on purpose — additive fields
  plus the token ARE the mixed-version answer. Ships with the stub
  battery (every refusal string and code asserted against the derived
  value) — whose first socket-level run caught a REAL daemon bug: the
  accept loop died on BSD/macOS ECONNABORTED when a peer hung up
  pre-accept. The listener survives its peers now. Release note: the
  tag was first cut as `v0.3.0` and PyPI refused honestly — version
  already exists, uploaded 2026-09-23 (a pre-0.4.0 build the ladder
  skipped). A burned number is dead forever; this is 0.19.0.

## [0.18.0] — 2026-10-14

### Added
- **The gate state, owned by the daemon (receipt v0.2.9 — 3hl4l)** —
  `peer_uid_checked` answered "could the platform tell": an UNGATED
  daemon on a checkable platform reported True. The daemon now reports
  `uid_gate_configured` beside the check flag, `SocketSigner.uid_gate()`
  derives the tri-state — "off" / "enforced" / "unavailable(<platform>)"
  — and a refused peer never receives a describe at all: the refusal IS
  the enforcement. Premise 6: the env var is inherited — the PIN left
  argv, not the daemon's address space.

## [0.17.0] — 2026-10-13

### Added
- **The custody mode, disclosed (receipt v0.2.8 — 3hkpp)** — the
  drop-in property makes the journal blind to custody, so the mode
  becomes a disclosure field: `registry_disclosure(signer_mode=...,
  uid_gate=...)` (schema `registry-disclosure/0.2`, null = unstated),
  derived from the daemon's own `SocketSigner.describe()` — and the
  darwin boundary lands in the ladder: the socket's 0600 separates
  USERS, not processes; the token PIN left argv.

## [0.16.0] — 2026-10-13

### Added
- **HSM signing — the same signer interface, hardware custody (ADR 020,
  rung 5)** — `P11Signer` (`noirebox/hsm.py`, the `hsm` extra,
  python-pkcs11 pinned 0.7.0) duck-types `.sign()` + `.public_hex()` and
  puts the material in a PKCS#11 token; the keyholder daemon becomes the
  hardware bridge (`--pkcs11-*`, `--ensure-key` imports the EXISTING
  journal key — continuity, not rotation); the PKCS#11 contract is
  CI-proven on SoftHSM2 (the `test-hsm` job). The HSM narrows the blast
  radius (live abuse, not stolen-key-forever), never the socket
  premise — and `CKA_NEVER_EXTRACTABLE` is a label an imported key
  honestly reports False.

## [0.15.0] — 2026-10-13

### Added
- **The keyholder — the operator's key lives in a process the agent is not
  (ADR 020 as a runtime property; the floor "a premise, not a cipher",
  re-priced)** — the PEM loads ONCE into a dedicated daemon
  (`noirebox keyholder`) and never leaves it: the socket answers `sign`
  and `describe`, nothing else (protocol `noirebox-keyholder/0.1`,
  newline-delimited JSON, oversized lines dropped by disconnection).
  `SocketSigner` duck-types `.sign()` + `.public_hex()`, so every writer
  path (store, `seal_writer`, `journal_report`) signs THROUGH the daemon
  unchanged — Ed25519 is deterministic, the signatures are byte-identical
  to the key's own, and every existing verifier reads the journal as
  before. `--allow-uid` gates the peer by uid (SO_PEERCRED, Linux) and
  FAILS CLOSED where the peer uid is not checkable. `noirebox
  keyholder-status` reads the daemon's public key out-of-band — the pin
  value, taken from the process that holds the key, never from the
  journal it sealed. The honest boundary: reachability of one socket path
  replaces readability of the key bytes; a deployment that wants "the
  agent cannot sign" mounts everything EXCEPT the socket, and the PEM can
  be removed after start (the daemon holds the material in memory only).
  HSM/PKCS#11 rides the same signer interface later.

## [0.14.0] — 2026-10-13

### Added
- **The pin (v0.2.7 — the §17 write race, closed: howcani's 3hj95)** —
  the registry's own authority was the residue: store-derived,
  first-write-wins — the agent could seal its own `writer` entry and win
  the vote by arriving first. `reconcile_receipts` now takes
  `registrar_public_hex`: the registrar's key supplied OUT-OF-BAND
  (ADR 008's TSA-root pattern, never read from the artifact under
  audit). At assembly, only registrar-sealed entries are admitted; a key
  the registrar attested under two domains is
  `registry_duplicate_undecidable` — emitted at assembly, never resolved
  first-wins. The verdict reads the registry the operator sealed, not
  the registry that arrived first. howcani's registered prediction is a
  test and holds: at the pinned head, the operator's attestation landing
  second reads `unverified_label`. ADR 021 amendment.
- **`registry_disclosure` — the descent's floor, disclosed (v0.2.7,
  howcani's 3hif9)** — the disclosure row: the verdict states the
  registrant and the evidence grade (grade 3, "anchored self", VOLUNTARY
  unless a regime imposes it — ADR 022). Sealed into the report via
  `journal_report(registry_disclosure=...)`; a disclosure is not a
  violation and never touches `clean_pass`. Unpinned, the mode line says
  "store-derived (first-write-wins)" — the registry nobody vouched for.
- **`check_gui_gap` — the receipt_gap invariant at the GUI layer (§16 —
  reid, SoftwareGym)** — actions served by the app vs OS state observed
  by the system, on the same key: the gap is the finding. A served
  action with no observation is `gui_served_unobserved` ("an app that
  survives twenty clicks without touching OS state passed the test by
  doing nothing"); OS state moved with no served action is
  `gui_observation_unserved`. Domain-blind as always: the runner counts
  the served side, the OS counts the observed side — the harness is the
  runner's, the denominator is ours.
- **The known-writers registry (v0.2.6 — the §15 structural design,
  howcani's registry)** — the residue of the probe fixes, closed
  structurally: the domain of every writer is declared at REGISTRATION
  and sealed by the verifier (`seal_writer` → `writer/0.1`), and
  `reconcile_receipts` in registry mode resolves keys and domains from
  the sealed registry — the caller supplies nothing. A witness is a
  registered writer whose domain differs from the receipt's own; an
  unregistered transport writer witnesses nothing; a receipt whose own
  writer is unregistered is `independence_undecidable` — never clean.
  The attacker row (`(k1,'agent'),(k2,'attacker')`) joins the replay
  suite as the pre-registered immobility test. ADR 021 amendment.

## [0.13.0] — 2026-10-12

### Fixed
- **Receipt v0.2.5 — the verdict reads keys, not labels (howcani's probe,
  the acceptance test)** — two broken lines in the v0.2.3/v0.2.4 schema,
  found by running the probe instead of reading the diff:
  - **the label flip**: the cross-writer verdict compared LABEL strings
    ("agent" vs "hook") — two agent-controlled keys with different labels
    flipped it. The comparison now resolves KEY MATERIAL (`_signer_key`);
    labels are presentation, keys are identity.
  - **the third undecidable input**: a receipt whose writer does not
    resolve against the known-writer set was CLEAN — it now seals as
    `independence_undecidable`, beside NOT RUN: undecidable is never
    clean.
  Acceptance: the probe's four-row matrix (same-writer / omitted / empty
  set / unresolved) all fire as named — run, not asserted.

## [0.12.0] — 2026-10-11

### Added
- **Receipt v0.2.4 — the ceiling of the join, closed (howcani's audit)** —
  the v0.2.3 label-vs-journal join shared a structural blind spot with the
  receipt: both sides came from the same store, the same key, the same
  writer — it caught the INCONSISTENT agent and was blind to the
  CONSISTENT one that never journals an llm_call ("the failure mode is
  absence — the one thing a chain cannot see"). Closed by inversion:
  `judged_by="deterministic"` is verified only by a TRANSPORT attempt on
  the same key (the hook process's `agent_tool_use`), sealed by a writer
  the agent does not control — absence or same-writer-only is the finding
  `unverified_label`. And `requirement_ref` goes load-bearing: the sealed
  requirement names its SCOPE (`requirement/0.2`), the diff's touched set
  comes from git (the first observation the citing agent does not author),
  and a citation whose scope touches nothing is
  `requirement_out_of_scope`. ADR 019 gains the corrected lineage:
  `alg: none` closes by refusing the algorithm; the wrong-issuer shape
  closes by NAMING the issuer.

## [0.11.0] — 2026-10-11

### Added
- **coverage_check — every write reconciles against a gate receipt (issue
  #44 — sinarezaei)** — the §5 invariant shipped as a ready-made check:
  mutating calls (`write_type` — a `pod_delete`, an `orders.capture`) are
  joined against the gate's receipts on the correlation key, and an exec
  with no receipt is `uncovered_write` — an exec the gate never vouched
  for. Pitched at K8s/platform teams; clean coverage returns an empty
  list, and the findings seal like any report.
- **SCAR-PROC-114 — the parallel-call race + the canary witness (Randal/gde,
  Fixture 5)** — the runtime race from the live tickets: an orchestrator
  defines the judge in the same parallel turn it reads the judge's bytecode,
  so the system prompt is hallucinated from pre-training priors (generic
  "Security"/"Performance" headings instead of the canonical planted canary,
  "4. Blast Radius" — a key cut from private history, never in a prior).
  Shipped: `seal_spec` → `spec/0.1` (the canonical bytecode sealed with its
  canary PLANTED — a seal whose text lacks the canary is refused at build
  time) and `reconcile_spec`: a judge defined with no sealed read of its
  bytecode BEFORE the definition is `judge_defined_before_spec_read`; a
  receipt whose spec_hash matches no sealed canonical bytecode is
  `spec_not_canonical` — the drift surfaces as a registry miss instead of a
  soft reviewer.
- **SCAR-BENCH — the claims format, the enforcement taxonomy, the
  differential (`docs/SCAR-BENCH.md` + `make differential`)** — every
  control graded Level 0/1/2 by WHAT ENFORCES IT (prose / primitive in
  context / host-enforced); the numerical-claims format taken from the
  catalog's published matrix (baseline → primitive → controlled delta, per
  model, denominator and significance); the replay suite positioned as a
  shared negative-control set ("run it against YOUR gate"); the W231 bridge
  to Mike Mol's mtools (mechanical/arithmetical/behavioral ↔ the digest, the
  denominator, the confronted label).
- **Receipt v0.2.3 — the alg:none door, closed (howcani's audit + Randal's
  lineage)** — `judged_by` becomes **required with no default**: v0.2.2's
  optional field defaulted to the tier that requires nothing, so an
  LLM-judged check that said nothing sealed the exact SCAR-45 receipt with
  "deterministic" written in it — omission and honesty produced the same
  bytes. Fail-closed costs an honest caller one keyword and ends the
  laundering path. The declarations stop being unverified claims:
  `reconcile_receipts` joins the label against the journal (a receipt
  declaring "deterministic" with an `llm_call` on the same key =
  `label_llm_call_mismatch`) and resolves `requirement_ref` against the
  sealed obligations registry (`seal_requirement` → `requirement/0.1`;
  a dangling citation = `dangling_requirement_ref`). Provable becomes
  surfaced — the same promotion `verdict_predates_terminal` got.
- **Receipt v0.2.2 — the seam SCAR-45 exposed, closed at the schema (Reid +
  howcani)** — `build_receipt` gains `judged_by` ("deterministic" | "llm")
  and the schema enforces the declaration's consequence: an **LLM-judged
  receipt without `spec_hash` refuses to seal** (for an LLM-judged check the
  prompt IS the predicate — the optional path is gone, not labeled). The
  `spec_hash` travels IN the payload, and `requirement_ref` cites the
  obligation the verdict serves ("art. 12(1)", a SOP clause) — the #47 tie:
  obligation, not immunity. Stated residue: `judged_by` is itself a sealed
  declaration — lying about it is visible in the artifact.
- **verdict_predates_terminal — the scar becomes the spec (issue #53 —
  SCAR-PROC-110, Randal/gde)** — the race the replay suite surfaced as a
  named gap on day one ships as a check: an invariant may declare
  `terminal_type` (the event sealing a run's end state), and an outcome
  contradicted by a LATER terminal event — a witness digest that differs
  from the terminal's, or a different verdict — is the mid-flight forgery,
  surfaced. Pairing reads the terminal, not the first response; the
  waitpid-equivalent order and a confirming late terminal stay clean.
  ADR 019 amendment.
- **The SCAR replay suite (issue #53 — Randal/gde)** — the four gate-attack
  fixtures from the "200k-token lobotomy" article, replayed AS ATTACKS
  against the reconciliation layer, each asserting what the layer DOES:
  **SCAR-43** (in-session rubber stamp) caught TWICE — `unlogged_attempt`
  (the child invocation never sealed) and `same_key_pairing` (one writer on
  the verdict and its check, by signature); **SCAR-45** (watered-down
  prompt) detectable by arithmetic when the spec is committed — two
  semantics cannot share one `check_id` — with the optional spec-less path
  ADMITTED as the gap (the schema cannot infer which checks are
  LLM-judged; closing it is the deployment-layer refusal, the single-key
  split); **SCAR-89** (covert critic farming) — unjournaled rounds are the
  omission (`unlogged_attempt`), journaled rounds are AUDITABLE
  (sum-to-n counts the farming trail); **SCAR-110** (mid-flight forgery) —
  the forged verdict is PROVABLY pre-terminal from sealed evidence (the
  witness binds the mid-run digest, the terminal digest differs, the
  sequence is on the record), auto-surfacing named as the gap (the pairing
  takes the first outcome), and the waitpid-equivalent order shown
  sealing the forgery shape out of existence.
- **The toolset baseline — the lockfile nobody writes (issue #50 — bloqarl)** —
  tool descriptions are instructions the MODEL reads, and they ride outside
  the image pin (runtime-produced; for remote MCP, nothing pinned at all).
  `noirebox toolset-pin` captures the `listTools` response at registration,
  hashes it (canonical bytes) and seals it as the REVIEWED baseline —
  `reviewed_by` required, a name not a role: the baseline is sealed by
  whoever reviewed it, never by the process that connects (two-writer by
  construction). Every session start, `--check` diffs the served definitions
  against the baseline: changed description or schema, added tool, removed
  tool — each a `toolset_changed` finding naming the tool. Checking against
  no baseline is refused, never silently clean. `demo_mcp_toolset.py` shows
  the silent rewrite caught; ADR 025.
- **Evidence-grade labels in the audit-pack (issue #51 — mickyarun)** — the
  three-grade taxonomy made explicit and rendered per event class in the
  authority-facing Annexe IV §2(f): **grade 1 adverse counterparty** (custody),
  **grade 2 disinterested custodian** (RFC 3161/OTS), **grade 3 anchored self**
  (operator-held) — each stating whose obligation backs it ("no one can impose
  a cost here" means the evidence is voluntary). The disclosure cannot hide a
  grade-2 custodian behind a grade-1 counterparty sentence. ADR 022 amendment;
  journal-local defaults to grade 3 — the honest default.
- **Obligation, not immunity (issue #47 — mickyarun)** — the top rung of the
  custody/anchoring ladder is regulatory: every proof grade documents itself
  WITH the obligation it serves (ADR 022 amendment). The evidence exists to
  prove an obligation was met, never to shield the operator from it — the
  art. 12 log is the evidence OF the record-keeping obligation, not immunity
  from it.
- **receipt_gap: the two-sided denominator (issue #48 — mickyarun)** —
  across a trust boundary the denominator needs BOTH journals: the server
  seals `fetches_served`, the consumer seals `receipts_held`, and
  `check_receipt_gap` grades the pair (ADR 020 family). A shortfall is the
  two-party omission (fetches out, no receipt held — the chain intact AND
  incomplete); a surplus is the fabricated half (receipts beyond anything
  served). Zero-sum coverage is the only clean answer.
- **Cross-chain reconciliation (ADR 024, issue #41 — sinarezaei)** — the
  fleet's graph gets its edges. Consumption edges seal in BOTH journals
  (`consumption_edge`: the consumer's `consumed_head` as observed, the
  producer's "consumed by" half; a missing half is `unrecorded_edge` —
  silence is the starting fact). Invariants are DERIVED from anchors, never
  asserted: `stale_consumed_head` (the consumed head is gone from the
  producer's chain, or superseded), `temporal_inversion` (the consumed
  event's seal time postdates the anchor covering the consumer's edge —
  fraud@41 consumed by underwriting@39). A `supersede` event kills a head
  and drives the fan-in: the blast radius propagates along recorded edges
  as a precise path set, not "everything downstream, maybe". No epoch
  field — temporal position stays a relation between two sealed chains
  (the rejected alternative, §4). CLI: `noirebox crosschain --journal
  name=path …`; the report seals always, clean pass included.
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

[Unreleased]: https://github.com/noirebox/noirebox/compare/v0.16.0...HEAD
[Unreleased]: https://github.com/noirebox/noirebox/compare/v0.19.0...HEAD
[0.20.0]: https://github.com/noirebox/noirebox/compare/v0.19.0...v0.20.0
[0.19.0]: https://github.com/noirebox/noirebox/compare/v0.18.0...v0.19.0
[0.18.0]: https://github.com/noirebox/noirebox/compare/v0.17.0...v0.18.0
[0.17.0]: https://github.com/noirebox/noirebox/compare/v0.16.0...v0.17.0
[0.16.0]: https://github.com/noirebox/noirebox/compare/v0.15.0...v0.16.0
[0.15.0]: https://github.com/noirebox/noirebox/compare/v0.14.0...v0.15.0
[0.14.0]: https://github.com/noirebox/noirebox/compare/v0.13.0...v0.14.0
[0.13.0]: https://github.com/noirebox/noirebox/compare/v0.12.0...v0.13.0
[0.12.0]: https://github.com/noirebox/noirebox/compare/v0.11.0...v0.12.0
[0.11.0]: https://github.com/noirebox/noirebox/compare/v0.10.0...v0.11.0
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
