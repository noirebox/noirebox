# ADRs — NoireBox

*Architecture Decision Records: design decisions, context, and justification. These documents show that the project reasons about choices instead of just stacking features.*

---

## ADR 001 — Guardrail: regex heuristics first, then ML micro-model, LLM judge last

**Status**: decided (stages 0 and 1 in production), LLM judge in roadmap.

**Context**: every incoming transcript must be scanned before the agent.
Three detector families are possible.

**Decision**: layered architecture, cheapest to most expensive —
1. regex (obvious cases, zero cost, deterministic, testable in CI)
2. French ML micro-model (293 KB, generalizes to paraphrases, local)
3. LLM judge (only for ambiguous scores) — because it is the only stage that costs time and money per request.

**Consequences**: scanning stages 1–2 is effectively free, so we can scan every request instead of a sample. The incident format is unified across engines (positions + category), and the API selects via `engine: regex|ml`.

---

## ADR 002 — Reject Meta's Llama Prompt Guard 2 as the engine

**Status**: evaluated and rejected deliberately.

**Context**: Prompt Guard 2 22M (Meta) is the industry-standard prompt injection classifier (~90 MB). The question was whether to rely on it instead of training a homegrown model.

**Decision**: do not integrate it, for four measured reasons:

| Criterion | Prompt Guard 2 22M | NoireBox ML (293 KB) |
|---|---|---|
| Language | English (our meetings are **French**) | FR, versioned FR corpus |
| Output | binary INJECTION/BENIGN | 4 attack families → audit report + scoring |
| License | **gated** (HF account + Meta acceptance + token) | project artifact, zero friction |
| Dependencies | torch + transformers (heavy, opt-in) | scikit-learn only, already present |

## ADR 003 — Third-party detectors (Llama Guard 3, Prompt Guard 2): documented path, not embedded

**Status**: integration path documented; no third-party detector embedded in v0.

**Context**: the question naturally comes back — “why not plug in the industry classifier?” ADR 002 documented the rejection of Prompt Guard 2 (language, binary output, gated license, dependencies). This ADR fixes the integration path for the day a real need arises (e.g., product sold in English, client requirement for Meta ecosystem).

**Decision**: every third-party detector integrates behind the existing engine interface without touching the core:

```python
# Contract: same shape as guardrail.scan_transcript / ml_guardrail.scan_ml
def scan_<engine>(text: str, min_confidence: float = 0.5) -> list[dict]:
    # → [{"category": str, "score": float, "excerpt": str, "start": int, "end": int}]
```

1. **Adapter** (~40 lines): call the third-party model, map its output to the incident format above and include line offsets.
2. **Isolated dependencies**: separate `requirements-<engine>.txt`, late imports in `main.py` so the core stays lean.
3. **Actionable 503** if the engine is missing (exact install message).
4. **Skip-if-absent tests**: never simulated — third-party model absent means skip, never a made-up response (project anti-fake rule).
5. **Published benchmarks**: the third-party detector is compared with the internal engines on unseen FR *and* EN sentences before activation.
6. **License**: no unofficial mirror; gated handling stays on the deployment side (`HF_TOKEN`), never in the repo.

**Consequences**: adding a detector costs only an adapter; the LLM judge from ADR 001 (stage 2) follows the same path via `llama-guard3:1b` — already served by the required Ollama for the LLM scene.

---

## ADR 004 — OAuth2 authentication (JWT bearer) and rate limiting: optional via configuration

**Status**: implemented (v0.2.0).

**Context**: the API writes to a proof journal — without auth, anyone able to reach the port can create events (not forge them, which is impossible, but pollute them). The threat model listed the lack of auth/rate limiting as an assumed gap.

**Decision**:
1. **Homegrown OAuth2 client-credentials**: `client_id:secret` (env `NOIREBOX_CLIENTS`) exchanged for a **1-hour HS256 JWT** (`POST /api/v1/token`), presented as `Authorization: Bearer`. Secret comparison uses constant-time logic (`hmac.compare_digest`).
2. **Explicit activation**: without `NOIREBOX_CLIENTS`, the API runs open (local demo without friction); with the variable set, writes and exports are protected. Security is a deployment choice, never an accident.
3. **Precise scope**: auth protects WRITES (`POST /events`, `/scan`) and EXPORTS. VERIFICATION routes (`/verify`, `/attestation`, `/attestation.pdf`) remain open — we never lock verification, which is foundational to the project.
4. **Per-client rate limiting**: sliding window in memory (60 req/min), 429 + `Retry-After`. In-memory rather than SQLite: near-zero cost and never polluting the append-only journal. Redis = documented multi-process extension.

**Consequences**: the threat model gap for a network attacker is reduced to transport authentication (TLS handled by the reverse proxy); the JWT signing secret is derived from the instance key if `NOIREBOX_JWT_SECRET` is not set (unique per deployment, no config required).

---

**Refinement (2026-10-04)**: the open routes come in two classes. Verification
(`GET /api/v1/verify`, `POST /api/v1/attestation/verify`) is open ALWAYS — the class the
"never lock verification" rule is about. The metadata routes (`GET /api/v1/activity`,
`GET /api/v1/attestation`, `GET /api/v1/attestation.pdf`) expose aggregates and digests
only — never payload content (that is what the auth-gated `/events` and `/export` carry) —
and stay open by default because the third-party and DPO hand-over flows fetch them
without credentials; a deployment that wants even the aggregates behind the bearer token
sets `NOIREBOX_METADATA_AUTH=1` (protection is an explicit choice, the mirror of this
ADR's activation rule). `/dashboard` serves static HTML: behind auth its event fetches
degrade to the locked state while the verify badge keeps working.

## ADR 005 — PDF attestation: proof for humans, JSON for machines

**Status**: implemented (v0.2.0).

**Context**: the JSON export is proof for a verifier; a DPO, however, needs a document that can be placed in a compliance file.

**Decision**: `GET /api/v1/attestation.pdf` produces a sober A4 page (reportlab, PDF ~3.6 KB): chain status, public key, signature, and especially **verification instructions printed on the document** (exit 0 / exit 1, no trust required). JSON remains the single source of truth; the PDF carries the promise and the method, never a claim of certification (printed note at the footer).

**Consequences**: reportlab joins the dependencies (lightweight, pure Python); the EN localization of the document will follow with the product i18n work.

---

## ADR 006 — RFC 3161 anchoring: close the “insider with the key” gap

**Status**: implemented (v0.3.0).

**Context**: the threat model assumed a gap: an operator holding the private key could regenerate the entire chain (consistent hashes, valid signatures) — the only detection path was via a published external attestation. The underlying question: the journal proves integrity, but the DATE was self-declared by the accused.

**Decision**: `POST /api/v1/anchors` seals the chain head with a TSA (Timestamp Authority, RFC 3161):

1. Only the **head hash** leaves to the TSA (no data leaves the infrastructure — zero GDPR leakage).
2. The signed token + TSA certificate are journaled as an `anchor` event **inside the chain itself**: the journal seals its own external proof; no parallel storage.
3. The third-party verifier gains a check: the head named by the anchor is the real chain head at that height, the token is signed by the embedded TSA certificate, and it covers that hash. A regeneration creates a head the old token does not cover — detected without any prior external publication.
4. **TSA is interchangeable via configuration** (`NOIREBOX_TSA_URL`): self-hosted OpenSSL TSA (`make tsa`, separate process with its own key — free, offline, sovereign) is the default demo mode; any public or qualified TSA works in production. A TOFU model is assumed (the certificate travels in the anchor), with pinning possible on the verifier side.

**Consequences**: the threat model gap for “insider with the key” is closed (detection occurs at the first anchor, not at attestation time); verifier dependency = openssl (universal on macOS/Linux); TSA rotation is recommended in production to distribute trust.

---

## ADR 007 — Self-hosted TSA: root + leaf chain, not a single certificate

**Status**: implemented (v0.3.0).

**Context**: `openssl ts -reply` requires a signer certificate with TimeStamping usage; `-verify` also requires a CA certificate as trust anchor. A single CA:TRUE + TimeStamping certificate is rejected ("invalid signer certificate purpose"): a CA should not sign tokens.

**Decision**: the TSA material (`tsa/gen_tsa.sh`) generates a two-certificate chain — self-signed root (CA:TRUE), TSA leaf (CA:FALSE, critical EKU `timeStamping`) signed by the root — and serves the bundle at `GET /cert`. The bundle travels with each anchor and is given to the verifier twice (`-CAfile bundle -untrusted bundle`).

**Consequences**: setup validated experimentally (verify OK for the correct hash, FAILED for a different one); TSA port 3318 (ports < 1024 are privileged); the TSA material (`tsa/material/`) is never committed.

---

## ADR 008 — Multi-TSA anchoring with pinned roots: the trust root leaves the operator's perimeter

**Status**: implemented (v0.3.x).

**Context**: ADR 006 closed the "insider with the key" gap, but a self-hosted TSA sits in the operator's own trust boundary (`docs/THREAT-MODEL.md`): a dishonest operator signs its own tokens and the bypass reopens. EU compliance (GDPR art. 5.2 accountability; AI Act art. 12/19/26 logs — deadlines 2 Dec 2027 after Regulation (EU) 2026/1744) needs evidence whose root of trust is OUTSIDE the auditee's control: qualified eIDAS TSAs for legal presumption (eIDAS art. 41), public TSAs for immediate free coverage. Live-validated endpoints: DigiCert, FreeTSA (tokens verify against public roots; a tampered hash fails).

**Decision**:
1. **Profiles**: `NOIREBOX_TSA_PROFILES` (JSON list: name, direct RFC 3161 POST endpoint, optional cert_url — else the chain is extracted from the token, certReq). Legacy `NOIREBOX_TSA_URL` keeps working. One `anchor` event carries all tokens; the flat legacy fields mirror the PRIMARY token (put the qualified eIDAS TSA first) so OLD verifiers still validate a real token; the full list travels in `tokens` for the new verifier.
2. **Pinned roots**: `verifier/tsa_roots/<profile>.pem` — the verifier checks a token against the auditor's pinned root instead of the operator-shipped certificate (TOFU stays as fallback, reported as such). Root policy is append-only in practice (git history): retired roots keep verifying past anchors. Pin ROOTS only; intermediates travel inside tokens.
3. **Rotation**: each anchor ≥ 1 qualified TSA + rotating public witnesses (no single TSA sees the whole timeline). Anchoring only goes forward — a coverage gap is forever.
4. **Egress control**: the TSA host must be in `NOIREBOX_TSA_ALLOWED_HOSTS` (default: loopback, for `make tsa`) — explicit egress allowlist; link-local (cloud-metadata) targets refused after DNS resolution; redirects never followed; requests go through one shared no-redirect client.

**Consequences**: the "dishonest operator with everything self-hosted" bypass closes once a profile points at an independent TSA — the verifier's pinned root is the auditor's, not the operator's; multi-witness exports degrade gracefully on old verifiers (primary token still checked); OpenTimestamps (compute-grade witness) is the planned next profile type (ADR 009); qualified-TSA endpoints are config entries per provider terms. Rationale and regulatory mapping: `docs/COMPLIANCE-EU.md`.

---

**Refinement (2026-10-04)**: the egress control's honest shape. `_checked_endpoint`
resolves the allowlisted host and refuses if ANY resolved address is link-local — but the
check runs at request-build time while the HTTP client re-resolves DNS at connect time:
an attacker controlling the DNS zone of an allowlisted host could swap the IP in between
(DNS rebinding). The window is NARROWED (admin-controlled allowlist, no redirects,
credentials never in URLs), not CLOSED — transport-level pinning of the resolved
addresses is the complete fix and stays on the roadmap. Overclaiming a security boundary
is how boundaries stop meaning anything.

## ADR 009 — OpenTimestamps witness: the compute-grade layer (no operator at all)

**Status**: implemented (v0.5.x).

**Context**: RFC 3161 witnesses are organizations; even a qualified eIDAS TSA is a regulated company, not a law of nature. The strongest available anchor is one no operator can forge: OpenTimestamps batches the digest into a Merkle tree committed in a Bitcoin block — forging it means redoing the network's proof of work. Verification is ~30 µs of SHA-256 (measured): expensive to fake, free to check, valid as long as Bitcoin exists (fits 30-year retention without any CA staying alive).

**Decision**:
1. **Profile** `{"name": "bitcoin", "kind": "ots"}` in `NOIREBOX_TSA_PROFILES` — rides in the same `anchor` event as the RFC 3161 TSAs. Optional dependency (`ots` CLI, `pip install opentimestamps-client`); a missing binary is a hard error at stamping time, reported (never hidden) at verification time.
2. **Manifest indirection**: `ots stamp` covers `sha256(manifest)`; the manifest (journaled inside the token, base64) names `head_seq` + `head_hash`. The verifier's manifest check is pure Python — tamper detection works even with no `ots` binary installed; the CLI check adds the Bitcoin confirmation.
3. **Lifecycle**: receipts are pending at stamping time and Bitcoin-confirmed at the next block (~10 min). `ots verify` output is parsed: "Success" counts as checked, "Pending" is recorded (unverifiable counter) but never fails an export. Runbook: periodically `ots upgrade` exported receipts and re-verify.
4. **Old verifiers**: an anchor carrying any RFC 3161 token keeps the flat legacy mirror (first RFC 3161 token); an OTS-only anchor has NO flat form — pre-ADR-009 verifiers cannot read it (documented limitation; auditors use the current verifier).

**Consequences**: the witness stack is complete — qualified eIDAS (legal presumption) + public TSAs (immediate, independent organizations) + Bitcoin (compute-grade, zero trust in any operator); all three can live in one anchor event; graders `pins`/`unverifiable` keep the report honest about which evidence was used.

---

## ADR 010 — AI-Act-shaped events + audit-pack: speak the regulator's language

**Status**: implemented (v0.5.x).

**Context**: the AI Act (post-Omnibus: Annex III high-risk from 2 Dec 2027) requires automatic event logging (art. 12) with specific contents — art. 12(3)(a) period of each use, (b) reference database, (c) matched input data, (d) identification of the natural persons who verified results (art. 14(5)) — retained ≥ 6 months (art. 19/26(6)); GPAI providers must keep track of and document serious incidents (art. 55(1)(c), LIVE since Aug 2025). Technical documentation must describe the logging characteristics (Annexe IV §2(f)). A generic journal forces every deployer to re-invent this mapping.

**Decision**:
1. **Vocabulary** (`noirebox/aiact.py`): builders `use_event` (art. 12(3)(a)-(c)), `verification_event` (art. 12(3)(d)), `incident_event` (art. 55(1)(c)/73) produce validated payloads — event types `ai_use`, `ai_verification`, `ai_incident`. Minimization by construction: inputs are sealed as sha256 digests, never raw (the builder refuses non-digest values); an invalid date/threshold cannot be sealed.
2. **Audit-pack** (`noirebox audit-pack <dir>`): writes `export.json` (full signed export), `verifier_report.json` (the auditor's recomputation) and `ANNEXE-IV-2f.md` — the logging-characteristics description GENERATED from the journal itself: event-type histogram, art. 12(3) mapping table, integrity design, witness list, public key, verification instructions. Regenerating the pack and diffing is itself a tamper check.
3. The mapping table (`ART12_MAPPING`) is machine-readable in the module — the same source renders the doc and can drive future conformity tooling.

**Consequences**: a deployer of a high-risk system can make the NoireBox journal BE the art. 12 log (the fields the law names have first-class, validated homes); the auditor receives one directory that answers "what do you log, why can it be trusted, how do I check"; no legal advice is claimed — conformity remains the deployer's responsibility (`docs/COMPLIANCE-EU.md`).

## ADR 011 — Content-provenance events: what model-collapse research asks for, in journal form

**Status**: accepted — documented convention + demo (`demo/demo_provenance.py`); no schema change (rides the existing free-form payload).

**Context**: model collapse (Shumailov et al., Nature 631, 755–759, 2024 / arXiv:2305.17493) is what happens when corpora swallow unlabelled synthetic text and models recurse on it. The paper's discussion names the gap: "The need to distinguish data generated by LLMs from other data raises questions around the provenance of content that is crawled from the Internet: it is unclear how content generated by LLMs can be tracked at scale." Its proposed remedy is coordination: "One option is community-wide coordination to ensure that different parties involved in LLM creation and deployment share the information needed to resolve questions of provenance." A shared, tamper-evident provenance registry is that coordination in infrastructure form — and it is the exact shape NoireBox already has: append-only hash chain, signatures, multi-TSA/OpenTimestamps anchoring (ADR 006–009), regulator-facing vocabulary and audit-pack (ADR 010). Honest scope up front: NoireBox proves DECLARED provenance, it does not detect synthetic text; the binding agent is whoever seals. This is evidence infrastructure for honest parties (authors asserting human origin, corpus builders asserting what they ingested), not a detector, and adoption is an ecosystem question.

**Decision**:
1. **Two event conventions** (hashes only, never raw content — minimization by construction as in ADR 010):
   - `content_provenance` — `{origin: "human" | "ai-agent" | "ai-assisted", content_hash, content_type?, author_key?}`, sealed at creation time; once anchored, the authorship claim is dated and non-repudiable.
   - `ingestion_decision` — `{batch, doc_hash, declared_origin ("human" | "ai-agent" | "ai-assisted" | "unknown"), decision ("include" | "exclude"), reason}`, one per ingested document; a corpus manifest becomes an auditable timeline instead of a claim.
2. **Retroactive recursion proof**: because every seal carries a timestamp and the chain is anchored, a batch that includes the hash of content sealed as `ai-agent` EARLIER in the chain is provable recursive training — even if the crawler never consulted the registry (one anchor seals the whole past, ADR 009). The demo walks the journal and flags exactly that case.
3. **Demo** (`demo/demo_provenance.py`): two origins sealed at creation; three ingestion decisions (include / exclude / include with `unknown` origin); the recursion proof on the unknown-origin document; a rewritten exclusion decision explodes the chain.

**Consequences**: corpus builders get an answerable "what did you train on, when, and can you prove it" without new infrastructure; authors get a dated, hash-level claim of human origin; any MCP client can seal the conventions today (witness recipe). The limit stays visible by design: `unknown` exists as a `declared_origin` value because coverage will be partial — the convention is NoireBox's contribution to the coordination the paper calls for, not a collapse vaccine.

---

## ADR 012 — Model-trajectory sealing: the flight recorder's flight recorder

**Status**: implemented (v0.7.x) — builder (`noirebox/trajectory.py`), CLI (`noirebox seal-trajectory`), tests.

**Context**: coding agents already ship their own flight data recorder: one JSONL file per session, one line per LLM call — request messages, response text, tool calls, token usage, timings, per-call origin. Some agents even expose a viewer menu over it. But the file is local, unsigned, unanchored: an edited, truncated or re-ordered log looks exactly like an honest one, and nothing distinguishes a reconstructed history from a recorded one. This is the exact gap NoireBox exists to close — and it is closed the same way for any agent emitting a per-call log. GDPR note that shapes the design: these files contain full conversation text, so the journal must never ingest them raw.

**Decision**:
1. **Event convention `model_trajectory`** — digests only, minimization by construction (as ADR 010): `file_sha256` (the bytes as observed), `trajectory_digest` (order-committed digest chain: `d0 = 0*64`, `d_i = sha256(d_{i-1} + record_digest_i)` over `sha256(canonical(record))` per line), `record_count`, `session_ids`, `models`, `query_sources`, `first/last_started_at` (the period-of-use shape of AI Act art. 12(3)(a)), `truncated_tail`. A Merkle root over a set would not suffice: the ORDER of calls is semantic — the same calls in a different order is a different behavior, and a rewrite of history must accuse.
2. **The seal names its sealer**: every `model_trajectory` payload carries `source: {tool, version}`. A proof is only as strong as the binding agent (ADR 011's stated limit — "the binding agent is whoever seals"); from this ADR on, the binding agent says who it is. Third-party sealers (an MCP client, a CI job) cite their own identity; the convention field is the first brick of sealer identity (v0.7).
3. **The observed log, not the reconstructed trajectory**: delta records are not stitched back together — reconstruction is the viewer's job. The seal commits to the log AS OBSERVED, per record: that is the byte-faithful claim a flight recorder can make. Corruption policy is honest by construction: an unparseable LAST line is an incomplete trailing write, reported (`truncated_tail`) and sealed as seen; an unparseable line mid-file is a hard error — silently sealing a partially-read log would manufacture the fake evidence this project exists against.
4. **Verification is recomputation**: `verify_trajectory(payload, file)` returns None when intact, otherwise the reason (house convention). Given the file and the payload, anyone recomputes the digests and confronts them — content edits, record insertion/removal, reordering and a swapped file each produce a distinct accusation. Anchoring (ADR 006–009) dates the seal: the trace existed, in that order, by that date, and no one — operator included — can rewrite it afterwards.

**Consequences**: an agent's behavior trace becomes auditable evidence — incident forensics ("what calls actually ran"), deployer accountability (art. 12), and the provenance register of ADR 011 gains its source side (a training run's own `querySource: subagent` chains can be sealed as they happened). The seal commits, it does not store: the trajectory file itself must be retained for the commitment to be checkable (same retention shape as ADR 010 inputs). Schema drift is tolerated by design — unknown fields hash fine (canonical JSON over whatever arrives), absent fields are simply not counted — so a future agent version does not break old seals.

---

## ADR 013 — Transcript-agnostic sealing + per-project journals: the integration layer

**Status**: implemented (v0.7.x) — `noirebox/transcripts.py`, `noirebox/locate.py`, `noirebox/hookcli.py`, CLI `seal` / `verify` / `locate` / `hook`, and the first integration plugin (Claude Code, `plugins/claude/`).

**Context**: ADR 012 sealed one log shape through one agent's hooks. The sealing machinery never needed that specificity — a JSONL line is a record, the digest chain commits whatever the record contains — but the reader hardwired one format, the journal path was deployment-specific (a hardcoded home directory), and growing integrations without fixing this would fork the core per app.

**Decision**:
1. **Formats are named by SHAPE, deliberately not by product**: `model-io` (one line per LLM call), `session-transcript` (one line per conversation event), `generic-jsonl` (fallback — still sealable, digests and count only). All ride the same `model_trajectory` event type and the same order-committed digest chain; `origin` carries the shape. Metadata extraction is tolerant and envelope-only (session ids, timestamps, model names, per-call origins — never message content): present fields are committed, absent fields are simply omitted, so schema drift degrades gracefully. ADR 012's strict reader stays as-is for `model-io` logs (legacy origin string unchanged — old seals keep verifying).
2. **Per-project journal discovery** (`locate`): `NOIREBOX_DB` wins explicitly; otherwise the nearest ancestor directory holding a `.noirebox/` directory owns the journal; otherwise `./.noirebox/journal.db` is created on demand (directory 0700, database 0600). One project = one journal: custody follows the working tree, and committing `.noirebox/` to git is the user's deliberate choice (evidence publication).
3. **Generic hook handlers** (`noirebox hook tool-use | session-end`): hook JSON on stdin, one event out. `tool-use` seals `agent_tool_use` (tool name + truncated input preview — data minimization as in ADR 010); `session-end` seals the transcript file named by the hook payload. Best-effort by contract: the agent never blocks, failures are loud on stderr, exit stays 0; an unreadable hook payload seals NOTHING (no evidence manufactured).
4. **The CLI completes the integration surface**: `seal <type> <json>` (one free-form event), `verify` (in-place chain verdict, exit 0/1), `locate` (print the resolved journal). Hooks, MCP server and CLI write the same journal with the same key.
5. **Integrations are glue, the core stays single**: the first plugin (Claude Code) is manifest + hook JSON + command docs over these shared handlers. Every other agent with a hook system or MCP support reuses the same handlers (see `docs/ROADMAP-PLUGINS.md`).

**Refinement (2026-10-04)**: the analysis commands (`reconcile`, `audit-pack`,
`seal-trajectory`) follow the same discovery — `NOIREBOX_DB`, then the nearest ancestor
`.noirebox/` — with one extra final fallback to the classic repository layout
`data/noirebox.db`, and they never create a per-project journal on demand. They operate on
a journal that already exists; `seal` (which creates on demand) and `audit-pack` (which must
not) resolving two different journals from one directory was the exact split-brain this
closes (`locate.resolve_existing_journal`).
**Consequences**: adding an app costs a manifest and two hook lines, not a fork; formats named by shape avoid turning one vendor's log format into convention debt. The honest limit stays visible: agents that expose neither hooks, MCP, nor a per-call log cannot be flight-recorded — for those, NoireBox is the on-demand custody layer (seal/verify/attest via MCP), and we do not claim otherwise.

---

## ADR 014 — The JWT signing secret is derived from private material, never from public data

**Status**: implemented (v0.7.x) — `noirebox/auth.py` `_jwt_secret()`, adversarial tests in `tests/test_auth_pdf.py`.

**Context**: the optional OAuth2 layer (ADR 004) signs its 1 h HS256 tokens with `NOIREBOX_JWT_SECRET` when set. Its zero-config fallback, however, derived the secret as `sha256(public_hex)` — and the public key is not a secret at all: it travels in every export and attestation, and `GET /api/v1/attestation` serves it open by design (ADR 004: one never locks verification). Anyone able to read an export could therefore re-derive the "secret" and forge tokens for any `client_id` — bypassing both authentication and the per-client rate limit. Enabling auth without the env var gave false assurance; the flaw was found by the 2026-10 project-wide review, not by an incident.

**Decision**:
1. **Fallback derivation uses private key material only**: `sha256(private_bytes_raw)` of the instance's Ed25519 key. The private PEM is chmod 600 and read by the server process alone (chain.py), so the derived secret is as exposed as the key file itself — and whoever holds the key file already owns the journal; there is no weaker intermediate state. Every deployment still signs with something unique, zero-config still works.
2. **`NOIREBOX_JWT_SECRET` remains the override** — deployments that rotate secrets independently of the journal key, or share one secret across replicas behind a load balancer, keep full control.
3. **Token validity stays bound to the key file**: regenerating the journal key invalidates the derived-secret tokens (same behavior as the old public derivation; documented, not an accident).
4. **Adversarial test as regression fence**: a token forged with the OLD public-key derivation must be rejected, the private-material roundtrip must pass, and a token issued against journal A must not verify where journal B lives (per-instance scoping).

**Consequences**: enabling auth is now meaningful with configuration alone (`NOIREBOX_CLIENTS`); the threat "forge tokens from public information" is closed by construction and fenced by a test named after it. Tokens issued by a pre-fix deployment are invalidated by the upgrade — deployments that care re-issue; the journal itself is untouched (payloads are opaque to the chain). The broader review lesson: nothing security-critical may be derived from data the system publishes.

---

## ADR 015 — The tier-2 judge: a local LLM behind the house taxonomy, JSON-pinned, honest when silent

**Status**: implemented (v0.8.x) — `noirebox/llm_judge.py`, `engine: "llm"` on `POST /api/v1/transcripts/scan` and the SDK, demo (`demo/demo_judge.py`), skip-gated real-judge tests + always-on stub tests.

**Context**: ADR 001 defined the guardrail as stages — regex (free, deterministic) → ML micro-model (paraphrases) → an LLM judge "only for doubtful cases" — and left stage 2 in the roadmap. The judge must not reintroduce what ADR 002 rejected: cloud calls, gated weights, unparseable binary output, or a taxonomy foreign to the journal's. The transcript also must not leave the machine: the judge is a LOCAL LLM (llama-guard3:1b via Ollama, `NOIREBOX_JUDGE_MODEL` to swap), the same runtime the demos already ship.

**Decision**:
1. **The house taxonomy is the contract** (`JUDGE_CATEGORIES`): the judge is prompted with the four families the journal already seals (instruction_override, data_exfiltration, pii_request, tool_abuse) — not with llama-guard's own S-category list, whose overlap with meeting-transcript injection is partial. A verdict outside the taxonomy is DROPPED: a hallucinated category is not an incident. The trade-off is stated: we prompt the model off its native policy format in exchange for a taxonomy the whole pipeline shares.
2. **JSON-pinned, temperature 0**: Ollama's `format: "json"` makes the parser's strictness enforceable, and a judgment must be reproducible before it is auditable. Line NUMBERS are the mapping contract (the model never emits offsets); the parser maps them back to exact text spans with the same splitlines walk the guarded pipeline's filtering uses — judge incidents filter lines exactly like regex/ML ones.
3. **Binary verdicts, honest shape**: score is fixed at 1.0 (a judgment is not a probability dressed as a measurement) and each verdict carries a short `reason` (≤ 200 chars) in the incident dict — additive key, other engines' dicts unchanged.
4. **Honest when silent**: an unparsable judge answer raises → the route answers 503; nothing is manufactured into an incident. Unavailability is detected, never assumed (`judge_available` checks Ollama AND the model's presence, mirroring `model_available`).
5. **Surface**: `engine: "llm"` on the scan route + SDK (the MCP tool keeps the regex engine in v1 — its surface stays minimal, the API carries the engines). Sealed incident payloads carry `engine: "llm"`, so the journal distinguishes which judge sealed what.

**Consequences**: the guardrail now has all three ADR 001 stages; deployers choose per scan whether to pay for the judge (explicit engine choice, no silent escalation in v1 — auto-tiering "regex → ML → judge on ambiguous scores" is documented as the next composition step, ADR 003-style). The real-judge tests are skip-gated like every Ollama path; the stub suite carries CI without the model. The judge inherits the honest limits: it is probabilistic, its false negatives are non-zero, and it is a PLUGIN — delete `llm_judge.py` and the core still runs.

---

**Amendment (2026-10-04, real-model evaluation)**: the proposed default judge was
evaluated on the FR attack corpus and REJECTED — the lesson of ADR 002 repeating itself,
this time caught by the skip-gated real-model tests this ADR introduced.
llama-guard3:1b does not follow a custom policy (prompted with the house taxonomy, it
answers in its native S-category format) and does not classify transcript injection as
unsafe: 3 of the 4 corpus attacks scored "safe". A general instruction-following model
with the house-taxonomy few-shot JSON prompt is the judge instead — default
`qwen2.5-coder:3b` (`NOIREBOX_JUDGE_MODEL`): 4/4 detections, correct categories, zero
false positives on the clean line in that evaluation. Two honest footnotes: the 0.5B
class followed the JSON format but flagged everything (format compliance is not
judgment); in full-transcript mode the 3B is conservative (it names the clearest
override, not all four planted attacks) — its sweet spot is arbitrating the doubt band,
which is exactly the tiered scan's shape. ADR 002's rule generalizes: evaluate the judge
on the real corpus before defaulting, not after.


---

## ADR 016 — The tiered scan: the judge pays only for doubt

**Status**: implemented (v0.8.x) — `noirebox/tiering.py`, `engine: "tiered"` on the scan route, stub-tested (the judge itself is real-tested in `tests/test_llm_judge.py`).

**Context**: ADR 001 described the guardrail as stages "cheapest to most expensive, the LLM judge only for ambiguous scores" — but the shipped engines were all-or-nothing per call: `engine=regex|ml|llm` each scan the whole text. Auto-escalation was the missing composition, and the one that makes a local 3B judge economically sensible: it should see the handful of lines the cheap engines could not decide, not every transcript.

**Decision**:
1. **Stage 1** — the regex scans the whole text (free, deterministic). **Stage 2** — the ML model scores every line with its documented 0.5 threshold. **Stage 3** — ONLY the lines both stages left unflagged while the ML did not call confidently clean — the doubt band `[0.20, 0.50)` — are arbitrated by the LLM judge (ADR 015). A line the ML confidently calls clean is NOT judged: `engine="llm"` is the choice for full-coverage judgment, `engine="tiered"` is the choice for automatic escalation.
2. **Stage 1 beats stage 2 on the same line**: an ML detection whose span a regex incident already covers is dropped — one attack, one incident, the deterministic engine names it.
3. **Degradation is visible, never silent**: if doubtful lines exist but the judge is unavailable, stages 1–2 stand and the count of unarbitrated lines travels in the sealed payload (`tiering: {judge_skipped: n}`) — the journal records exactly how much doubt went unanswered.
4. **The meta is part of the evidence**: the incident payload carries the tiering split (`regex / ml / judge / doubtful / judge_skipped`) — an auditor sees not only what was caught but which stage caught it and how much doubt there was.

**Consequences**: the full ADR 001 pipeline exists end to end, and its cost profile is the promised one — regex runs always, the ML always (milliseconds), the judge only when the cheap engines disagree with themselves. The doubt band `[0.20, 0.50)` is a product constant, not a hidden threshold; moving it is a deployment conversation.

---

## ADR 017 — The fleet hub, v0: one seal covers N journals, wired into the product

**Status**: implemented (v0.8.x) — `noirebox/fleet.py`, CLI `noirebox fleet-anchor` / `noirebox fleet-verify`.

**Context**: the Merkle layer (ADR 008) existed as a library and a demo only: the Certificate-Transparency shape was documented but nothing in the product built or checked a fleet seal. The hub was the oldest open roadmap item after the judge.

**Decision**:
1. **`noirebox fleet-anchor journal1 journal2 … [--db hub.db]`** collects each journal's 32-byte head, builds the canonical Merkle tree (merkle.py — sorted leaves, ~log2(N) proofs), gets ONE witness token over the root through the same TSA profile machinery as single-journal anchors (ADR 006/008), and seals a `fleet_anchor` event in the hub's own journal — the hub is itself a NoireBox, so even it cannot rewrite which heads took part.
2. **`noirebox fleet-verify journal --db hub.db`** recomputes the member's inclusion branch locally and confronts it with the sealed root. No hub contacted, no TSA called back — the arithmetic decides. A journal whose history was regenerated produces a head the seal never committed to: not covered, exit 1.
3. **Witness semantics are honest by mode**: without a configured TSA the seal refuses by default; `--allow-local` seals with `witness: "local"` in the payload — the proofs still verify, but no external date attests the root, and the payload says so.
4. **Honest limits**: empty journals are skipped loudly (a GENESIS head proves nothing); duplicate member names are refused (proofs are indexed by journal name); the third-party verifier does not yet check `fleet_anchor` tokens inside a full export — fleet verification goes through `fleet-verify` until the verifier learns the event type.

**Consequences**: the fleet story is now product, not poetry: N boxes, one seal, per-member proofs, local detection of rewritten members. What stays open is the scheduled hub (console, alerting, automatic re-anchoring of a growing fleet) — the operational layer around a primitive that now exists.

---

## ADR 018 — The key may live outside the disk: secret-manager injection, loud on mismatch

**Status**: implemented (v0.9.x) — `noirebox/chain.py` `load_instance_key()` + `KeyPair.from_private_pem()`, wired through the server and every CLI journal path.

**Context**: the threat model says it plainly — the private key on disk is a v0 limit (HSM/KMS on the roadmap), the countermeasure being the published, anchored attestation. The honest middle step before hardware: let the deployment's secret manager (Vault, AWS/GCP secret stores, KMS-wrapped PEM) hold the key and inject it, so no PEM file has to exist at all. What the journal cannot tolerate is the OTHER direction: a key that changes, because the chain's identity IS its key — a new event signed by a different key breaks verification from that append on.

**Decision**:
1. **`NOIREBOX_KEY_PEM` wins over the key file**: the environment hands the Ed25519 PEM the secret manager holds; `load_instance_key` uses it and never writes a file. No env → the classic 0600 file beside the journal, unchanged.
2. **Mismatch is refused at boot, loudly**: if a key file already exists and the injected PEM is a DIFFERENT key, booting fails with a RuntimeError naming the consequence ("appending with it would break the chain") — a misconfigured secret becomes a boot error, not an auditor's discovery weeks later.
3. **The key is the journal's identity, and that is not negotiable**: rotating the secret requires re-anchoring and a new journal (or an explicit, deliberate key-file removal). No silent rekey path exists — by design.

**Consequences**: the HSM/KMS checkbox moves from "key on disk, documented" to "key in the operator's secret infrastructure, injection contract tested" — the hardware step (an HSM actually signing inside itself, so the key never exists in process memory) remains the genuinely roadmap item. Everything else in the stack needed no change: the verifier never sees the private key, the attestation carries only the public one, and the anchoring machinery is agnostic to where the key sleeps.

---

## ADR 019 — Receipt schema v0.2: the verdict binds its check, its evaluator, and its reach

**Status**: accepted — consolidation of the public launch threads (sunnydachs "verified", anp2network, mayailands, housharenet/Ryan Cole); implementation in `reconcile.py` v0.2 + the `witness` convention. To be linked to sunnydachs ("yes to the schema pass when it exists").

**Context**: the journal seals what was sealed — but a verdict like "tests pass" is a self-report unless the receipt binds (a) the exact bytes judged, (b) the check that judged them, (c) the checker itself, (d) the questions asked, and (e) a signature the judged party cannot forge. Each gap was named in public, independently, within one week.

**Decision** — a `receipt` payload carries:
1. **`artifact_sha256`** — the verdict binds the bytes (existing).
2. **`check_id` = predicate + declared inputs + version** — the verdict binds the check that produced it. A no-op verifier can no longer emit the same record as a real one: the predicate is part of the commitment (anp2network).
3. **`evaluator_sha256`** — hash of the checker script itself. If the judged agent can touch the test suite, receipts produced after the touch are invalid — the exam and the candidate hash together (housharenet/Ryan Cole).
4. **`predicate_id` anchored on the BASE BRANCH** — the questions live outside the agent's working tree; "the agent cannot rewrite the exam".
5. **`run_id` + timestamp** — correlation across the run; counting becomes sum-to-n (sunnydachs).
6. **Signature outside the judged party's reach** — a receipt signing key NOT in the agent's context, a verdict file written read-only, a gate enforced at merge/handoff. The agent cannot self-certify; that is deployment architecture, not schema — but the schema names the requirement.
7. **Pairing imposed by schema, not requested from integrators**: the receipt and the check-name are emitted under **two different keys** (sunnydachs, reply to slabb, 05/10). A check name is fabricable as true by whoever holds one key; two keys with a reconciliation pairing make the forgery a visible two-writer problem.
8. **Normalized witness, not raw** (Ryan Cole's question): binding exit_code + raw stdout is noise (timestamps, locale, progress bars). The witness binds: exit code, byte counts stdout/stderr, SHA-256 tree of modified files before/after, container image digest. When content is needed, canonicalize first (volatile fields stripped, fixed locale, no wall-clock) then hash. Both sides of the conversation independently byte-count — the pattern is validated.
9. **Clean passes are events too** — the reconciliation layer seals its report even when everything matched: a checker that only journals findings has no proof it ever ran (sunnydachs). Sum-to-n must climb from the analyzer to the handoff.
10. **Negative controls are receipts too** — the checker emits receipts on deliberately-false probes; a verifier that never said false carries no information (mayailands + close). A scheduled false probe is the cheapest proof the check still bites.

**Consequences**: `reconcile.py` v0.2 ships the implementable core tonight — always-sealed reports with run counts, negative probes, the attempt/outcome pairing (ADR 020). The two-key receipt pairing and merge-gate enforcement are deployment contracts the schema names; first implementations may start single-key and say so in the payload (`pairing: "single-key"`), because a labeled weakness beats an invisible one.

**Amendment (v0.2.1, Oct 8 — sinarezaei's TOCTOU + sunnydachs's spec step + the single-key refusal made explicit)**:
1. **State binding**: a receipt can carry `state_binding: {resource, resource_version}` — the state version the gate evaluated, in the executor's own currency (Kubernetes resourceVersion, git tree-ish, ETag). The executor applies it as a precondition: a call carrying the sealed version fails loudly when the state moved (optimistic concurrency — the mechanism Kubernetes already ships; noirebox specifies it as a SCHEMA field, not an integrator option). Divergence is a sealed event: `receipt_expired_by_state_change` → new gate pass → new receipt — never silent reuse of a receipt invalidated by state change. Time-of-use now fails whenever it diverges from time-of-check.
2. **The spec hash is inside the check identity**: `check_id` accepts `spec_hash` — the hash of the spec/prompt defining the predicate's semantics ("the step I had not taken" — sunnydachs). Required for LLM-judged checks; without it one check_version can validate two semantics under one id.
3. **The single-key refusal, stated**: the schema LABELS (`pairing: "single-key"` is a required-validated field) and the layer above REFUSES — an invariant with `require_two_key` treats a same-key matched pair as the `same_key_pairing` finding (shipped in reconcile v0.2). Labeling is the schema's job; refusing is the gate's; both are now written down.
4. **The executor verifies the SIGNATURE, not the presence** (slabb's close on the sinarezaei thread): a receipt proves non-mutation only if the executor verifies the writer's signature — a control plane where writer and executor share one trust domain is the shared-dependency test (ADR 021) one layer down. One line, now in the deployment docs.

---

**Amendment (Oct 8, issue #35 — mickyarun)**: the precedence rule is a sealed
event (`reconciliation_policy/0.1` — scope, winner enum decision|outcome|external,
absorbs_cost, decided_by REQUIRED, a name not a role). Decided before the
incident, journaled like everything else; the argument is no longer settled by
seniority.

**Amendment (Oct 8, issue #38 — glenallen)**: legitimate transformations are a
sealed convention (`content_transformation/0.1` — before/after sha256,
transformer identity). A formatter changes the artifact as a witnessed
transformation, not an attack.

**Amendment (Oct 9, issue #42 — pm25coder, verifier thread round 4)**: a
negative control's known value is a RANGE, not a point — and the range is an
**a-priori bound**, derived from what the construction licenses (the bound the
conditional law sets), never fitted from the enumerated constructions: fitted
in-sample, the first correct construction the checker has never met reads as a
failure. Shipped as `calibration/0.1` (`seal_calibration` — value AND width
predate the run, `derivation` and `declared_by` required; `source` grades the
derivation and the layer above REFUSES an `observed-spread` range as the
finding `calibration_fitted_in_sample`, the ADR 019 §3 split). The observed
spread is not discarded — it travels with the witness as calibration HISTORY
(`calibration_observation`), never re-fitting the bound. The run itself is
graded against the bound (`control_out_of_range` — the checker drifted, or the
range was fitted).

**Amendment (Oct 10, v0.2.2 — Reid + howcani: two commentators, one evening;
the seam SCAR-45 exposed, closed at the schema)**: `build_receipt` gains
`judged_by` ("deterministic" | "llm") and the schema enforces the
declaration's consequence — **`judged_by="llm"` without `spec_hash` REFUSES
to seal**: for an LLM-judged check the prompt IS the predicate, and the
optional path the replay suite walked through no longer exists. `spec_hash`
travels IN the payload — the artifact carries the commitment it was judged
against, not just an id that may or may not embed it — alongside
`requirement_ref`: the obligation the verdict serves, cited ("art. 12(1)", a
SOP clause), the #47 tie — obligation, not immunity. The honest residue,
stated in the builder's own docstring: `judged_by` is itself a sealed
declaration; lying about it is visible in the artifact — one step stronger
than a label, one step weaker than mind-reading.

**Amendment (Oct 11, v0.2.3 — howcani's audit ran the validator, not the
diff; Randal mapped the seams to the classics)**: `judged_by` becomes
REQUIRED with no default. v0.2.2's optional field defaulted to the tier
that requires nothing — an LLM-judged check that said nothing sealed
exactly the receipt SCAR-45 walked through, with "deterministic" written
in it: omission and honesty produced the same bytes. A two-valued security
enum defaulting to the unverified tier on omission is the classic
default-to-permissive downgrade (the `alg: none` structural twin); the
fix is fail-closed — an honest caller pays one keyword, the laundering
path ceases to exist. The receipt's declarations also stop being
unverified claims: `reconcile_receipts` joins the label against
**out-of-band telemetry** — a receipt declaring "deterministic" while the
journal contains an `llm_call` for the same key is the finding
`label_llm_call_mismatch` (a self-reported label checked against an
observation the labelled party did not author), and `requirement_ref`
resolves against the sealed obligations registry (`seal_requirement` →
`requirement/0.1`) — a dangling citation is `dangling_requirement_ref`.
Provable becomes surfaced: the same promotion `verdict_predates_terminal`
got.

**Amendment (Oct 11 evening, v0.2.4 — howcani pulled the tarball, re-ran
the three receipt paths, then named the CEILING)**: everything above
holds — and the v0.2.3 join has a structural blind spot both sides of it
share: the label AND the observation come from the same store, the same
key, the same writer as the receipt. The join catches the INCONSISTENT
agent; it is structurally blind to the CONSISTENT agent that never
journals an llm_call. *The failure mode is absence — the one thing a
chain cannot see.* Three closures:

1. **The transport-writer invariant** (the burden inverts, one layer
   down): a receipt declaring `judged_by="deterministic"` is verified
   only by a TRANSPORT attempt on the same key (the hook process's
   `agent_tool_use` — sealed by a writer the agent does not control),
   sealed by a key other than the receipt's own. No transport attempt,
   or only same-writer attempts: the finding `unverified_label`. No
   longer "prove no model was called" (unverifiable from inside) — "a
   deterministic label without a transport witness is the finding."
   Absence becomes a missing event, not a missing negative; the
   attempt-first move (ADR 020) applied to the transport layer.
2. **`requirement_ref` goes load-bearing** — the citation is confronted
   with its SCOPE: the sealed requirement names the paths it governs AT
   SEAL TIME (`requirement/0.2`), and the diff's touched set — from git,
   the first observation the citing agent does not author — must
   intersect that scope, or the finding `requirement_out_of_scope`: the
   obligation cited does not govern this work.
3. **The lineage, corrected (this supersedes the `alg: none` mapping
   above)**: howcani's note — same FAMILY (the seal verifies but proves
   nothing), DIFFERENT repairs. `alg: none` closes by refusing the
   ALGORITHM; the wrong-issuer shape closes by NAMING the issuer. v0.2.3
   was the wrong-issuer repair done right: `judged_by` required makes
   every receipt NAME who judged, and v0.2.4's transport join then
   CHECKS the named issuer against an observation the issuer does not
   control. The next schema reader starts here, not at JWTs.

**Amendment (Oct 10, issue #53 — SCAR-PROC-110, the scar becomes the spec)**:
the replay suite surfaced the pairing race as a named gap on its first day;
it ships as a check the same week. An invariant may declare `terminal_type` —
the event sealing a run's END state (transcript digest, terminal verdict). An
outcome contradicted by a LATER terminal event (a witness digest that differs
from the terminal's, or a different verdict) is the mid-flight forgery:
`verdict_predates_terminal`. The sound orders stay clean — terminal before
the verdict (the `waitpid()`-equivalent), or a later terminal that confirms
it (honest, just slow). Pairing reads the terminal, not the first response.

## ADR 020 — The denominator: attempt-first sealing, outcomes ≤ attempts

**Status**: accepted — the hardest critique of the week (arhancanli, thread james): "every logged number is real and the denominator is missing." James conceded it publicly; whoever solves it scores.

**Context**: a hash chain catches tampering with what was written. It structurally cannot catch **the entry never written**: an agent that attempts 20 times, seals one success, produces a perfectly intact chain of an omission. Integrity of what is sealed ≠ completeness of what happened.

**Decision**:
1. **Attempt-first convention**: every consequential action is preceded by an `attempt` event sealed BEFORE the outcome exists — attempt (intent + inputs digest) → outcome (result). The attempt is cheap, it is the denominator, and it is sealed at the moment of least temptation.
2. **The invariant is testable**: `outcomes sealed ≤ attempts sealed` per correlation key. An outcome with no attempt sealed earlier is the omission, surfaced: status `unlogged_attempt`.
3. **Sum-to-n climbs the ladder**: run receipts (ADR 019) carry attempt/outcome counts; reconciliation reports them; a hand-off can demand n attempts and n-1 outcomes with an explanation — the count is a first-class artifact.
4. **Honest limit, stated in the schema**: the convention only covers flows that USE it. An agent bypassing the attempt convention produces a chain that is intact AND incomplete — which is why the denominator critique is answered with a convention + an invariant, not a promise. Completeness of coverage remains the deployer's discipline (as with the guardrail: the journal is domain-blind).

**Consequences**: `reconcile.py` gains `attempt_type` support and the `unlogged_attempt` status; the demo flows seal attempts. The critique's residue is now a named, counted, reconcilable gap instead of a blind spot.

**Amendment (Oct 8, issue #37 — david_ilands, the outbound half)**: a pending expectation is PROVABLE only if it is witnessed — its head anchored (verified against the chain, not claimed) or co-signed by a different known writer (`expectation_ack`). Otherwise the finding is `unwitnessed_expectation`: a wish with a hash. The invariant opts in with `witnessed_expectations: true`.

**Amendment (Oct 9, issue #43 — david_ilands, the channel rung)**: admissibility
sits UPSTREAM of delivery — sent/accepted/delivered presuppose a counterparty
already reachable in the space where the answer is visible (same agent, same
month: 0 replies from 10 cold emails vs 3 from live-thread comments). The
expectation MAY declare `channel: {kind, reachability: "demonstrated"|
"assumed"}`; every expectation row grades it: **demonstrated** (admissible —
silence measures the exchange), **assumed** (cold — silence measures the
SENDER's channel choice, not the recipient's conduct), **undeclared** (no
admissibility story on record — the same invisibility the schema refuses
elsewhere). Convention, not enforcement: the journal records the grade; it
cannot make the counterparty answer — and the denominator critique (arhancanli)
applies to the channel too.

**Amendment (Oct 9, issue #48 — mickyarun, the two-sided denominator)**: across
a trust boundary the denominator needs BOTH journals. The server seals
`fetches_served`, the consumer seals `receipts_held` — both counters sealed
like everything else — and `check_receipt_gap` grades the pair. A shortfall is
the two-party `unlogged_attempt`: fetches went out with no receipt held, the
consumer's chain intact AND incomplete. A surplus is the worse half — receipts
for fetches the server never served: the fabricated side, surfaced with the
same finding (`receipt_gap`), the note naming the direction. Zero-sum coverage
is the only clean answer.

**Amendment (Oct 13, the keyholder — "per PROCESS" as a runtime property)**:
this ADR's own audit found the gap (howcani, 3hif9): the code read a PEM file
(`db_path + ".key"`, chmod 600) or `NOIREBOX_KEY_PEM` — nothing bound the key
to a process, uid or role. "Keys are per PROCESS" was aspirational where the
code reads a file: *what stands on it is a premise, not a cipher*. The
keyholder closes the custody half structurally: the key loads ONCE into a
dedicated daemon (`noirebox keyholder`) and never leaves it — signers get a
unix socket (`noirebox-keyholder/0.1`) that answers `sign` and `describe`,
nothing else, and `SocketSigner` duck-types `.sign()` + `.public_hex()` so
every existing writer path (store, seal_writer, journal_report) signs
THROUGH the daemon unchanged, signatures byte-identical (Ed25519 is
deterministic). `--allow-uid` gates the peer by uid (SO_PEERCRED) and FAILS
CLOSED where the peer is not checkable — asking for a check and not getting
one is a refusal, never an assumption. The honest re-pricing of the floor:
reachability of ONE socket path replaces readability of the key bytes — a
deployment that wants "the agent cannot sign" mounts everything EXCEPT the
socket, and after start the PEM can be removed from the agent-reachable
volume entirely (the daemon holds the material in memory only). What the
keyholder does NOT do: it does not bind the key to a hardware root (HSM/PKCS#11
rides the same signer interface, later), and where agent and operator share a
uid AND a socket, the gate is the filesystem's — stated, not hidden. The pin
(v0.2.7) named the authority; the keyholder moves the material; the pair
makes "the one writer the agent cannot be" a deployment ASSERTION instead of
a deployment hope.

**Amendment (Oct 13, HSM — the same interface, hardware custody)**:
`P11Signer` (`noirebox/hsm.py`, the `hsm` extra) duck-types
`.sign()` + `.public_hex()` and puts the material in a PKCS#11 token — the
keyholder daemon becomes the hardware bridge
(`noirebox keyholder --pkcs11-module ... --ensure-key`), the agent keeps
speaking the socket. Continuity is the point: `ensure_hsm_key(pem=...)`
imports the EXISTING journal key — the public hex does not move, no
signature breaks, no rotation. What this rung does NOT claim: the HSM does
not change WHO can ask for a signature — that stays the socket premise —
it changes what a compromise COSTS. A PEM read once is forgery forever,
offline; a non-extractable key must be abused LIVE — detectable, revocable,
rotatable. Blast radius: from "key stolen" to "live abuse only". And the
honesty about the CI token: SoftHSM2 is an HSM-shaped FILE — it proves the
INTERFACE (determinism, continuity, drop-in; the test asserts signatures
byte-identical to the PEM key's own), never the non-extractability. PKCS#11
itself keeps the pattern honest one layer down: `CKA_NEVER_EXTRACTABLE` is
a LABEL — an imported key reports False, the token telling the truth that
the seed did exist outside once; only keys BORN on real silicon make the
label true. The attribute is a claim; the hardware is the predicate.

---

**Amendment (Oct 13, v0.2.8 — 3hkpp: the custody mode is disclosed)**:
the probe confirmed the drop-in holds byte-identically from another
process, then measured its consequence: the journal CANNOT tell custody
modes apart — by design. So the mode becomes a disclosure field:
`registry_disclosure(signer_mode=..., uid_gate=...)` (schema
`registry-disclosure/0.2`, fields null when the caller states nothing —
null visibly says nothing, it never implies the peer was checked), and
`SocketSigner.describe()` reports `peer_uid_checked` so the caller
derives the gate status from the daemon instead of asserting it. The
platform boundary is now in the ladder: on darwin there is no peer check
at all — the gate is unusable rather than unsafe (it refuses,
fail-closed) and the 0600 separates USERS, not processes; rung 4's
residue is rung 3's sentence with one noun changed. And the token PIN
left argv: `NOIREBOX_HSM_PIN` carries it (an argv PIN sits in the process
table, readable via `ps`; the daemon warns when it sees one).

---

**Amendment (Oct 14, v0.2.9 — 3hl4l: the gate's configuration is a fact
the daemon owns)**: the probe's acceptance run confirmed v0.2.8, then
read its own seam back: `peer_uid_checked` answered "could the platform
tell" — an UNGATED daemon on a checkable platform reported True, and the
recommended derivation printed 'checked' for a daemon that checks
nothing. A field true about one question, read as true about another —
the shape this week has been closing. The daemon now reports
`uid_gate_configured` beside the check flag (protocol
`noirebox-keyholder/0.2`), and `SocketSigner.uid_gate()` derives the
tri-state the disclosure wants: "off" (nobody's uid consulted), 
"enforced" (a gate configured and this peer passed it), 
"unavailable(<platform>)" (configured, uncheckable, refused fail-closed).
A refused peer never receives a describe at all — the refusal IS the
enforcement. And the probe's narrowing is a premise now: the env var is
inherited, so the PIN left argv but not the daemon's address space —
possession of the address space is a host boundary (premise 6), not an
application property.

---

**Amendment (Oct 14, v0.3.0 — 3hnok: the derivation read prose)**: the
re-probe of v0.2.9 accepted everything, then read the derivation itself:
`uid_gate()` string-matched "not the allowed operator" — **the strongest
token in the vocabulary had the interface's weakest derivation** — any
error containing the sentence laundered into `enforced`, the platform in
`unavailable(...)` was the CALLER's when the fact belongs to the
daemon's host, and an unclassifiable refusal raised, inviting the caller
to write "not stated" over "could not be derived" — the ladder's own
rule, broken where it must hold most. The seventh premise is on the
ladder in the probe's wording: **a derived value's meaning is coupled to
the wording of the message that carries it.** The code carries the
enforcement: every daemon refusal gains a machine-readable
`error_code` beside the prose (the not-checkable refusal carrying the
DAEMON's platform), `uid_gate()` derives from the code — never the
sentence — and the fourth token `undecidable(<reason>)` becomes the
resting state for everything unclassifiable: an old daemon's prose reads
`undecidable(unclassifiable-refusal)`, null goes back to meaning only
"not stated". The wire handshake stays `noirebox-keyholder/0.2` ON
PURPOSE: the fields are additive and the token is the mixed-version
answer — an old peer degrades to a named state instead of breaking
loudly. The stub battery ships with it: a scripted transport answering
each refusal string and each code, asserting the derived value — the
malformed-self-report cells are reachable from the suite. (The battery's
first socket-level version also caught a real daemon bug: the accept
loop died on BSD/macOS ECONNABORTED when a peer hung up pre-accept — the
listener survives its peers now.)

---

## ADR 021 — Flow independence is a testable invariant, not a claim

**Status**: accepted — shared-dependency attack (glenallen, picked up by james as "the attack that would actually hurt"); clock/key independence (indiainfranotes); sealer identity (naveen thread, 27/09 + james: "a name, not a role").

**Context**: two flows — the audit flow and the truth flow. If ONE compromised service, credential or store touches both, independence is theater: the attacker rewrites the truth and the evidence in the same stroke.

**Decision**:
1. **The shared-dependency test** is the first invariant of the independence layer: enumerate what each flow touches (store, key, clock, network, process) and assert the intersection is empty. A bench ships the assertion — "can one compromise reach both?" becomes a CI answer, not a paragraph.
2. **Clock and key independence**: the reconciliation flow is independent only if its clock and its key are. Each flow's chain head is anchored to a third party on its own cadence — backdating one flow shows against the other's anchors.
3. **Sealer identity — "a name, not a role"**: one instance = one keypair does NOT mean independent writers. Keys are per PROCESS, and the payload names the sealer in a way that resolves to a person ("who authorized this" has an answer). A role label ("ci-bot") is a costume; a name is an accountability path.
4. **The invariant document lives before the break**: the taxonomy + test land in this repo ahead of the review that will hunt them.

**Consequences**: the independence bench is the prepared ground for external review; ADR 019's two-key pairing is the first instance of the per-process key rule; multi-flow deployments get a vocabulary ("flow", "head", "anchor cadence") that makes independence assertions writable.

---

**Amendment (Oct 12, v0.2.6 — the §15 structural design, howcani's registry)**:
the known-writer set becomes a SEALED REGISTRY. The v0.2.5 key-material
verdict still could not see that two DISTINCT agent-controlled keys share
one owner — key material alone never will. The closure is structural: the
domain of every writer is declared at REGISTRATION and sealed by the
verifier (`seal_writer` → `writer/0.1` — public_hex → domain, attested
before any run the writer could influence), and `reconcile_receipts` in
registry mode resolves keys and domains from the sealed registry — **the
caller supplies nothing**. A witness is a registered writer whose domain
differs from the receipt's own; an unregistered transport writer witnesses
nothing; a receipt whose own writer is unregistered is
`independence_undecidable` — never clean. Pattern: `seal_requirement`,
extended to writers.

**Amendment (Oct 13, v0.2.7 — the §17 pin, howcani's write race)**:
the registry's own authority was the residue. In v0.2.6 the registry is
store-derived: "operator" is a word with no referent in the predicate, the
agent can seal its own `writer` entry, and `setdefault` made FIRST-WRITE-WINS
the registrar — howcani's fixture (receipt by k1, attempt by k2, both keys
agent-held; the agent self-registers k2 as `hook-transport` before the
operator's honest attestation lands) read clean, and the operator's entry
sat in the store inert. The closure is the pin, ADR 008's TSA-root pattern
applied one layer down: **the registrar's key is supplied to the verifier
OUT-OF-BAND** (`registrar_public_hex` — never read from the artifact under
audit). At assembly, only registrar-SEALED entries are admitted — a write
the registrar did not seal cannot vote in either order; a key the registrar
attested under TWO domains is the operator contradicting itself —
`registry_duplicate_undecidable`, emitted AT ASSEMBLY, never resolved
first-write-wins. The verdict reads the registry the operator sealed, not
the registry that arrived first. The howcani prediction is a test and
holds: at the pinned head the fixture reads `unverified_label`. And the
descent's floor gets its disclosure row (`registry_disclosure`, sealed into
the report): the verdict states the registrant and the grade — at the last
layer the artifact stops being evidence about the agent and becomes a
statement of trust in the operator, grade 3, "anchored self", VOLUNTARY
unless a regime imposes it (ADR 022). Disclosure is not violation: it never
touches `clean_pass`, it only stops a clean verdict from pretending to rest
on more than the operator's own custody.

## ADR 022 — Custody vs anchoring: map the trust boundary, disclose the proof grade

**Status**: accepted — the best framing received this week (mickyarun, PSD2); ops cadence from the reid thread (30/09) + mickyarun.

**Context**: anchoring (TSA/OTS) answers WHEN and is structurally indifferent to WHAT. Custody answers WHAT, because the counterparty who wrote their own record has a reason to disagree with yours. Conflating them oversells anchoring — the bank does not care that your hash is in Bitcoin; the bank cares that YOUR record of the payment matches THEIRS.

**Decision**:
1. **Every consequential action maps to its trust boundary**: if a counterparty exists (payment, message, contract, order), custody beats anchoring — require THEIR flow and reconcile the two (ADR 019 pairing). If the action is first-party end-to-end, anchoring is the grade of proof — and you disclose which: "operator-held, anchored, no second party."
2. **Disclose the grade** in payloads and docs: the receipt says what its proof is worth. The AI Act's art. 12 asks for the weakest grade explicitly — a tool that states its grade is auditable by its own documentation.
3. **Ops cadence defaults (the anchor window)**: "the interesting events live between the last anchor and the incident." Defaults: anchor on a WALL-CLOCK timer (a killed session's dead time counts in minutes, not in turn boundaries), and anchor BEFORE consequential actions (a destructive gesture starts on an anchored head). Shipped as the server's optional auto-anchor timer.
4. **Reconciliation names its cost** (mickyarun): multi-flow custody has a bill — another store, another key, another cadence, reconciliation latency. An honest cost note accompanies the benefit pitch; a tool that only sells the benefit is selling.

**Consequences**: the trust-boundary mapping becomes part of deployment docs; the auto-anchor timer ships (wall-clock cadence, before-consequence guidance documented); the cost note is a standing section in the reconciliation docs.

**Amendment (Oct 14, §20 — the custody grade, operationalized)**: the
rudratosh/fluffydesk thread extended the taxonomy and this amendment
ships it. fluffydesk's formula: **a witness is worth min(authoring,
retention)** — receipts authored grade-1 but retained in
operator-controlled storage sit at grade 3, and retention is the only
grade that is **wrong by drift**, so it wants monitoring, not just an
audit. Three closures: (1) retention changes are SEALED EVENTS
(`seal_retention` → `retention/0.1`, action bounded to
prune/migrate/policy-change/restore — the v0.3.0 enum lesson, one layer
over): a prune or a migration with no sealed trace was an invisible
grade change, the dashboard staying green while the custody moved;
(2) `check_custody_drift` monitors the tail — the events beyond the
newest anchor are the unanchored window, and exceeding the bound (by
count or by wall-clock cadence) is `custody_drift`, a named state,
never silence; (3) `custody_grade` discloses the journal's grade as the
TAIL's grade — 2 ("disinterested custodian") while the anchor witnesses
the head within cadence, 3 the moment it drifts — sealed into the
report via `journal_report(custody_disclosure=...)`, never touching
`clean_pass`. The head anchor itself (TSA/counterparty — a point the
operator key cannot rewrite) is ADR 006/008's machinery, now priced as
the retention witness.

**Amendment (Oct 9, issue #47 — mickyarun, the top rung is regulatory)**:
**"obligation, not immunity."** Every proof grade documents itself WITH the
obligation it serves — the evidence exists to prove an obligation was met,
never to shield the operator from it. The art. 12 log is the standing example:
the record-keeping obligation is the point, and the log is the evidence OF the
obligation, not immunity from it. A grade disclosed without its obligation
answers "how good is the proof" while hiding "proof of WHAT is owed" — the
disclosure rule in §2 gains its obligation line.

**Amendment (Oct 9, issue #51 — mickyarun, the three-grade taxonomy, made
explicit)**: the scale gets its names, and the audit-pack labels every event
class with it — **grade 1, adverse counterparty** (custody: the other side's
own record, reconciled against yours); **grade 2, disinterested custodian**
(a third party with no stake attests WHEN — RFC 3161 / OTS); **grade 3,
anchored self** (operator-held, hash-chained, anchored). Counterparty-shaped
events grade 1, third-party witnesses grade 2, everything journal-local
grade 3 — the honest default, because a fact the operator holds can never
honestly claim a stronger grade than its own custody. Each label states
whose obligation backs it: "no one can impose a cost here" means the
evidence is voluntary. The authority-facing disclosure cannot hide a
grade-2 custodian behind a grade-1 counterparty sentence.

---

## ADR 023 — Seal the belief, not only the action: the resolved view before the consequence

**Status**: accepted — james ("real addition", credited by him); implement it before he does it on his side.

**Context**: a journal full of actions answers WHAT was done. The harder question is what the agent BELIEVED when it did it — which environment did it see, which identity did it assume, which target did it resolve this name to. A wrong action taken on a false belief is indistinguishable from a malicious one unless the belief itself is on the record.

**Decision**:
1. **`decision_belief` convention** (free-form payload, sealed BEFORE the consequential action): `{resolved_target, environment, identity_assumed, inputs_seen (digests), confidence?, source: {tool, version}}`. The resolved view at decision time — the WHY, falsifiable after the fact.
2. **The belief is a self-report, and the schema says so**: a field `belief_grade: "self-report"` travels with it. It is not evidence of the world — it is evidence of what the agent claimed to see, which is exactly what an investigator replays the environment against.
3. **Ordering is the proof**: belief sealed before the action means the action could not have been retro-fitted to a rewritten belief — the sequence in the chain forbids it (an attempt-style convention, ADR 020's shape).

**Consequences**: incident forensics gain the why ("it resolved api.example.net to this IP because..."); ADR 021's identity question gains its input ("which identity did it assume"); the self-report grade keeps the honesty line — a tool that labels its evidence grades is the opposite of one that oversells them.

---

**Amendment (Oct 8, issue #39 — tom_jones)**: witness ≠ author is ENFORCED at seal time (`build_receipt` refuses a witness resolving to the author) and available at serve time (`ensure_witness_distinct` — skip the slot and escalate). Tom's live failover found the witness running the drafter's own model twice: the failure mode is real, silent, and now structurally refused.

## ADR 024 — Cross-chain reconciliation: consumption edges, partial order, fan-in

**Status**: accepted — full ADR by iteration on the sinarezaei threads, Oct 7–8. Lineage to credit: **sinarezaei** (consumption edges, partial order, the orphan case, fan-in propagation), **james/arhancanli** (the never-written entry — this ADR is its ancestor), **david_ilands** (silence as a first-class fact). Final formulation validated by slabb in-thread.

**Context**: agents consume each other's outputs. Today those dependencies live in nobody's journal: agent A acts on agent B's report, and when B's output is later superseded or revealed orphaned, A's decision — and every downstream decision built on A's — sits in an intact chain with no thread to pull. A fleet of journals is a graph with no edges. This ADR adds the edges.

**Decision**:
1. **Consumption edges are sealable events**: when one agent consumes another's output, the consumption itself is an event carrying the producer's **chain head as observed** (`consumed_head`) plus the correlation id. The dependency enters BOTH journals — the producer's (what was consumed) and the consumer's (what was being consumed).
2. **The contract is a partial order, not a global timeline**: the invariant is **admissibility of each edge** (an admissible predecessor → consumer relation), not "what happened first everywhere." A fleet that had to agree on one notion of time would be re-deriving consensus just to keep an audit trail — rejected by design.
3. **Edge invariants are DERIVED from anchors, never asserted by the agent**:
   - `consumed_head` is an **ancestor** of the producer's currently anchored head;
   - the consumer's **anchor interval follows** the consumed event;
   - a **temporal inversion** (fraud@41 consumed by underwriting@39) is a cross-chain finding — the same species as `orphan_outcome`, across chains.
4. **No self-declared epoch field** (rejected alternative, recorded): a self-stamped watermark is a self-report — the exact thing ADR 023 grades as such; an allocator-issued one re-opens the per-call latency tax (reid's objection). Temporal position is a **relation between two sealed chains**, derived from anchors — not a field anyone writes.
5. **Fan-in: forward finding propagation** — when a consumed head turns out superseded or orphaned, the finding propagates along the dependency graph to every downstream journal that recorded an edge to the dead head. The blast radius is a **precise path set**, not "everything downstream, maybe." The consumer's chain staying intact is the proof of belief; the producer's supersede event is the proof of staleness; the reconciliation layer correlates the two.
6. **Silence is the starting fact** (david_ilands): a flow that never recorded the edge is not outside the blast radius — it is the first thing the propagation asks.

**Consequences**: `reconcile` gains cross-chain findings (`stale_consumed_head`, `temporal_inversion`, `unrecorded_edge` — tracked in the follow-up issue); a consumer that journaled its edge can PROVE it believed the right thing when it acted; a producer that supersedes owes the graph a supersede event; and the fleet layer (ADR 017/021) gains its actual topology — journals are nodes, consumption edges are the graph, anchors are the clock. The ecosystem is already attacking this layer ("see you in the issue tracker"); this ADR must exist before they arrive.

**Amendment (Oct 9, issue #41 — the findings ship)**: `crosschain.py`
implements the vocabulary and the invariants. Consumption edges seal in BOTH
journals (`consumption_edge` — consumer half `{edge_id, producer,
consumed_head}`, producer half `{edge_id, consumer}`; a half missing on
either side is `unrecorded_edge` — silence is the starting fact). A
`supersede` event (`superseded_head` + reason) kills a head and drives the
fan-in: a journal tainted from its stale edge taints every later head of its
own that gets consumed — the blast radius travels as a precise path set in
the finding's note. `stale_consumed_head` fires when the consumed head is
absent from the producer's chain (rewritten away, or never was — the anchors
decide WHO is lying, the verifier's job) or superseded; a head merely not
yet covered by an anchor is UNDERIVABLE, not stale (the queue is the only
open window). `temporal_inversion` fires when the consumed event's seal time
postdates the anchor covering the consumer's edge — the anchor event's seal
time is journal-local (the honest weakness stated; token-level genTime
checks belong to the verifier), and with no anchor covering the edge
nothing is asserted. The report seals always, clean pass included
(`crosschain_reconciliation`), and the CLI gains `noirebox crosschain
--journal name=path …`.

---

## ADR 025 — The toolset baseline: tool descriptions are instructions, pin them

**Status**: accepted — bloqarl's Docker-thread observation (issue #50): tool
descriptions are instructions the MODEL reads, and they ride outside the
image pin — runtime-produced at registration time; for remote MCP servers,
nothing is pinned at all. A changed description is a changed instruction
surface, and nothing in the deployment noticed.

**Decision**:
1. **Capture the toolset at registration** — the `listTools` response's
   tools array, hashed with the journal's own canonical serializer and
   sealed as the reviewed baseline (`toolset-baseline/0.1`): the whole-set
   hash plus a per-tool digest table, so the diff names the tool, not just
   "something changed."
2. **Two-writer by construction**: the baseline is sealed by whoever
   REVIEWED it (`reviewed_by` — a name, not a role, ADR 021), never by the
   process that connects. The connecting process holding the key that seals
   its own instruction surface is the shared-dependency test (ADR 021) one
   layer up.
3. **Every session start diffs the served definitions against the baseline**:
   a changed description or input schema, an added tool, a removed tool —
   each a `toolset_changed` finding whose note names the tool and the
   direction. "The model reads different instructions than the ones that
   were reviewed" is the whole finding.
4. **Checking against no baseline is refused**, never silently clean: no
   baseline for the server is a loud error — the absence of a lockfile is
   not compliance.

**Consequences**: `noirebox toolset-pin` ships (seal, and `--check` as the
session-start gate, `--fail-on-drift` for CI/cron); `demo_mcp_toolset.py`
shows the silent rewrite caught. The model's instruction surface now has
the same tamper-evidence as every other sealed surface.

## ADR 026 — Admission receipts: seal the basis, not only the act

**Status**: accepted — You-An Lin, *"Capability Is Not Authority:
Semantic Ownership Architecture for Persistent Conversational Agents"*
([DOI 10.5281/zenodo.23315265](https://doi.org/10.5281/zenodo.23315265),
2026-10-12, CC BY 4.0), the fourth independent arrival in this corridor —
after the SCAR catalog (Randal Schwartz), the Negative Witness (Mike
Mol's mtools W231), and this journal — and the first to arrive at the
half the ladder names only by implication: not *who wrote this* but *who
was entitled to originate it*. Lin's Paper I ([DOI
10.5281/zenodo.23171351](https://doi.org/10.5281/zenodo.23171351))
builds the persistent Resident as first-class runtime state and leaves
"control and ownership questions" out of scope; Paper II is that scope,
arriving four days later.

**The finding that matters here** (Paper II, §6.3): a live agent
correctly attributed foreign history to another Resident *while using
it* — the foreign record had already shaped its deliberation without an
admission basis. Attribution correct, admission invalid, every
output-level metric green. That is the check-vs-proof seam one floor up
from `verdict_predates_terminal` and the custody grade: the OUTPUT is
not the unit of audit. Lin's transition chain — presence ≠ availability
≠ admission ≠ ownership ≠ authority ≠ execution ≠ realization — is the
ordering-vs-authenticity wedge restated at the semantic layer: a
promotion without an independent basis is exactly the reordering a hash
chain catches, except nothing yet catches it, because the runtime state
that would attest admission (his §5.6, `resident_admission:
"non_admitted"`) is itself an unwitnessed, silently-promotable resource.
His failure family applies to the witness. The two stacks are halves:
the paper defines the statuses and the bases, and has no custody — who
saw that the admission check ran, with which scope, when. That is the
journal's whole job.

**Decision** — promotions become first-class sealed events:

1. **`admission/0.1`** — a receipt for the promotion itself:
   `{actor, source (origin + surface), transition, basis, decision,
   participation_ownership, scope}`. The transition vocabulary is Lin's
   four invalid promotions, named: `visibility→admission`,
   `capability→move`, `relevance→payload`, `style→stance`. The basis is
   the independent one his laws require — a user-instruction ref, a
   prior receipt `seq`, an explicit scope grant — never the resource's
   own presence, relevance, plausibility, or usefulness (laws 1–8 are
   the negative space this field refuses to encode as a basis).
2. **`decision` fails closed, house vocabulary**: `admitted` | `denied`
   | `admission_undecidable` — undecidable is never clean; a check that
   did not run reads `admission_check_not_run` (the
   `scope_check_not_run` lineage, ADR 019).
3. **`participation_ownership` ∈ {same, foreign, shared}** — the
   false-first-person-ownership guard as a field discipline, not a
   prompt: a receipt proves an earlier actor's decision; it never makes
   it the citing actor's autobiography. Downstream use of
   foreign-sourced material requires the citing actor's OWN admission
   receipt.
4. **`check_admission_basis` in the reconciler**: payload content whose
   source is foreign and whose admission receipt is missing reads
   `admission_gap` — the `receipt_gap` finding, one transition deeper.
5. **The SCAR-BENCH admission axis**: Lin's §6.3 names the metric —
   "a stronger benchmark varies admission rights and actor identity
   while keeping the substantive task fixed, then observes whether
   foreign information changes attention, stance, initiative, or
   payload." Graded on receipts of the PATH (visibility → admission →
   move → payload), never on the answer text. His own single-turn null
   result (§6.1–6.2, ceiling parity between the prose contract and the
   generic baseline) is the Level-0 lesson restated by a fourth team:
   a contract written in prose measures nothing at ceiling — which is
   why the laws land here as schema, not as rubric.

**Consequences**: the four invalid promotions become machine-checkable
invariants against the sealed registry (Level 2 — the reconciler
surfaces, structurally); the ladder gains a second descent — after
"who wrote this" comes "on what basis was this admitted" — under the
same honesty rules (undecidable named, skipped checks reported,
disclosure ≠ violation). This ADR ships the contract; the schema, the
check, and the fixtures land in 0.22.0. The paper asked for an
admission-sensitive benchmark; it should find one already running.

**Amended (ADR 032 train, October 2026)**: `admission/0.1` gains an
optional `reach` field — T5-011 of agentic-ai-test-checklist-110: a
tenant-scoped export check should pass on evidence, not on a boolean.
`reach` names the boundary the admission check enforced (e.g.
`tenant:acme`); absent means journal-wide, exactly what every receipt
sealed before the field already was, and a blank is refused at seal
time. Additive only: no existing receipt changes meaning.

## ADR 027 — Post-quantum evidence: hybrid signing behind the signer interface

**Status**: accepted (direction) — implementation gated behind export
`format_version 2`. References: NIST FIPS 204 (ML-DSA), FIPS 205
(SLH-DSA), SP 800-208 (LMS/XMSS); ANSSI's post-quantum migration
roadmap (hybrid algorithms on the horizon of 2030 for sensitive
systems).

**The asymmetry that forces this.** The journal's promise is
longevity: the archiving tiers sell ten-year probative value, an
anchor sealed today may be re-verified in 2040. On that horizon the
two primitives diverge. SHA-256 survives a quantum adversary with its
margin halved (Grover: 2²⁵⁶ → 2¹²⁸ preimage — expensive, not broken);
Ed25519 does not survive at all (Shor). Every event signature in this
journal is written in an algorithm with an expiry date, while the
chain that binds them isn't. A proof tool that states its perimeter
honestly cannot leave that unstated.

**What is already post-quantum here** — worth writing down before
anything is added: the append-only chain itself (SHA-256 only), and
the OpenTimestamps/Bitcoin witness (a receipt forgeable only by
redoing the network's proof of work, verifiable in ~30 µs of
SHA-256). The exceptions are the event signatures (Ed25519) and the
RFC 3161 tokens (RSA/ECDSA — the *legal* layer of anchoring, a
convenience witness next to Bitcoin, and the reason this ADR exists
rather than a victory lap).

**Non-goals, stated so they can be refused in public**: the one-time
pad (a confidentiality primitive; the journal adds no confidentiality
to prove) and QKD (a point-to-point physical link between two optics
terminals; a journal that anchors over HTTPS to witnesses of its
choosing is not that). If "quantum-proof" ever appears in a marketing
claim beside either word, this paragraph is the retraction.

**Decision** — a fourth signer, behind the seam that already exists:

1. **`HybridPQSigner`** implements the exact `.sign()` / `.public_hex()`
   interface of `KeyPair` (`chain.py`), `SocketSigner` (`keyholder.py`)
   and `P11Signer` (`hsm.py`). No new trust path: custody already
   solved down to hardware stays custody; the algorithm is a parameter,
   not an architecture.
2. **Hybrid by construction**: sealed events carry both signatures —
   Ed25519 (today's verified interop) + ML-DSA-65 (FIPS 204). Hybrid
   because PQ v1 cryptography is young; if either half falls, the other
   still decides, and the verifier already counts both. SLH-DSA (FIPS
   205, hash-based, stateless) is the sanctioned alternative where
   signature size beats code size.
3. **`format_version 2`**: exports carry `signatures: [{alg, sig}]`,
   with the Ed25519 half mirrored in the legacy flat fields — the
   ADR 008 precedent: old verifiers keep verifying the classical half;
   new verifiers demand both.
4. **Verifier dual-path**: `verifier.py` accepts v1 (Ed25519-only) and
   v2 (hybrid); a v2 export missing either half fails hard; the
   audit-pack gains a PQ disclosure line so the grade system (ADR 022)
   can name the signature era an export belongs to.
5. **The anchor's own signature is in scope, later**: stateful
   hash-based LMS (SP 800-208) fits an anchor cadence — a handful of
   signatures per day makes the state tractable — and relies on
   nothing but the hash function the journal already trusts. Sequenced
   after the event-signing path; not a v2 blocker.

**Honest residue**: hybrid signing does not make today's exports
retroactively quantum-proof — it makes the *verifiable path forward*
survive the transition, which is what a ten-year archive actually
requires. Pre-v2 exports migrate by re-anchoring, never by rewriting:
the chain doesn't change; the anchors get newer, stronger witnesses.
And the packaged form of this work — managed hybrid migration, PQ
disclosure in audit-packs, the long-retention archiving tier — is
service layer. The signer lands in the MIT core like the other three.

## ADR 028 — Decision receipts: the System One layer under seal

**Status**: accepted — vLLM v0.32.0 (2026-10-18, PR
[#59299](https://github.com/vllm-project/vllm/pull/59299)) baked
decision routing into the inference engine: `POST /v1/systemone`
answers `choice` / `noul` / `score` questions over a state and returns
a probability for EVERY allowed answer, computed from the labels'
logprobs in one read. The wire format is TypeSafe's Jev ("System One")
and it is already a layer, not a proposal: Ollama v0.35 serves it,
Cloudflare ships Clef models for it, LiteLLM translates it, OpenAI
serves the same seam as `/v1/decisions`, Databricks and Microsoft
Foundry list decision models (reidmarlow, "Why vLLM 0.32 Baked
Decision Routing Into the Engine"). Routing decisions are becoming
engine primitives the way tool calls became API primitives — and this
journal exists because primitives do not carry their own evidence.

**The seam.** A decision model is a BETTER evidence substrate than a
parsed prose label: the answer is bounded, the distribution over the
allowed answers comes back with it, and vLLM even reports per-question
diagnostics — `label_mass` (where the answer's mass actually went) and
`argmax_is_label` (whether the reported answer was the argmax over the
label tokens at all). It is a WORSE audit surface: the call happens
inside the engine, the harness sees an enum, and nothing outside the
engine remembers how the answer was reached. "The engine saw
everything, the audit log sees an enum" is the ordering-vs-authenticity
wedge one layer below the check-report gap receipt/0.2.x closed. The
engine says the rest plainly in its own docs: probabilities can VARY
between identical requests (batching, prefix-cache). Replay is not
proof here. The seal is.

**Decision** — decisions become first-class sealed events:

1. **`decision/0.1`** (`noirebox/decision.py`): `{format (systemone |
   openai-decisions), model, run_id, judged_by: "llm", state_sha256,
   spec_hash, questions, answers, diagnostics?, requirement_ref?}`.
   The state travels as a DIGEST, never as data (the `use_event`
   rule). The answers carry the distribution the engine returned — a
   bare label is what an attacker edits; a distribution is what they
   must explain. The diagnostics are sealed VERBATIM and never
   interpreted at build: the engine's confession is evidence, not a
   verdict.
2. **The SCAR-45 door is welded at birth.** `spec_hash` is REQUIRED
   with no exception path — a decision model's question set IS its
   predicate, and receipt/0.2.x spent v0.2.2 and v0.2.3 learning what
   an LLM-judged verdict without its committed spec seals. The
   embedded questions must hash back to `spec_hash`: the receipt
   cannot claim a menu it does not carry.
3. **`seal_decision_spec`** commits the canonical question set as a
   spec/0.1 event, canary planted — the SCAR-PROC-114 machinery reused
   unchanged. A caller that hallucinated the menu from priors, or was
   handed a different one by an injected state, trips the canary
   exactly like the judge that never read its bytecode.
4. **`reconcile_decision`** — five findings, each the schema-level
   version of an attack that used to need a reviewer:
   `decision_spec_not_canonical`; `questions_not_canonical` (the
   builder refuses this; a hand-forged event that skips the builder is
   exactly the drift the re-check exists for); `answer_outside_spec`
   (the chosen option is not in the sealed menu);
   `decision_contradiction`; `label_not_argmax` (the engine's own
   doubt, surfaced so a confession cannot sit in an archive nobody
   reads).
5. **The contradiction check judges the CHOICE, never the
   distribution.** Two decisions on the same (state, spec) with
   different chosen answers is the quiet flip, surfaced as a registry
   join. Probabilities jitter between honest retries (batching,
   prefix-cache — the engine documents it); a flip is not jitter.
   Judging distributions would make the reconciler lie on the honest
   path.
6. **SCAR-DM-1** lands in the replay suite: the routing flip
   (block→safe under injection), the swapped menu caught both ways
   (builder bypass and the unsealed spec), the answer outside the
   menu, the clean twin. The measured open-weights leg — a real
   `/v1/systemone` endpoint, the SCAR-BENCH grid — is the frontier
   leg: SCAR-BENCH §7 holds the landing pad, and no numbers exist
   until a run happened (the honesty rules are not negotiable).
7. **Admission rides the same train** (ADR 026's public promise,
   kept): `admission/0.1` + `check_admission_basis` — Lin's four
   invalid promotions named, the never-bases refused at seal time,
   the decision failing closed, `admission_gap` firing when foreign
   content is consumed with no earlier admitted basis.

**Non-goals, stated so they can be refused in public**: noirebox does
NOT proxy decision traffic — no `/v1/systemone` passthrough; we are
the evidence layer, not the engine, and a proxy would put the witness
inside the thing it witnesses. It does NOT stop a decision model being
fooled — injection can still move probability mass; the receipt's job
is to make that visible (the distribution and label_mass in the
journal, the flip as a finding), not to pretend it cannot happen. And
it does NOT judge distributions: calibration is the engine's problem;
ordering and authenticity are ours.

**Consequences**: `noirebox/decision.py`, `seal_decision_spec`,
`reconcile_decision`, `seal_admission`, `check_admission_basis`, and
the SCAR-DM-1 / SCAR-ADM-1 fixtures ship; 29 tests join the suite
(428 collected). The AI Act tie is direct: a routing decision that
gates a human review is an automated decision with logging obligations
(art. 12) and oversight hooks (art. 14) — `requirement_ref` names
which. The HTTP seal endpoint and the live-endpoint bench harness land
with the first integration that needs them.

---

## ADR 029 — Chunking receipts: the cut is a decision, the corpus is a chain

**Status**: accepted (direction) — lineage: ByteByteGo EP#229, *"8
Chunking Strategies for RAG"*, and the thread's provenance comment:
with agentic chunking, the method choice is invisible at retrieval
time — a paragraph-cut contract clause and a row-cut table look
identical in the index — so each chunk should carry its label and its
splitter. That comment is the check-report gap one artifact lower, and
it lands here because no one else is holding the seam. Implementation
(`noirebox/chunking.py`, the manifest seal, the drift check, SCAR-CK-1)
lands with the first integration that needs it — no schema ships
without its tests.

**The seam.** Retrieval-augmented systems cut a corpus into chunks
before anything else happens, and from that moment the cut decides
what the model CAN read: retrieval never sees a sentence the cut
destroyed, never keeps a clause with its exception if the splitter put
them in different chunks. Three facts about the cut are unwitnessed
end to end. WHAT each chunk contains — corpora mutate silently between
the evaluation run and the production run, and the index id does not
change. HOW each chunk was cut — strategy and parameters (size,
overlap, threshold, prompt) live only in the pipeline's memory, and
the EP#229 taxonomy names eight live strategies with more arriving.
WHO chose the strategy, when the chunker is agentic — a model makes
the choice, and the choice is a decision in exactly ADR 028's sense:
taken from a state, under a menu, load-bearing downstream. The
decision receipt sealed what was DECIDED; admission sealed the BASIS
of an act; nothing seals what was READ. Retrieval moves the read into
the decision loop — the corpus is the least witnessed artifact in the
agentic stack, and ordering-vs-authenticity does not even get to
start: a vector index attests neither.

**Decision** — the cut becomes a sealed event family:

1. **`chunking/0.1`**, the chunk receipt: `{doc_sha256, chunk_sha256,
   chunk_index, chunk_count, strategy, splitter, params?, corpus_id?,
   decided_by?, requirement_ref?}`. The document and the chunk travel
   as DIGESTS, never as text (the `use_event` rule — the chunk's
   custody stays with the pipeline's store; ADR 022 already mapped
   that boundary and this ADR does not move it). `strategy` is the
   named cut method — an open string, not an enum: strategies churn
   faster than schemas, and the receipt's job is to bind what RAN, not
   to adjudicate a taxonomy (the EP#229 eight — fixed, recursive,
   document-based, semantic, LLM-based, agentic, late, hierarchical —
   are values, not vocabulary). `splitter` is the implementation
   identity (library and version): the label-vs-implementation seam
   receipt/0.2.x closed for `judged_by`, closed again one artifact
   lower. `params` are the cut's knobs VERBATIM — a strategy without
   its parameters is a label, and labels are what attackers edit.
   `decided_by`, when present, names the decision receipt that sealed
   the strategy choice; absent means the pipeline chose
   deterministically — the receipt still seals the cut, it just has
   nobody to blame for it.
2. **The corpus manifest is a hash chain in cut order.** Chunk
   receipts append in document order; `corpus_sha256` is the chain
   head at seal time. A chunk edited, inserted, dropped, or reordered
   trips the chain — the one primitive this project is, applied to the
   artifact that currently has nothing. `check_corpus_drift` (the
   `check_custody_drift` pattern): manifest against live store, and
   every chunk whose digest no longer matches is a finding —
   eval-versus-prod corpus drift as a named result, not a vibe.
3. **Agentic chunking rides ADR 028 unchanged.** When a model picks
   the strategy for a document, that pick IS a decision receipt:
   `decision/0.1`, questions = the strategy menu (a `choice`
   question), `state_sha256` = the document digest, `spec_hash` welded
   with no exception path — the SCAR-45 door starts welded, house rule
   since ADR 028. The chunk receipt's `decided_by` names that decision
   receipt's identity — two receipts, one fact: what was chosen, and
   what the choice produced. No new trust primitive is invented here;
   reusing the 028 machinery unchanged is the point.
4. **The join is admission's, not a new schema.** When a grounded act
   consumes retrieved content, the chunk digest travels in the
   admission receipt's `basis` — an independent warrant by
   construction (it cites a sealed artifact, not the resource's own
   pull), and `admission_gap` ALREADY enforces that the basis precedes
   the use: a chunk receipt sealed after the act clears nothing, the
   same fail-closed direction as every basis check. A standalone
   `retrieval/0.1` (query, scores, ranking provenance) is the frontier
   leg, named and refused for now: witnessing the query moment needs a
   witness at query time — an integration seam, not a schema.
5. **SCAR-CK-1** joins the replay suite: the swapped chunk (same index
   id, different bytes), the strategy laundering (manifest says
   paragraph-cut, the bytes say row-cut), the post-eval mutation
   (corpus changed between the benchmark and the deployment, receipts
   not re-sealed), the unsplit corpus (nothing was ever sealed — the
   honest absence, surfaced like `admission_gap` rather than
   forgotten), and the clean twin. No numbers exist until a run
   happened; the honesty rules are not negotiable.
6. **SCAR-BENCH gets its reproducibility pin.** Semantic-beats-
   fixed-size is today an unbenchmarked claim — the EP#229 thread's
   open question (whether a good reranker recovers most of what clever
   boundaries buy) has no numbers attached, and none are citable
   without pinning the cut. Chunk receipts make a chunking grid
   replayable: same `doc_sha256` + same `strategy` + same `params` =
   byte-comparable chunks; a benchmark claim that pins its manifest is
   falsifiable, one that does not is a mood. Evidence grades apply to
   chunking claims like any other claim.
7. **The model-collapse lineage closes at the right grain.** ADR 011
   sealed content-provenance events for ingestion; this ADR gives that
   ingestion its unit — the chunk — and a confrontable identity at the
   grain that actually enters the context window.
   Agent-consumes-agent-generated-text is witnessed where it happens:
   not at the document (nobody reads whole documents) and not at the
   token (nobody attests tokens), at the chunk.

**Non-goals, stated so they can be refused in public**: noirebox does
NOT chunk, embed, retrieve, or rank — no vector store, no embedding
model, no reranker; we are the evidence layer, not the index, and (ADR
028's own refusal, restated) a witness inside the thing it witnesses
is no witness. We do not measure retrieval quality; we make the cut
confrontable so that OTHERS' quality claims become falsifiable. We do
not stop a bad cut from degrading an answer — a wrong strategy sealed
honestly is still a wrong strategy; the receipt's job is to make the
choice attributable, not to make it wise. And we do not seal chunk
text: digests bind identity, custody of the bytes stays with the store
(ADR 022's line, not a new one).

**Consequences**: `noirebox/chunking.py` (builder, validators, manifest
head), `seal_corpus_manifest`, `check_corpus_drift`, and the SCAR-CK-1
fixtures ship together, with tests, at the first integration; the
builder follows the house gate — a chunk receipt without `doc_sha256`,
without `strategy`, or with params that contradict the splitter's
identity does not seal. The AI Act tie is direct: for a high-risk
system, the retrieval corpus is data the system consumes at inference,
inside art. 10's data-governance reach (relevance, examination) and
art. 12's logging duty — a corpus manifest with document versions, cut
provenance, and per-chunk digests is the audit-pack page a regulator
actually asks for and a pipeline cannot produce after the fact. The
C2PA bridge inherits for free: a chunk receipt is a `noirebox.sealed`
assertion binding a content hash to a cut action — vocabulary C2PA 2.4
has no word for, the journal provides.

## ADR 030 — Marking receipts: the label can be stripped, the receipt can't

**Status**: accepted — implemented (`seal_marking`,
`check_marking_coverage`, `noirebox seal-marking`, with tests). Lineage:
AI Act art. 50(2) (Reg. (EU) 2024/1689) has applied since **2 August
2026** — providers of systems generating synthetic audio, image, video
or text must ensure the outputs are marked machine-readably and are
detectable as generated. Reg. (EU) 2026/1744 (the Digital Omnibus on
AI, in force 27 July 2026) left that date alone and added one narrow
transition, art. 111(4) via its art. 1(39)(b): providers whose systems
were already on the market before 2 August 2026 have until **2 December
2026** for 50(2) (recital 38: "a transitional period of four months").
That second date is now a marketing deadline, and a wave of marking
SDKs is arriving for it with a hosted "evidence log" as the proof leg
(October 2026). A hosted log is the custodian's own record, editable by
the custodian, with a vendor inserted between a provider and its own
evidence — the exact trust boundary `THREAT-MODEL.md` refuses. The gap
is not the mark. It is the receipt for the marking.

**The seam.** Art. 50(2) asks two things of an output, and both live
INSIDE the artifact: a machine-readable mark, and detectability.
Anything inside the artifact dies with the artifact. Re-encode the
image and the C2PA manifest is gone; crop the frame and the visible
watermark is gone; paste the paragraph into a mail and the text
watermark survives only as long as the tokens do. The provider's
obligation was met at generation time; the evidence that it was met
evaporates at the first hostile edit — and the edit is the whole
threat, because a stripped label is indistinguishable from a label that
never existed. Vendors answer with a log: "we recorded that we marked
it". A log is grade 3 at best (ADR 022: the operator's own record,
voluntary, editable); a hosted log is grade 3 with a second operator.
What survives the stripping is not the mark and not the log: it is a
receipt, bound to the output's digest, in a chain the operator cannot
reorder, anchored to a witness the operator does not control. **A label
can be stripped, a log can be edited, an anchored receipt can't.**

**Decision** — the marking becomes a sealed event:

1. **`marking/0.1`**: `{article: "50(2)", output_digest, modality,
   status, system_ref, methods?, manifest_digest?, exemption?,
   detector?}`. The output travels as its sha256 DIGEST, never as
   content (the `use_event` rule, ADR 010). The digest is the point:
   stripping the mark changes the bytes, not the receipt, and the
   receipt still names the bytes that carried the mark — the one fact
   that honestly survives. `modality` is closed to art. 50(2)'s four
   (`text | image | audio | video`); `system_ref` names which system
   generated the output, because 50(2) binds the PROVIDER of a system,
   not an operator in the abstract.
2. **`status` fails closed**: `marked | not_marked | exempt`. An output
   that left unmarked is sealed as exactly that — `not_marked` is a
   receipt, the gap on the record, the house rule since
   `admission_check_not_run`. `exempt` must name WHICH of art. 50(2)'s
   three carve-outs it claims — `assistive_editing`,
   `no_substantial_alteration`, `authorised_by_law` — as vocabulary; a
   bare "exempt" is the laundering word and is refused at the gate. The
   receipt records the claim; the regulator judges it.
3. **`methods` is a CLOSED set** — the opposite call from ADR 029's
   open `strategy`, for a reason: the reader of this field is an auditor
   asking "how do I re-detect this mark", and detection techniques
   enumerate where chunking strategies churn. `watermark | metadata |
   c2pa_manifest | fingerprint | visible_label`; a new KIND of mark is a
   schema bump, not a free string. `c2pa_manifest` binds
   `manifest_digest` (the sha256 of the manifest) and refuses to travel
   without it; a manifest digest with no manifest method is refused the
   other way — two fields, one fact, or neither. `detector`, when
   given, names how a third party re-detects the mark: "machine-readable
   AND detectable" is two halves, and a mark nobody can find satisfies
   neither.
4. **The join** — `check_marking_coverage`: every generation event the
   journal knows by `output_digest` must meet a receipt that says
   `marked` or `exempt` for that digest; anything else is
   `marking_gap`. A `not_marked` receipt IS the gap, surfaced at its
   own seq and never erased by a later `marked` receipt for the same
   digest (the unmarked release happened; a later mark does not
   un-happen it — admission's direction, applied here). One finding per
   digest. Order is NOT checked in 0.1, and the limit is named rather
   than hidden: delivery is not an event the journal sees yet, so a mark
   sealed after the generation event still covers it. The day a
   `delivery/0.x` lands, the rule becomes "receipt before delivery" —
   the basis-precedes-the-act shape, nothing new to invent.
5. **The C2PA bridge keeps its own namespace.** `c2pa_action("marking")`
   is `noirebox.marking`, not a borrowed verb: C2PA marks the FILE, the
   receipt seals that the marking HAPPENED — the act of complying is not
   a media edit, and we do not spend a verb the standard defines for
   something else. Two artifacts, one digest binding them: the manifest
   is the mark, the receipt is its proof, and the receipt outlives the
   manifest.
6. **The shell surface ships with the schema** — `noirebox
   seal-marking`, same function, same refusals verbatim (exit 2, no
   event lands). Lesson of #122, kept: a schema without its command is a
   schema the generic `noirebox seal` will happily write with none of
   the checks.
7. **Grade stated, not inflated.** A marking receipt is grade 3 (ADR
   022: anchored self) — the operator says it marked. The anchor lifts
   WHEN to grade 2; what would lift WHETHER is a counterparty's own
   detection record — a platform that re-detects the mark and seals the
   detection — reconciled against this receipt: the two-journal shape
   of ADR 020, named here, not built here.

**Non-goals, stated so they can be refused in public**: noirebox does
NOT mark — no watermarking, no C2PA signing, no detector ships here; we
are the evidence layer and (ADR 028's refusal, again) a witness inside
the thing it witnesses is no witness. We do not verify that a mark is
present in the bytes — we never hold the bytes, only the digest — and a
receipt that says `marked` is the operator's claim under seal, not our
inspection. We do not adjudicate the carve-outs. Art. 50(1), 50(3) and
50(4) — interaction disclosure, emotion/biometric disclosure, deepfake
and published-text disclosure — bind DEPLOYERS with a different
vocabulary and are a sibling `disclosure/0.x`, not folded in. And we do
not compute the 2 December question: whether a system was on the market
before 2 August 2026 is a fact about the system, not about an output.

**Consequences**: `seal_marking` + `check_marking_coverage` in
`noirebox/reconcile.py`, the `seal-marking` subcommand, `marking_gap` in
the named-states vocabulary, tests, this record. `COMPLIANCE-EU.md`'s
calendar is corrected in the same train — the Omnibus DID touch
transparency, in exactly one narrow way (art. 111(4)), and a compliance
dossier that says otherwise is a dossier with a date wrong. The French
developer guide to art. 50 on noirebox.eu carries the sentence this ADR
is named after; the sentence is the product.

## ADR 031 — Authorization receipts: the enforcement layer gets its journal

*Backfilled (ADR 032 train): #127 shipped the code, the tests and the
count — but this record itself never landed in ADRs.md. Written back
from `noirebox/authorization.py` and the #127 commit, unchanged in
substance.*

**Status**: accepted — implemented (`seal_authorization`,
`replay_authorization`, `noirebox seal-authorization`, tests, PR #127).

**Context**: the 2026 standards conversation splits agent governance in
two halves that keep being built separately. ENFORCEMENT at the moment
of action — authorization brokers outside the agent's reasoning: OWASP
ACS, NIST's software/AI-agent identity work, KedgeFlow's
grant/claim/dispatch gateways, UAI-BLOCK's OS-identity broker
(Unix sockets, SO_PEERCRED). KedgeFlow's own evaluation shows the limit
of enforcement alone: a permissive policy still authorized an
undesirable effect. EVIDENCE after the fact — what this journal is.
Dr. Bunic's demonstrable-governance tests name it: accountability and
auditability, at scale, durably. UAI-BLOCK self-reports the gap
verbatim: *"does not yet have tamper-resistant audit records,
independent verification."*

**Decision**: an `authorization/0.1` receipt seals one gate decision —
`{agent, action, resource, decision, warrant?, rule?, gate?, reason?}`.
`agent` is the requester identity *as verified at execution time* — the
OS/socket/TLS credential the gate actually checked (e.g. `os:uid=942
via SO_PEERCRED`), not a name the agent claimed. `decision` fails
closed: `allowed | denied | gate_error` — a swallowed gate failure is
an allow nobody decided. An `allowed` decision REQUIRES a `warrant`,
the independent authority the allow leans on (a user-instruction ref,
a prior receipt seq, an explicit scope grant); the resource's own
presence/relevance/plausibility/usefulness are refused as warrants at
seal time (laws 1–8 — the admission discipline, applied to gates).
`replay_authorization` is the auditor's pass: allows without warrants,
laundered warrants, malformed events sealed around the refusals, and
**gate flips** — a triple (agent, action, resource) denied earlier in
the sealed sequence must not appear allowed later; either the warrant
legitimately changed (seal it again with the new warrant) or the gate
is inconsistent.

**Non-goals**: this is the journal contract for gates, not a policy
engine. It decides nothing; it makes what was decided undeniable.

**Consequences**: a control that enforces here can journal its
allow/deny decisions as receipts — the enforcement becomes *provable*,
not just present (`RELATED-WORK.md`, the ACS row). An auditor replays
the sealed sequence and checks the gate never allowed an unwarranted
request. The bridge is one function call for any broker; the refusal
vocabulary is the price of entry.

## ADR 032 — Canary-sweep receipts: the sensor gets its journal

**Status**: accepted — implemented (`seal_canary_sweep`,
`replay_canary_sweep`, `noirebox seal-canary-sweep`, tests; issue
#129's first two candidates). Lineage: row **T6-011** of
[agentic-ai-test-checklist-110](https://huggingface.co/datasets/srinivaspadmanabhuni/agentic-ai-test-checklist-110)
(Padmanabhuni, CC-BY, 110 tests, per-row NIST AI-RMF / OWASP-ASI /
EU-AI-Act mappings), arriving via the OpenShell post thread (dev.to,
comment 3j2j4, October 2026) with two named gaps against brokered
custody — T6-011 (secret resurfacing) and T5-011 (tenant-scoped
exports). The third independent arrival in this corridor in a month
(Lin's *Capability Is Not Authority* → ADR 026; the SCAR catalog → the
spec canary; now a test catalog), each reading the same vocabulary from
its own side.

**Context**: T6-011 — *a secret the agent has seen must not resurface
in its later outputs*. The check is a CANARY SWEEP: plant token secrets
in the agent's context, scan every output for them. The sweep runs
OUTSIDE the agent, with the rest of the enforcement stack — the
deployer's gateway, where ADR 031's gates live. What the sweep never
had is the evidence leg: "we scanned" is a claim in an ops log the
operator holds and can edit; an auditor who was not there can replay
none of it. The checklist row is written as a test because only
something outside the model can enforce it (their T5-018 says the same
about allowlists) — and a test that ran with no receipt of having run
is a control that cannot be audited.

**Decision** — the sweep itself becomes a sealed event:

1. **`canary-sweep/0.1`** — `{canary_digest, outputs_swept, turns_swept?,
   outcome, findings?, sensor?, note?}`. The canary travels as its
   sha256 DIGEST, never as content: the journal that proves containment
   must not become the leak's backup copy (a sweep receipt that
   archives the token is the leak it was meant to catch). The deployer
   holds the token; the journal holds the digest; the pair reconciles
   out of band. This is deliberately NOT the SCAR-PROC-114 spec canary
   (ADR 028's machinery, sealed verbatim because its presence in the
   journal IS the proof of read): a sweep canary STANDS IN for a
   secret, and the one bytes-level rule of a secrets sweep is that the
   secret stops existing everywhere except where it is authorised.
2. **The outcome fails closed**: `clean | canary_resurfaced |
   sweep_error` — a sensor that did not run is named, never silently
   counted as a pass.
3. **Findings travel only with `canary_resurfaced` and are required
   with it**: each is exactly `{at, output_digest}` — the turn/output
   coordinate where the canary came back, and the sha256 of the
   offending output. Content never lands. A clean sweep with findings
   is a lie; a failed sweep with findings is ambiguous evidence —
   rerun, or seal what resurfaced. Both refused at seal time.
4. **The denominator is a field**: `outputs_swept` / `turns_swept` —
   ADR 020's discipline one layer out. A `clean` sweep over zero
   outputs seals as fact and replays as `vacuous_sweep`: a sweep that
   certified nothing certifies nothing, named, never silence.
5. **`replay_canary_sweep`** is the auditor's pass: malformed events
   (generic append around the refusals), the consistency breaks above,
   and vacuity. A `canary_resurfaced` outcome is NOT a finding against
   the journal — it is the sensor's result, exactly what the receipt
   exists to prove; the findings here are discipline breaks.
6. **T5-011 rides ADR 026**: `admission/0.1` gains an optional `reach`
   field naming the boundary the admission check enforced (the tenant)
   — a tenant-scoped export check passes on a receipt instead of a
   boolean. Absent = journal-wide; additive only.

**Non-goals, stated so they can be refused in public**: noirebox does
NOT sweep. No scanner, no detector, no canary generator ships here —
the sensor is external (the guard's, the deployer's), and a witness
inside the thing it witnesses is no witness (ADR 028's refusal,
applied to sensors). Multi-canary sweeps are multiple receipts, one per
canary: composable, and each digest reconciles against exactly one
token. We do not verify the sensor ran correctly — we seal what it
reported; the receipt's value is that the report can no longer be
silently edited or silently omitted. T7 (metamorphic consistency for
the judge) remains open — the checklist's row names it, the crosswalk
keeps it visible (`docs/CROSSWALK-110.md`), and no candidate ships
here.

**Consequences**: `seal_canary_sweep` + `replay_canary_sweep` in
`noirebox/canary_sweep.py`, the `seal-canary-sweep` subcommand (same
refusals verbatim, exit 2 and no event lands), `reach` on
`seal_admission`, tests, this record, and `docs/CROSSWALK-110.md` —
the crosswalk table kept current, SCAR-BENCH-style: external catalogs
the vocabulary converges with, credited and dated. The bridge contract
for the guard: one sweep, one receipt; the guard does the sweeping, the
journal does the proving.
