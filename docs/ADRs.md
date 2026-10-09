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

## ADR 022 — Custody vs anchoring: map the trust boundary, disclose the proof grade

**Status**: accepted — the best framing received this week (mickyarun, PSD2); ops cadence from the reid thread (30/09) + mickyarun.

**Context**: anchoring (TSA/OTS) answers WHEN and is structurally indifferent to WHAT. Custody answers WHAT, because the counterparty who wrote their own record has a reason to disagree with yours. Conflating them oversells anchoring — the bank does not care that your hash is in Bitcoin; the bank cares that YOUR record of the payment matches THEIRS.

**Decision**:
1. **Every consequential action maps to its trust boundary**: if a counterparty exists (payment, message, contract, order), custody beats anchoring — require THEIR flow and reconcile the two (ADR 019 pairing). If the action is first-party end-to-end, anchoring is the grade of proof — and you disclose which: "operator-held, anchored, no second party."
2. **Disclose the grade** in payloads and docs: the receipt says what its proof is worth. The AI Act's art. 12 asks for the weakest grade explicitly — a tool that states its grade is auditable by its own documentation.
3. **Ops cadence defaults (the anchor window)**: "the interesting events live between the last anchor and the incident." Defaults: anchor on a WALL-CLOCK timer (a killed session's dead time counts in minutes, not in turn boundaries), and anchor BEFORE consequential actions (a destructive gesture starts on an anchored head). Shipped as the server's optional auto-anchor timer.
4. **Reconciliation names its cost** (mickyarun): multi-flow custody has a bill — another store, another key, another cadence, reconciliation latency. An honest cost note accompanies the benefit pitch; a tool that only sells the benefit is selling.

**Consequences**: the trust-boundary mapping becomes part of deployment docs; the auto-anchor timer ships (wall-clock cadence, before-consequence guidance documented); the cost note is a standing section in the reconciliation docs.

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
