# Article 12 mapping — the AI Act's logging requirements, implemented

> **Position paper, October 2026.** CEN-CENELEC JTC 21 is drafting the
> harmonized standard for AI Act article 12 ("record keeping through logging
> capabilities") under standardisation requests M/593 and M/613 — no
> harmonized standard has yet been cited in the Official Journal. This
> document maps each article 12 requirement to the exact NoireBox mechanism
> that implements it, with the verification method an auditor runs. It is
> our contribution to the drafting conversation: a working, reproducible
> reference implementation is worth more to a drafting committee than
> another position paragraph.
>
> Legal disclaimer: not legal advice. Conformity remains the deployer's
> responsibility (see [COMPLIANCE-EU.md](COMPLIANCE-EU.md)).

## The mapping

| AI Act requirement | NoireBox mechanism | Verification |
|---|---|---|
| **Art. 12(1)** — automatically record events over the lifetime of the system | The journal IS an automatic recorder: every event is sealed by the runtime (API, MCP, CLI, hooks) — no manual step exists in the write path (`store.py`, append-only SQLite) | `GET /api/v1/verify` — the chain recomputes in place |
| **Art. 12(2)** — traceability of functioning; deployer monitoring (art. 26(5)) | Free-typed events cover the full lifecycle: `decision_belief` (the resolved view before acting), `llm_attempt`/`llm_call`/`llm_output` (the act), `run_witness` (what actually happened, byte-counted), `incident` (guardrail catches) — sealed IN THIS ORDER, the order being part of the proof | `noirebox replay <meeting-id>` — reconstructs the decision timeline from sealed evidence |
| **Art. 12(3)(a)** — period of each use (start/end of eachSession) | `model_trajectory` events carry `first_started_at`/`last_completed_at` (the envelope, never the content); `ai_use` builders (ADR 010) carry the validated use period | Field presence in the sealed payload; the auditor reads the export |
| **Art. 12(3)(b)** — the reference database | The `model` field on `llm_call` and in `model_trajectory` metadata commits to the model identity per call; the belief event commits to `resolved_target` | `noirebox replay` shows which model answered, per call |
| **Art. 12(3)(c)** — the input that prompted the match | Inputs are sealed as **sha256 digests by construction** (ADR 010 minimization): `inputs_seen` in `decision_belief`, per-record digests in trajectories — the match is provable without storing personal data | `verify_trajectory(payload, file)` — recomputation against the retained log |
| **Art. 12(3)(d)** — identification of the natural persons who verified (art. 14(5)) | `ai_verification` builders require `human_verifier` (validated, non-empty); **writer identity is cryptographic**: per-process keys, `verify_chain_multi` resolves which known key sealed each event — "a name, not a role" (ADR 021) | Signature verification per event; `reconciliation_policy.decided_by` for decisions |
| **Art. 19 / 26(6)** — logs retained ≥ 6 months | The journal is append-only SQLite (0600); retention is deployment policy, and the **anchored attestation survives retention windows**: one anchor seals the whole past — an export retained 6 months proves the state at sealing time forever | `verifier/verifier.py export.json` — offline, exit 0 |
| **Art. 55(1)(c)** — serious incident tracking (GPAI, live) | `ai_incident` builders (validated severity, digests-only inputs); guardrail incidents sealed with engine, category, offsets | Audit-pack: `noirebox audit-pack ./audit` |
| **Annex IV §2(f)** — describe the logging characteristics | **Generated, not written**: `noirebox audit-pack` renders `ANNEXE-IV-2f.md` FROM the journal itself — event histogram, witnesses, public key, verification instructions | Regenerate and diff: the pack IS a tamper check |
| **Integrity of the logs** (the requirement the harmonized standard is still defining) | SHA-256 hash chain + Ed25519 per-event signatures + **external anchoring** (RFC 3161 multi-TSA, OpenTimestamps/Bitcoin — roots pinned in the verifier, never the operator's) — an insider holding the key cannot rewrite history without the anchors exposing it (ADR 006-009) | `verifier.py` recomputes the chain AND every anchor token, offline, exit 0 |

## What we ask the drafting committee to keep in the standard

1. **Integrity must be externally testable.** A log that verifies "against its own key" proves only that someone with the key built it. The standard should require an export + independent verification path (ours: a standalone verifier + pinned TSA roots), not merely on-box attestation.
2. **Minimization and logging are not in tension.** Article 12(3)(c) asks for the matched input; data protection asks for restraint. Digest-first sealing (input hashes + retained source logs) satisfies both — the standard should name the digest pattern explicitly.
3. **Writer identity is cryptographic or it is decoration.** "Identification of natural persons" (art. 12(3)(d)) should resolve to per-writer keys with signature resolution — role labels are costumes (ADR 021).
4. **Completeness needs the denominator.** A chain proves what was written, not that everything was: the standard should encourage attempt-before-outcome conventions and reconciliation invariants (`outcomes ≤ attempts`) so omission becomes a finding, not a blind spot (ADR 020).
5. **Disclose the grade of proof.** Anchoring answers WHEN; custody answers WHAT (a counterparty's record beats yours). Deployments should disclose which grade they hold: *operator-held, anchored, no second party* (ADR 022).

## Reproduce everything above

```console
$ pip install noirebox
$ noirebox serve                     # the journal on :8768
$ noirebox seal decision '{"k":"v"}' # one event, chained + signed
$ noirebox audit-pack ./audit        # export + verifier report + Annexe IV §2(f)
$ python verifier/verifier.py audit/export.json
[✓] INTACT — … exit 0
```

Every claim in this document is a command. That is the position.
