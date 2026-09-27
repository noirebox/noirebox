# Threat Model — NoireBox v0.3.0

*Method: simplified STRIDE. The guiding principle is to document what the system does NOT cover as honestly as what it does cover — this is a proof tool, not a talisman.*

## Assets to protect

| Asset | Why |
|---|---|
| **Journal integrity** | the heart of the project: an undetected falsified record = total failure |
| **Private Ed25519 key** | compromise allows forging a full chain |
| **Transcripts / payloads** | potentially personal data (GDPR) |
| **Third-party trust** | the published attestation must remain impossible to recycle |

## Actors and scenarios

| Actor | Scenario | Coverage | Status |
|---|---|---|---|
| **Malicious participant** (in the meeting) | injection via transcript (“ignore previous instructions…”) | regex + ML guardrail, incident journaled | ✅ measured (tests + `make demo-llm`) |
| **Insider / rushed dev** | rewriting a payload in the database | chain: recomputed hash ≠ stored hash | ✅ demonstrated (`demo_tamper.py`) |
| **Methodical insider** | deleting or reordering events | sequence + `prev_hash` links | ✅ tested |
| **Insider with private key** | complete chain regeneration | **closed in v0.3.0**: RFC 3161 anchoring ([ADR 006](ADRs.md)) makes the chain head signed by an external TSA — a retroactive token is impossible, and regeneration creates a head the old token does not cover | ✅ tested (`test_insider_regeneration_is_caught_by_anchor`); HSM/KMS remains defense-in-depth |
| **Network attacker** | API abuse, flood, exfiltration of DB via HTTP | **closed in v0.2.0**: OAuth2 JWT + rate limiting 60 req/min/client ([ADR 004](ADRs.md)); TLS is handled by the reverse proxy | ✅ tested |
| **Model attacker** | bypassing the guardrail through unknown reformulation | probabilistic: measured false negatives are non-zero | ⚠️ stage 2 LLM judge in roadmap |
| **Dishonest service operator** | modifies the ordinary app logs | exactly the use case: append-only journal + independent third party | ✅ project principle |
| **External auditor** | wants to verify without trust | export + offline `verifier.py`, zero network calls | ✅ tested |
| **Lying source** (write-time misreport) | logs “approved by policy X” when the check silently no-opped — the lie ships *at write time*, not after | **outside the chain’s guarantees**: tamper-evidence ≠ accuracy-at-source — the hash proves the record wasn’t altered, not that it was true when sealed; a lie sealed at write time verifies clean forever | ⚠️ partial mitigation shipped: source separation (each truth-source journals its own events) + `noirebox reconcile` — an outcome with no sealed decision behind it surfaces as `orphan_outcome`; fooling it requires lying at every sealing source |

## Environment assumptions

- The server hosting SQLite + the key is under reasonable control
  (chmod 600, no public disk access) — otherwise, see the insider-with-key case,
  now detected by RFC 3161 anchoring.
- **RFC 3161 anchoring**: trust comes from the TSA. Self-hosted (`make tsa`), it sits in the same trust boundary as the server (helpful for the mechanism and offline use; for stronger third-party trust, point at public/qualified TSAs and run several). The TSA certificate travels with the anchor (TOFU) — pinning is possible.
- `verifier.py` is obtained from a trusted source (the repository).

## Outside v0 scope

- Availability (DoS) — proof service, not a critical production system
- Payload encryption (GDPR minimization is caller responsibility)
- Multi-tenant, sharding, high availability
- Full host compromise (OS-level trojan): beyond the scope of an application library; hardware detection (HSM) is on the roadmap
- **Accuracy-at-source** — the journal proves what was sealed, when, and in what order, never that a sealed claim was true when written (see the “Lying source” actor above); the mitigation is source separation, cross-checked by `noirebox reconcile`
