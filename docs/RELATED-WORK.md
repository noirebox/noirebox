# Related work — where the journal sits in the 2026 agent-governance stack

*NoireBox is the EVIDENCE layer: an append-only, hash-chained, signed journal
that makes agent decisions and their outcomes tamper-evident and offline-
verifiable. It enforces nothing at execution time. The efforts below enforce
at execution time and mostly log nothing tamper-evident. These are
complementary layers of the same stack — this page maps them honestly.*

---

## Enforcement efforts (the other half of the stack)

| Effort | What it does | Relation to NoireBox |
|---|---|---|
| [OWASP Agent Control Standard (ACS)](https://genai.owasp.org/resource/agent-control-standard-acs/) (Sep 2026) | Portable runtime policy enforcement and visibility across agent platforms | Controls that enforce here can journal their allow/deny decisions as [`authorization` receipts](../noirebox/authorization.py) (ADR 029) — the enforcement becomes *provable*, not just present |
| [NIST: Identity & Authorization for Software and AI Agents](https://www.nist.gov/news-events/news/2026/02/new-concept-paper-identity-and-authority-software-agents) (Feb 2026) | Concept paper: agent identity, authorization, auditing | Shares the vocabulary (identity, authorization, auditing); NoireBox contributes the auditing third with cryptographic attribution instead of claimed names |
| [KedgeFlow](https://arxiv.org/abs/2610.14810) (Oct 2026) | Programmable control plane: language-independent contracts, signed single-use allowances, grant–claim–dispatch linkage; 6,560 concurrent claim attempts with exactly-one-claim guarantees; MCP reference implementation | The strongest enforcement neighbor — and its own evaluation names our reason to exist: *a permissive policy still authorized an undesirable effect*. Enforcement alone cannot tell you afterwards what was authorized, by whom, on which warrant. KedgeFlow's retained outcome records + NoireBox's sealed journal is the natural composition |
| Judge Protocol (community, 2026) | Production gate at the moment of action: consequential decisions require human authorization | Same split: the gate decides, the journal proves the decision happened and wasn't bypassed |
| [UAI-BLOCK](https://futurium.ec.europa.eu/en/apply-ai-alliance/community-content/uai-block-ai-governance-principles-tested-access-controls-technical-progress-and-international) (Futurium, Oct 2026) | Citizen-led OS-identity broker prototypes (Unix sockets, SO_PEERCRED) | Its own disclosure names the gap NoireBox fills: *"does not yet have tamper-resistant audit records, independent verification, or demonstrated operation at scale"*. The `authorization` receipt (ADR 029) is designed for exactly such brokers |
| Meta Sentinel / DAS (Futurium, 2026) | Protected validation, separation of computation from authority | Shares the computation ≠ authority principle; the journal adds the evidence half |

**The bridge, concretely**: every allow/deny a gate produces can be sealed as
an `authorization` receipt — agent identity *as verified* (SO_PEERCRED, TLS),
action, resource, decision, and the independent warrant behind any allow
(refused at seal time if it leans on the resource's own presence, relevance,
plausibility or usefulness — laws 1–8). `replay_authorization` then gives the
auditor: allows without warrants, laundered warrants, malformed events sealed
around the refusals, and *gate flips* (a triple denied early, allowed later).

## Dr. Bunic's four tests of demonstrable governance

The SSRN working paper *"From Declared Governance to Demonstrable Governance"*
(Futurium, Oct 2026) judges governance claims on four tests. Honest self-score:

| Test | NoireBox status |
|---|---|
| **Accountability** | ✅ Decision receipts (ADR 026/028), admission receipts, attribution by signature — not by claimed name |
| **Auditability** | ✅ Hash-chained journal, Ed25519-signed events, offline `verify`, public attack-fixture catalog replayed in CI, mutation-tested checks (24/24) |
| **Scale** | ⚠️ Not yet benchmarked: journal throughput/size at production volume is unmeasured. Tracked; honest gap |
| **Durability** | ⚠️ SQLite append-only file + signed attestations, but no out-of-band anchoring yet (RFC 3161 TSA / public commit pin) — a compromised host could still truncate the tail. Tracked; honest gap |

## What we are not

Not an enforcement agent, not a policy engine, not a sandbox. If you need a
gate, use one of the efforts above — then point it at this journal, so its
decisions survive it.
