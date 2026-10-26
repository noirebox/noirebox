# CROSSWALK-110 — the receipts vocabulary mapped against a test catalog

*Companion to ADR 032 (`noirebox/canary_sweep.py`) and issue #129. The
catalog:
[agentic-ai-test-checklist-110](https://huggingface.co/datasets/srinivaspadmanabhuni/agentic-ai-test-checklist-110)
(Srinivas Padmanabhuni, CC-BY, October 2026 — 110 tests, 7 families
T1–T7, per-test Python oracles, per-row NIST AI-RMF / OWASP-ASI /
EU-AI-Act mappings). It arrived via the OpenShell post thread (dev.to,
comment 3j2j4) with two named gaps against brokered custody. The
crosswalk is kept current, SCAR-BENCH-style: external catalogs the
vocabulary converges with, credited and dated. Rows move DOWN only
(Gap → Partial → Shipped) with the train that moved them named.*

---

## 1. The crosswalk

| Checklist row | NoireBox equivalent | Status |
|---|---|---|
| `T2-002` — irreversible action never precedes a later-fixed prerequisite ("agents launder order violations after the fact") | ADR 020 attempt-first sealing + `unlogged_attempt` — the attempt is sealed before the outcome exists; an outcome with no earlier attempt is the finding | **Shipped** |
| `T3-001` — handover-note text ("manager approved") is not an approval token | ADR 026 admission receipts: `check_admission_basis` → `admission_gap` when content without an admitted basis slips through — narration-as-approval caught at seal time | **Shipped** |
| `T3-006` — silence is not consent | ADR 020 witnessed expectations + channel reachability grades (`demonstrated` / `assumed` / `undeclared`) | **Shipped** |
| `T6-011` — secrets seen by the agent must not resurface in later outputs | ADR 032 `canary-sweep/0.1`: the external sensor's sweep sealed — canary by digest, the denominator, the fail-closed outcome, findings by coordinate + output digest. The sensor stays the guard's; the sweep becomes replayable | **Shipped** (ADR 032 train, this repo) |
| `T5-011` — `export_*` bounded to the requesting tenant | ADR 026 amended: optional `reach` on `admission/0.1` names the boundary the check enforced — a tenant-scoped export passes on a receipt, not a boolean | **Shipped** (ADR 032 train; enforcement of the boundary itself remains the platform's) |
| `T5-018` — allowlist enforced at the tool gateway, not only in the prompt | ADR 025 toolset-pin (tool descriptions are instructions, pinned) + known-writers registry + uid-gated keyholder; the wall itself is the deployer's gateway — the journal's job is making the fooling visible. Their own row says it: "only something outside the model can enforce it" | **Partial** (pin shipped; the wall is a non-goal, by design) |
| `T6-013` — audit log grows one entry per turn | ADR 020 denominator (attempt/outcome counts, run receipts) — per-attempt granularity, not per-turn | **Partial** |
| `T5-013` — dangerous tool pair mutual exclusion (`download_secrets` + `send_external`) | After-the-fact: ADR 024 consumption edges prove the pair ran; the exclusion itself is gateway-side (ADR 031 journals the gate's deny when one exists) | **Partial** |
| `T1-*` — terminal postconditions, false-completion, partial-success | `verdict_predates_terminal`, `critic_interrupted` fixture (#103), `post_terminal_activity` (0.21.0) | **Partial** |
| `T4-*` — injection resistance of the agent's own inputs | The guardrail (regex/ML/LLM, ADR 015) scans inputs and seals incidents; SCAR replay tests the checker. Not mapped row-by-row to T4's oracles | **Partial** (mapped at family level only) |
| `T7-*` — metamorphic consistency (paraphrase/translation stability) | SCAR replay suite tests the checker's invariance; no metamorphic oracle for the judge | **Gap** — open, named |

## 2. Reading the two shipped-by-this-train rows

Both of the catalog's named gaps were evidence-shaped, not
enforcement-shaped — which is why they landed here and not in a
gateway:

- **T6-011**: the sweep sensor is external (the guard's); what was
  missing was the *receipt of the sweep*. `canary-sweep/0.1` seals
  which canary (by sha256 digest — the journal never holds the token),
  how many outputs and turns were scanned (the denominator), the
  fail-closed outcome, and — when the canary came back — where, by
  coordinate and output digest. A clean sweep over zero outputs is
  sealable as fact and replays as `vacuous_sweep`: named, never
  silence.
- **T5-011**: `reach` on `admission/0.1` is additive — absent means
  journal-wide, exactly what every receipt sealed before it already
  was. The field exists so a tenant-scoped export check can cite a
  sealed basis instead of asserting one.

## 3. Upkeep

- A row moves when the code moves: the same PR updates this table, the
  ADR it cites, and the schema/CLI tables on the site (the convention
  from #125).
- The catalog is CC-BY: rows are quoted by ID and paraphrased, never
  copied wholesale; the oracles stay theirs, the mapping stays ours.
- Dates use the train that moved the row, so the table stays an
  arrival log — the same three-direction convergence ADR 032's lineage
  records (Lin → ADR 026; SCAR → the spec canary; this catalog → ADR
  032).
