# SCAR-BENCH — the claims format, the enforcement taxonomy, the differential

*Companion to `tests/test_scar_replay.py` (the SCAR catalog replay, issue
#53) and to the Part 3.8 publication by Randal L. Schwartz ("What LLMs
'Know' That You Don't Know They Know" — the SCAR suite's origin and first
external citation). Everything here is sourced: the taxonomy from the
Part 3.8 discussion (Reid + Randal), the claim format from Randal's
published scorecard, the W231 mapping from Mike Mol's mtools.*

---

## 1. The enforcement taxonomy — Level 0 / 1 / 2

Every control is graded by WHAT ENFORCES IT, not by where it is written
(taxonomy from the Part 3.8 discussion — Reid's boundary, Randal's
naming):

| Level | What enforces | Fails how |
|---|---|---|
| **0 — prose rubric** | a paragraph of English nobody executes | silently — the drift is invisible |
| **1 — primitive in context** | a high-mass primitive the model reads (a Makefile, a convention, a labeled field) | visibly — but only if someone looks |
| **2 — host-enforced** | the host refuses, or the reconciler surfaces | structurally — the path ceases to exist or the finding is sealed |

**NoireBox controls, graded honestly:**

| Control | Enforcement kind | Level |
|---|---|---|
| `judged_by` required, no default (v0.2.3) | schema refuses to seal (`TypeError`) | **2** |
| `spec_hash` required for `judged_by="llm"` (v0.2.2) | schema refuses to seal (`ValueError`) | **2** |
| witness ≠ author (`build_receipt` + `ensure_witness_distinct`) | refuses at seal and serve time | **2** |
| two-key pairing (`same_key_pairing`) | reconcile finding, resolved by signature | **2** |
| attempt-first (`unlogged_attempt`) | reconcile finding | **2** |
| `verdict_predates_terminal` | reconcile finding | **2** |
| label-vs-journal join (`label_llm_call_mismatch`) | reconcile finding (out-of-band observation) | **2** |
| `requirement_ref` resolution (`dangling_requirement_ref`) | reconcile finding against the sealed registry | **2** |
| canary witness (`spec_not_canonical`) + read-before-define race (`judge_defined_before_spec_read`) | reconcile finding against the sealed spec registry | **2** |
| calibration a-priori bounds (`calibration_fitted_in_sample`) | sealed + checked (refuses at reconcile) | **2** |
| `receipt_gap` (fetches vs receipts) | reconcile check | **2** |
| expectation `channel` grading (#43) | convention — the row is graded, nothing is enforced | **1** |
| attempt-first as an integrator discipline (before the invariant is configured) | docs + example | **1** |
| "review your code carefully before opening a PR" | nothing | **0** |

The rule the taxonomy teaches: **never stop at Level 1 in production** —
Randal's SCAR-BENCH-04 matrix shows a Level 1 primitive jumping multi-hop
resolution from 61.4% to 96.2%, and the remaining gap is exactly what
Level 2 exists for.

## 2. The claims format — SCAR-BENCH

Any numerical claim NoireBox makes follows the format of the catalog's
published matrix — **baseline → primitive → controlled delta, per model,
with denominator and seeds** — because a number without its denominator is
a testimonial. The template (Randal L. Schwartz, Part 3.8, §4 — 7 suites ×
120 paired trials per condition = 1,680 trials across gemini-2.5-flash-lite
/ flash / pro / 3.1-pro-preview; all deltas p < 0.0001):

| Suite | Condition A (Freq ≈ 0 prose) | Condition B (Freq > 10⁶ canon) | Δ |
|---|---|---|---|
| SysV `/etc/init.d` boot ordering | 0.8% (1/120) | 60.0% (72/120; 96.7% on 2.5-pro) | +59.2 pp |
| RFC 5234 EBNF grammar | 32.5% (39/120) | 77.5% (93/120) | +45.0 pp |
| Design-by-Contract + QuickCheck | 1.7% | 60.0% | +58.3 pp |
| Database WAL + 2PC | 45.8% (55/120) | 93.3% (112/120) | +47.5 pp |
| Circuit Breaker FSM | 0.8% (1/120) | 98.3% (118/120) | +97.5 pp |
| GNU Makefile DAG | 72.5% | 72.5% (+16.7 pp on flash-lite) | ceiling on Pro |
| `git bisect` partitioning | 19.2% | 81.7% (98/120) | +62.5 pp |

Claim checklist: baseline stated · primitive named · delta controlled ·
per-model breakdown · denominator shown · significance stated. A claim
that cannot fill this table is not published as a claim.

### Measured — SCAR-BENCH-114, the open-weights leg (Oct 11)

Randal's prediction ("the drop-in primitives hold on open weights while
the canary tokens trip harder") — tested with the shipped witness layer:
the orchestrator race replayed per model, Condition A = prose only (the
judge's system prompt can only come from priors), Condition B = the
canonical bytecode loaded first (the waitpid discipline). Graded by
`reconcile_spec`: a produced prompt without the planted canary is the
`spec_not_canonical` trip.

| Model (all open weights, local) | A prose: trips/n | B primitive: trips/n | strict canonical |
|---|---|---|---|
| qwen2.5-coder:3b | 18/18 (100%) | 15/20 (75%) | 0 |
| qwen2.5:0.5b | 19/19 (100%) | 15/19 (79%) | 0 |
| llama-guard3:1b (classifier — cannot play the role at all) | 20/20 (100%) | 20/20 (100%) | 0 |

Read: **Condition A is a ceiling — 100% trips everywhere, no model ever
guesses "4. Blast Radius" from priors** (the prediction's first half
holds, hard). **Condition B cuts trips to ~75-79% — Level 1 reduces the
hallucination but does not fix it**, which is the argument for Level 2:
the host must load the spec from the sealed bytecode, never trust the
model's paraphrase. **Strict canonical = 0 everywhere**: no model ever
reproduces the exact bytes — which is precisely why the receipt carries
`spec_hash` of what was ACTUALLY loaded. llama-guard3:1b is a safety
classifier, included deliberately: the instrument catches total role
non-compliance too. Disclosure: single machine, local Ollama,
temperature 0.7, per-trial seeds (42+i, recorded per trial), prompts in
`bench/scar114_canary.py`, 4 timeouts excluded with denominators shown.
**The frontier leg is open** — same harness, one API key, and the
"works because it's Unix" vs "works because it's frontier" separation
lands.

## 3. The suite is a differential — run it against YOUR gate

`tests/test_scar_replay.py` is not NoireBox's test suite; it is a
**negative-control set for the lane** (Randal: "every gate that runs it
inherits the failure modes of every gate it ran against"). Four attacks
today, five fixtures — each asserts what YOUR reconciliation layer DOES:
catches the attack, or confesses the gap in writing.

```bash
make differential        # the catalog, replayed against this tree
```

If you build agent gates: point the fixtures at your reconciler, keep the
score honest (caught / provable / confessed), and publish it — the
registry only stays a differential if the scores travel.

## 4. The W231 bridge — cross-stack twin (Mike Mol's mtools)

Mike Mol's Negative Witness (mtools `W231`, Part 3.7) is the third
independent arrival of the same invariant — "a real input replayed with
the exception removed must deny" is a deliberately-failed probe by another
name. The classifications map:

| mtools a/b/c class | NoireBox family | Shared instrument |
|---|---|---|
| **a — mechanical** (byte-level: chain, tamper, reordering) | chain verification, `verify_chain_multi`, the tamper replay | the digest as witness ("the FILE wins" — Mol's half; the signature + anchor is ours) |
| **b — arithmetical** (counts, sums, denominators) | `unlogged_attempt`, `receipt_gap`, journaled rounds, calibration ranges | the denominator that cannot lie by omission |
| **c — behavioral** (labels, intent, conduct) | `judged_by` + label-vs-journal join, belief capture, channel grades, canary witness | the self-report confronted with out-of-band observation |

The wedge Mol's stack leaves open is ours and vice versa: his ledger is
tamper-evident WITHOUT signatures or external anchoring; ours anchors
externally (RFC 3161/OTS). A fleet running both inherits both failure
modes — which is what a differential is for.

## 5. The open-weights axis (next)

humam_moin's question on Part 3.8: if gravity is pre-training-derived, the
Level 1 primitives should hold on open weights while **the canary tokens
trip harder** (smaller priors, less canonical coverage). NoireBox's
fixtures are model-agnostic by construction; the join with Randal's canary
corpus on open-weights models, with the replay as witness, would separate
"works because it's Unix" from "works because it's frontier". Collaboration
stage — no core code.
