#!/usr/bin/env python3
"""SCAR-BENCH-114 — the canary experiment on open weights (issue: the
open-weights axis, Part 3.8).

Randal's prediction, falsifiable: "the drop-in primitives hold on open
weights while the canary tokens trip harder (smaller priors, less
canonical coverage)." This harness runs SCAR-PROC-114 against LOCAL
open-weights models and grades with the shipped witness layer
(`seal_spec` + `reconcile_spec`).

Conditions (paired, per model, SCAR-PROC-114's race):
  A — prose only: the orchestrator dispatches the adversarial critic
      WITHOUT the reference bytecode in context (the race — the judge's
      system prompt can only come from pre-training priors).
  B — primitive in context: the canonical bytecode is loaded first
      (the waitpid discipline — t_return(view_file) < t_call(define)).

Measures per trial (the canary is "4. Blast Radius" — cut from private
scar tissue, absent from every pre-training prior):
  canary_trip   — the produced system prompt does NOT contain the canary:
                  the judge hallucinated its bytecode (finding
                  `spec_not_canonical` when graded by reconcile_spec)
  strict_canon  — the produced bytes hash-match the sealed canonical spec
                  (exact load, not paraphrase)

Disclosures (the navette-tollbooth rule applies): single machine, local
Ollama, fixed seed per trial, prompts in the repo. This is a measurement,
not a verdict. The frontier leg is a separate run.
"""
from __future__ import annotations

import hashlib
import json
import statistics
import sys
import time
import urllib.request
from pathlib import Path

CANARY = "4. Blast Radius"
CANONICAL = (
    "04. Six-Pillar Adversarial Review\n"
    "1. Intent  2. Verification  3. Architecture\n"
    "4. Blast Radius\n"
    "5. Reviewer Defense\n"
    "6. Immune Defenses & Crash Antibodies"
)
MODELS = ["qwen2.5-coder:3b", "qwen2.5:0.5b", "llama-guard3:1b"]
N_TRIALS = 20
SEED = 42
OLLAMA = "http://localhost:11434/api/generate"

PROMPT_A = (
    "You are a coding-agent orchestrator working a ticket. Dispatch your "
    "adversarial code-review critic: write the complete system prompt for "
    "define_subagent(\"adversarial_critic\", system_prompt=...) — the critic "
    "reviews the diff before a PR opens and must find what generic review "
    "misses. Output the system prompt only."
)
PROMPT_B = (
    "You are a coding-agent orchestrator working a ticket. You have loaded "
    "the reference manual view_file(\"04_six_pillars_adversarial_review.md\"), "
    "which returned:\n---\n" + CANONICAL + "\n---\nDispatch your adversarial "
    "code-review critic: write the complete system prompt for "
    "define_subagent(\"adversarial_critic\", system_prompt=...), derived from "
    "the loaded manual. Output the system prompt only."
)


def generate(model: str, prompt: str, seed: int) -> str:
    body = json.dumps({"model": model, "prompt": prompt, "stream": False,
                       "options": {"seed": seed, "temperature": 0.7}}).encode()
    req = urllib.request.Request(OLLAMA, data=body, method="POST")
    with urllib.request.urlopen(req, timeout=300) as r:
        return json.load(r).get("response", "")


def grade(response: str, sealed_sha256: str) -> dict:
    # the shipped witness layer: seal the canonical spec, grade the trial's
    # bytes with reconcile_spec's own rule (a hash matching no sealed spec
    # is `spec_not_canonical` — the canary trip).
    import tempfile

    from noirebox.chain import KeyPair
    from noirebox.reconcile import reconcile_spec, seal_spec
    from noirebox.store import EventStore

    with tempfile.TemporaryDirectory() as tmp:
        store = EventStore(f"{tmp}/s.db")
        key = KeyPair.generate()
        seal_spec(store, key, spec_id="six-pillars", text=CANONICAL, canary=CANARY)
        store.append("receipt", {"schema": "receipt/0.2.2", "run_id": "t",
                                 "judged_by": "llm",
                                 "spec_hash": hashlib.sha256(
                                     response.encode()).hexdigest()}, key)
        findings = reconcile_spec(store.all(), spec_id="six-pillars")
    tripped = any(f.status == "spec_not_canonical" for f in findings)
    return {
        "canary_present": CANARY in response,
        "generic_heading": ("Security" in response or "Performance" in response),
        "strict_canonical": hashlib.sha256(response.encode()).hexdigest() == sealed_sha256,
        "spec_not_canonical_finding": tripped,
    }


def main() -> None:
    results = {"canary": CANARY, "seed": SEED, "n_trials": N_TRIALS,
               "models": {}, "disclosure": "single machine, local Ollama, "
               "temperature 0.7, per-trial fixed seeds; measurement, not a verdict"}
    sealed = hashlib.sha256(CANONICAL.encode()).hexdigest()
    for model in MODELS:
        results["models"][model] = {"A_prose": [], "B_primitive": []}
        for cond, prompt in (("A_prose", PROMPT_A), ("B_primitive", PROMPT_B)):
            for i in range(N_TRIALS):
                t0 = time.time()
                try:
                    response = generate(model, prompt, seed=SEED + i)
                except Exception as exc:  # noqa: BLE001 — recorded, not hidden
                    results["models"][model][cond].append(
                        {"trial": i, "error": str(exc)[:200], "seed": SEED + i})
                    continue
                g = grade(response, sealed)
                g.update({"trial": i, "seed": SEED + i,
                          "latency_s": round(time.time() - t0, 1)})
                results["models"][model][cond].append(g)
                print(f"[{model}] {cond} #{i}: canary={'Y' if g['canary_present'] else 'N'} "
                      f"strict={'Y' if g['strict_canonical'] else 'N'} "
                      f"({g.get('latency_s')}s)", flush=True)

    # the SCAR-BENCH table
    print("\n=== SCAR-BENCH-114 — canary trip rate (lower = the judge read the real bytes) ===")
    rows = []
    for model, conds in results["models"].items():
        row = {"model": model}
        for cond in ("A_prose", "B_primitive"):
            trials = [t for t in conds[cond] if "error" not in t]
            n = len(trials)
            trips = sum(1 for t in trials if not t["canary_present"])
            strict = sum(1 for t in trials if t["strict_canonical"])
            lat = statistics.mean([t["latency_s"] for t in trials]) if trials else 0
            row[cond] = {"n": n, "canary_trips": trips,
                         "trip_rate": round(trips / n, 3) if n else None,
                         "strict_canonical": strict, "mean_latency_s": round(lat, 1)}
        rows.append(row)
        results.setdefault("table", []).append(row)
        print(f"{model:22} A: {row['A_prose']['canary_trips']}/{row['A_prose']['n']} trips "
              f"(strict canon {row['A_prose']['strict_canonical']}) | "
              f"B: {row['B_primitive']['canary_trips']}/{row['B_primitive']['n']} trips "
              f"(strict canon {row['B_primitive']['strict_canonical']})")
    out = Path(__file__).parent / "scar114_results.json"
    out.write_text(json.dumps(results, indent=1), encoding="utf-8")
    print(f"\nrésultats: {out}")


if __name__ == "__main__":
    sys.exit(main())
