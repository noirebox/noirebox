<div align="center">

🇬🇧 English · [🇫🇷 Français](README.fr.md)

# ⬛ NoireBox

**The black box for AI agents — tamper-evident journal, guardrails, verifiable proof.**

[![PyPI](https://img.shields.io/pypi/v/noirebox)](https://pypi.org/project/noirebox/)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](pyproject.toml)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Lint: ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![Image on GHCR](https://img.shields.io/badge/image-ghcr.io%2Fslabbdev%2Fnoirebox-blue)](https://github.com/slabbdev/noirebox/pkgs/container/noirebox)
[![Made in France](https://img.shields.io/badge/made%20in-France-blue)](#)

**Your AI agent writes meeting notes that bind your clients.
Eighteen months from now — who can prove what it *exactly* produced, and why?**
NoireBox seals every decision in a SHA-256 hash-chained + Ed25519-signed
journal, flags poisoned transcripts before they reach the agent, and exports
an attestation anyone can verify offline — **without trusting you**.

> **Works with any agent, in French and English.** The journal, the API, the
> MCP tools and the verifier are domain- and language-agnostic; each language
> gets a ~250 KB detector trained from a reproducible dataset (seed 42) — a new market =
> one dataset generator + `make train`. **Already have a guardrail? Keep it** —
> it's just another event source. 🇪🇺 Built for the
> [European market (GDPR & AI Act)](#built-for-the-european-market-gdpr--ai-act) — engineered in France.

[Quickstart](#quickstart) · [Real LLM scene](#the-real-llm-scene-local-ollama) ·
[Specs](docs/SPECS.md) · [Threat model](docs/THREAT-MODEL.md) ·
[ADRs](docs/ADRs.md)

</div>

---

## Built for the European market (GDPR & AI Act)

European AI vendors face a compliance reality their US competitors don't:
**proving** — not promising — what their systems did. NoireBox is engineered
around exactly that obligation. And the clock is real: GPAI incident
tracking is **live since August 2025** (art. 55(1)(c)), transparency
obligations applied in August 2026, and high-risk logging lands
**2 December 2027** (AI Act as amended by the Digital Omnibus,
Reg. (EU) 2026/1744) — with fines up to €35 M / 7 % of turnover.

| Requirement | How NoireBox answers |
|---|---|
| **GDPR art. 5(2)** — accountability: the controller must *demonstrate* compliance | Tamper-evident journal of what the AI produced, when, on which input |
| **GDPR art. 15/20** — data subject rights (access, portability) | Signed export of everything related to a meeting — verifiable *by the subject's own auditor* |
| **EU AI Act art. 12 + 19/26(6)** — automatic event logging, retained ≥ 6 months | Every agent decision sealed at runtime; log integrity is cryptographic, not a promise |
| **EU AI Act art. 55(1)(c)** (GPAI systemic risk — live) | Serious incidents kept track of, documented and reported — sealed as first-class events (`ai_incident`) |
| **AI Act Annexe IV §2(f)** — document the logging characteristics | `noirebox audit-pack`: one folder for the auditor — export + verifier report + generated logging description |
| **eIDAS art. 41** — a qualified timestamp carries a legal presumption | Anchor profiles for qualified eIDAS TSAs (Universign, Certigna…), public TSAs, and Bitcoin via OpenTimestamps — see [ADR 008/009](docs/ADRs.md) |
| **DPIA / DPO workflows** | Attestation exportable for the DPO; incident taxonomy feeding risk documentation |
| **Sovereignty** | Self-hosted, no telemetry, no cloud dependency, Ed25519 keys stay on your infrastructure — deploys anywhere (including EU-only clouds) |

> **Honest scope** (we're a building block, not a certification): NoireBox
> proves the *integrity* of your AI's record. Data minimization of payloads
> and HSM-grade key storage are the deployer's responsibility in v0 — see
> the [threat model](docs/THREAT-MODEL.md). A tool that oversells compliance
> is a liability; one that states its perimeter is auditable.

## Why

- **GDPR**: a platform claiming "GDPR-compliant" must be able to demonstrate
  what its AI produced, on which data, and when.
- **EU AI Act (art. 12)**: risk systems must keep *automatic event logs*.
  Today, virtually every LLM stack logs for *debugging* — not for *proof*.
- The market gap: observability tools (Langfuse, LangSmith…) are built for
  devs, remain modifiable after the fact, and produce nothing presentable
  to an auditor, a DPO or a client.

## Honest positioning (state of the art)

| Tool | What it does | What it doesn't |
|---|---|---|
| Langfuse / LangSmith / Helicone | LLM observability, debugging, traces | No tamper-evident proof, nothing exportable for an audit |
| Garak / PyRIT / promptfoo | **offline** model-level red-teaming | No runtime guardrail, no proof journal |
| halo-record / gate-oc-audit | hash-chained journals for *coding* agents | No business domain, no third-party attestation, no French |
| **NoireBox** | **immutable Ed25519 journal → RFC 3161 anchoring → exportable attestation + standalone verifier** (bundled FR/EN guardrail = one pluggable event source; **fleet anchoring**: one TSA seal covers N journals) | — |

**NoireBox applies the Certificate-Transparency model to AI-agent journals:**
many journals, one root signed by a timestamp authority, inclusion proofs that
anyone verifies offline (`noirebox/merkle.py`, `make demo-fleet`). To our
knowledge, no other agent-audit tool does this.

## The core is the journal. The guardrail is a plugin.

![NoireBox architecture](docs/architecture.svg)

No ambiguity about what the product is:

- **One NoireBox per agent or service** — like one flight recorder per
  aircraft. One instance = one SQLite file, one key pair, one chain. The
  fleet layer (`noirebox/merkle.py`) aggregates **proofs** (32-byte chain
  heads), never events: your journal never leaves your infrastructure.
- **The journal is the product** — chain, signatures, append-only storage,
  RFC 3161 anchoring, export, standalone verifier. It is domain-agnostic,
  agent-agnostic and language-agnostic: an event is a free-typed `type`
  plus a payload, nothing more. `chain.py`/`store.py`/`anchors.py` import
  zero detection code — delete the whole guardrail and everything still runs.
- **Prevention is pluggable** — a guardrail is just one event producer
  among others. Already have Lakera, Llama Guard, your own LLM-judge, your
  own regexes? **Keep them.** Journal their verdicts the same way
  (`POST /api/v1/events`, `type: "incident"`) and their catches become
  tamper-evident and third-party verifiable instead of rewritable app logs.
- NoireBox ships a bundled guardrail (regex + trained ML) as a
  **working example of that plugin contract** — and as a convenience if you
  have none. It is swappable by design ([ADR 003](docs/ADRs.md)).

> Prevention varies per stack. Proof is universal.

## Quickstart

```bash
pip install noirebox       # the ML engine ships inside the wheel (FR + EN)
pip install noirebox[pdf]  # + the DPO-ready PDF attestation (optional extra)
noirebox serve             # API on http://127.0.0.1:8768/docs
```

From source:

```bash
./start.sh          # venv + deps + tests + API on http://127.0.0.1:8768/docs
make demo           # the full story in one command (see below)
```

Or with Docker — no Python needed, the ML engine ships inside the image:

```bash
docker run -p 8768:8768 ghcr.io/slabbdev/noirebox:latest
# API + OpenAPI docs on http://127.0.0.1:8768/docs — data persists in ./data
```

Standalone demos:

```bash
make demo                # 100% real: micro-model → journal → auditor → caught pirate
make demo-mcp            # NoireBox as an MCP tool (agent protocol)
.venv/bin/python demo/demo_scan.py     # regex guardrail on 2 transcripts
.venv/bin/python demo/demo_tamper.py   # tampering → the chain explodes
```

Verify an export as a third party (auditor, DPO, client):

```bash
curl -s http://127.0.0.1:8768/api/v1/export > export.json
.venv/bin/python verifier/verifier.py export.json   # exit 0 = chain intact
```

> The verifier needs the NoireBox package on the auditing machine —
> `pip install noirebox` is enough (no model, no framework).

## Chain timestamping — outside witnesses you choose (RFC 3161 + Bitcoin)

The journal proves integrity, but *when* was it sealed? A server announcing
its own dates is the suspect writing its own report. And the threat model
had one open gap: an operator holding the private key could **regenerate the
whole chain** with valid signatures.

Anchoring closes it — with **witnesses you choose, in layers**
([ADR 006/008/009](docs/ADRs.md)):

- **Qualified eIDAS TSAs** (Universign, Certigna…) — a qualified timestamp
  carries a *legal presumption* (art. 41): the date and the integrity of the
  sealed data are presumed until challenged;
- **Public TSAs** (DigiCert, FreeTSA…) — free, immediate, independent
  organizations; the auditor verifies against **roots pinned in this
  repository** ([`verifier/tsa_roots/`](verifier/tsa_roots/)), never against
  a certificate the operator ships;
- **OpenTimestamps / Bitcoin** — a receipt no operator can forge: forging it
  means redoing the network's proof of work; verifying it is ~30 µs of
  SHA-256, valid as long as Bitcoin exists.

One `anchor` event carries all of them. Only the **32-byte head hash** ever
leaves (zero data, zero GDPR exposure). And anchoring is **retroactive**: one
external anchor seals the *entire* prior chain — a regenerated chain shows a
head the tokens don't cover, caught at verification time without any prior
external publication. Anchor regularly and the falsifiable window shrinks to
the tail since the last anchor.

```bash
export NOIREBOX_TSA_PROFILES='[
  {"name": "freetsa",  "url": "https://freetsa.org/tsr"},
  {"name": "bitcoin",  "kind": "ots"}]'
export NOIREBOX_TSA_ALLOWED_HOSTS=freetsa.org
curl -X POST localhost:8768/api/v1/anchors   # one call, both witnesses, the whole past sealed
noirebox audit-pack ./audit                  # the auditor's folder: export + report + Annexe IV §2(f)
```

A self-hosted OpenSSL TSA still ships for sovereign/offline deployments
(`make tsa`) — same trust boundary as the operator, documented as such.
Full regulatory mapping: [docs/COMPLIANCE-EU.md](docs/COMPLIANCE-EU.md).

## The bundled guardrail — one plugin, two engines

| Engine | Size | Languages | Role | Dependency |
|---|---|---|---|---|
| `regex` | ~0 | FR+EN | obvious cases, zero cost | none |
| `ml` | 243–293 KB | **fr** & **en** (`lang` param) | paraphrases the regex misses, local | scikit-learn |

**Architecture decision — [ADR 002](docs/ADRs.md)**: we evaluated Meta's
Llama Prompt Guard 2 (the industry classifier, ~90 MB) and **rejected it
knowingly**: gated license, torch/transformers as dependencies, and binary
output without an audit taxonomy. The ADR also documents the **integration
path** if you ever need it (adapter ≈ 40 lines behind the same engine
interface). The tier-2 judge stays a local LLM (`llama-guard3:1b` via
Ollama) — same binary we already ship, zero new deps.

## The real LLM scene (local Ollama)

A **real LLM** (qwen2.5:0.5b, 397 MB, local via Ollama — never committed,
fetched by `ollama pull`) receives the poisoned transcript:

```bash
brew install ollama && ollama serve && ollama pull qwen2.5:0.5b   # once
make demo-llm                                                     # the scene
```

Measured outcome (temperature 0, reproducible):
- **Without NoireBox**: the model rewrites the attacker's instructions into
  "its" own summary — competitor's email and `DROP TABLE utilisateurs`
  included. The attack succeeds.
- **With NoireBox**: 4 poisoned lines removed *before* the call, incident
  sealed in the journal, and the model's real output is clean.

See also [deploy/DEPLOIEMENT.md](deploy/DEPLOIEMENT.md) for €0 deployment
(instant cloudflared tunnel, permanent Hugging Face Space) or a €3–6/mo VPS.

## The ML micro-detector — trained in-repo, two languages, ~250 KB each

```bash
make train        # FR: gen_dataset.py (5,400 examples) → detector.joblib
make train-en     # EN: gen_dataset_en.py (5,400 examples) → detector_en.joblib
```

A new language is a dataset, not a rewrite: the trainer, the registry and
the API (`lang: "fr" | "en"`) are shared. Adding Spanish = one
`gen_dataset_es.py` + `ml/train.py --lang es`.

**Honest evaluation** (the part that earns credit in reviews):
- the test sets share templates with their train sets → accuracy 1.000
  measures consistency, not generalization;
- the generalization proof lives elsewhere: **held-out sentences** (slang,
  typos, never-seen formulations) are frozen in `tests/test_ml_guardrail.py`
  — in *both* languages — correct category detected, **zero false positives**
  on trap-clean sentences ("send the report to the accountant", "I rotated
  my password");
- the EN held-out suite caught a real weakness in v1 ("take orders from
  me" scored 0.37) → dataset extended → model retrained → suite green.
  That loop *is* the ML workflow, and it's in the git history.

| Artifact | Size |
|---|---|
| `models/detector.joblib` + `models/detector_en.joblib` (versioned) | 293 + 243 KB |
| `data/dataset.jsonl` + `data/dataset_en.jsonl` (versioned) | ~1.3 MB |

## Plugging NoireBox in — 3 real ways

**1. REST** (any language):

```bash
curl -X POST https://noirebox.example.com/api/v1/transcripts/scan \
     -H 'Content-Type: application/json' \
     -d '{"meeting_id": "MTG-42", "text": "<transcript>", "engine": "ml"}'
```

**2. Python SDK** (`noirebox/client.py`):

```python
from noirebox.client import NoireBoxClient
nb = NoireBoxClient("https://noirebox.example.com")
nb.scan("MTG-42", transcript)          # guardrail before the agent
nb.log_event("llm_output", {...})      # seal the agent's output
nb.verify()                            # check the chain
```

**3. MCP** (the agent protocol — Claude Desktop and every MCP client):
4 tools exposed (`noirebox_scan`, `noirebox_log_event`, `noirebox_verify`,
`noirebox_attestation`). Config (`claude_desktop_config.json`):

```json
{ "mcpServers": { "noirebox": {
    "command": "/path/to/noirebox/.venv/bin/python",
    "args": ["-m", "noirebox.mcp_server"] } } }
```

Stdio JSON-RPC implementation with no external SDK: the protocol stays
readable end to end (`demo/demo_mcp.py`).

## Use cases — any agent that "decides"

| Agent | What NoireBox brings |
|---|---|
| Meeting assistant (demo scenario) | provable notes + transcript anti-injection |
| Coding agent | immutable journal of executed actions (files, commands) |
| AI customer support | proof of what was promised to the client, when and why |
| Legal / medical RAG pipeline | traceability of sources used and outputs produced |
| Business copilots (finance, HR…) | exportable attestation for internal audit / DPO / client |

The **journal** is universal (free-typed events). The shipped **guardrail
corpus** specializes in FR meeting transcripts — extending it to another
domain = adding examples to the dataset and re-running `make train`.

## The code — core first, plugins after

```
noirebox/            ← package (≈ PSR-4 namespace)
├── chain.py         THE CORE: SHA-256 hash chain + Ed25519 signatures
├── store.py         THE CORE: append-only SQLite, parameterized queries, lock
├── attestation.py   THE CORE: signed digest of the chain state
├── anchors.py       THE CORE: RFC 3161 anchoring (TSA witness)
├── pdf_export.py    THE CORE: DPO-ready attestation PDF
├── main.py          FastAPI routes (the HTTP layer)
├── schemas.py       Pydantic DTOs (request validation)
├── client.py        Python SDK
├── mcp_server.py    MCP tools server (stdio JSON-RPC)
├── guardrail.py     PLUGIN: 4 FR/EN attack categories caught by regex
├── ml_guardrail.py  PLUGIN: trained micro-models (fr + en, ~250 KB each)
└── llm_agent.py     PLUGIN DEMO: real Ollama agent behind the guarded pipeline
```

## API

| Route | Auth | Role |
|---|---|---|
| `POST /api/v1/token` | — | Exchange `client_id`/`client_secret` for a 1 h JWT |
| `POST /api/v1/events` | 🔒 | Record an event (prompt, output, eval…) |
| `GET /api/v1/events` | 🔒 | Paginated event list |
| `GET /api/v1/verify` | open | Verify the chain in place |
| `POST /api/v1/transcripts/scan` | 🔒 | Guardrail: detect injections, journal the incident |
| `GET /api/v1/attestation` | open | Signed attestation of the current state |
| `GET /api/v1/attestation.pdf` | open | Attestation as a DPO-ready A4 PDF |
| `POST /api/v1/attestation/verify` | open | Verify a submitted attestation |
| `POST /api/v1/anchors` | 🔒 | RFC 3161 anchor: seal the current chain head with a TSA |
| `GET /api/v1/export` | 🔒 | Full auditable export |

🔒 = requires `Authorization: Bearer <token>` when `NOIREBOX_CLIENTS=id:secret,…`
is set; **verification routes stay open by design** — one never locks the
verification ([ADR 004](docs/ADRs.md)). Rate limit: 60 req/min per client.

## Bundled plugin — v0 attack taxonomy

- `instruction_override` — "ignore all instructions", "you are now…"
- `data_exfiltration` — "send … to email@… / https://…"
- `pii_request` — "give me the passwords / banking data"
- `tool_abuse` — "run DROP TABLE / rm -rf / curl"

See `corpus/attaques.json`. Extending = add regex patterns or dataset
examples, then `make train`.

## Tests

107 tests: cryptography (tampering, reordering, wrong key), regex and **ML
guardrails on held-out sentences in FR and EN**, API agent, MCP server, SDK
client against a **real uvicorn server** (ephemeral port), real LLM agent
(skipped if Ollama is absent — never simulated), **OAuth2 JWT auth + rate
limiting + DPO-ready PDF attestation + RFC 3161 anchoring against a real
local TSA (incl. the insider chain-regeneration attack)**, and the full
third-party verifier contract. Everything replays locally: `make test`
re-trains both language models and runs the full suite.

**Consuming AI-agent decisions in your own pipeline?** Gate your builds on
the integrity of the journal — the verifier ships as a GitHub Action
([Marketplace](https://github.com/marketplace/actions/noirebox-verify)):

```yaml
- uses: slabbdev/noirebox-verify@v1
  with:
    export-path: export.json
    noirebox-ref: v0.5.0   # pin the verifier ref — reproducible audits
```

## Roadmap

- [x] OAuth2 (JWT bearer) + rate limiting — [ADR 004](docs/ADRs.md)
- [x] PDF attestation export for DPOs — [ADR 005](docs/ADRs.md)
- [ ] Local LLM judge for doubtful cases — tier 2 of [ADR 001](docs/ADRs.md)
- [x] RFC 3161 timestamping of the chain head — [ADR 006/007](docs/ADRs.md), self-hosted TSA included
- [x] **Fleet anchoring (Merkle)** — `noirebox/merkle.py`: one TSA seal covers
      N journals (Certificate-Transparency pattern); inclusion proofs are
      ~log2(N) hashes, verified offline — see `make demo-fleet`
- [x] **Reconciliation plugin v0** — invariants over the journal ("every decision
      must have an outcome"): `noirebox/reconcile.py` + CLI
      `noirebox reconcile --fail-on-findings`, schema from
      [issue #3](https://github.com/slabbdev/noirebox/issues/3) (community
      request), pattern sketch in [`demo/demo_payout.py`](demo/demo_payout.py)
- [ ] Fleet hub: scheduled aggregation of many instances (console, alerting)
- [x] **Multi-witness anchoring + auditor-pinned roots** — `NOIREBOX_TSA_PROFILES`, egress allowlist, `verifier/tsa_roots/` ([ADR 008](docs/ADRs.md))
- [x] **OpenTimestamps witness** — a Bitcoin-anchored receipt rides in the same anchor event ([ADR 009](docs/ADRs.md))
- [x] **AI-Act vocabulary + audit-pack** — art. 12(3) builders, `noirebox audit-pack` ([ADR 010](docs/ADRs.md))
- [ ] Prometheus + Grafana metrics
- [ ] HSM/KMS private key migration ([threat model](docs/THREAT-MODEL.md))
- [x] Product page rebuilt for GitHub Pages — premium dark landing in
      [`docs/`](docs/index.html), auto-deployed by
      [`.github/workflows/pages.yml`](.github/workflows/pages.yml)
      (enable Pages → Source: GitHub Actions)

## Support

NoireBox is free and MIT — verification included, forever. If it saved you
time (or a compliance headache), a coffee is the best way to say it helps:

<a href="https://buymeacoffee.com/samlabbe"><img src="docs/bmc_qr.png" width="160" alt="Buy Me A Coffee — scan to support NoireBox"></a>

*Scan or click — [buymeacoffee.com/samlabbe](https://buymeacoffee.com/samlabbe)*

## License

MIT — see [LICENSE](LICENSE).
