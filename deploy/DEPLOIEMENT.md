# 🚀 Deploying NoireBox — honest options, from $0 to VPS

> Principle: the repo is around 2 MB (code + FR + EN micro-models), with reproducible datasets via
> `make train` (seed 42).
> The Ollama LLM (~400 MB) never ships in the repo or demo server — it lives on the machine
> running `make demo-llm`.

## Overview

| Option | Cost | Public URL | Constraints | For what |
|---|---|---|---|---|
| **cloudflared tunnel** | $0, no account | `xxx.trycloudflare.com` (ephemeral) | your Mac must stay on | live demos during calls / video calls |
| **Hugging Face Spaces** | $0, free account | permanent | sleeps after inactivity (wakes in ~30s), free CPU | shareable public link |
| Koyeb / Render (free tier) | $0 | permanent | card may be required, also sleeps | alt to HF |
| Scaleway / OVH VPS | $3–6/month | permanent, yours | you manage it (or just Docker) | when real users exist |
| Scaleway serverless / K8s | pay-per-use | — | monitor billing | later — oversized here |

## Option 1 — instant tunnel ($0, ~2 minutes)

```bash
./start.sh &                                   # API on 127.0.0.1:8768
cloudflared tunnel --url http://localhost:8768 # immediate public HTTPS URL
```

The displayed URL (`https://…trycloudflare.com`) is reachable from anywhere while the command runs.
It is perfect for showing the API in a call: a client opens `…/docs` and scans a transcript from the browser.

## Option 2 — Hugging Face Spaces ($0, permanent URL — recommended for demos)

1. Create an account on huggingface.co → New Space → **Docker** (free CPU).
2. Copy into the Space: `Dockerfile` (already ready), `noirebox/`, `requirements.txt`, `corpus/`.
3. Add a Space `README.md` with the frontmatter (template: `deploy/hf-space-README.md`).
4. Push → automatic build → `https://huggingface.co/spaces/<your-handle>/noirebox`.

The Space runs `uvicorn noirebox.main:app --port 8768` as-is (the port is declared in the frontmatter).
The ML model (293 KB) is committed to the repo, so no retraining is required at deployment time — it remains reproducible via `make train` if needed.

## Option 3 — VPS when the project has real users

Scaleway / OVH from about $3/month: `docker compose up -d` and you're done
(volume `./data` for the database and private key). This is justified only when a VPS is genuinely needed — not before.

## What deployment does not change

Third-party verification remains local: `verifier/verifier.py export.json`
recomputes the chain **offline** — an auditor does not need access to the server, and that is the project’s core principle.

---

## Custody vs anchoring — mappez vos frontières de confiance (ADR 022)

L'ancrage (TSA/OTS) répond à **quand** et est structurellement indifférent au
**quoi**. La custody répond au **quoi** : quand une contrepartie existe, c'est
SON record qui fait foi — écrit par quelqu'un avec une raison de désaccord.
La règle de design : chaque action conséquence est mappée à sa frontière de
confiance.

| Action de l'agent | Contrepartie existe ? | Grade de preuve à exiger |
|---|---|---|
| Paiement, transfert | Oui (la banque, le PSP) | **Custody** : le flux de la contrepartie + réconciliation croisée (`noirebox reconcile`) |
| Email, notification client | Oui (le fournisseur email) | Custody : leurs delivery/bounce events, réconciliés avec votre décision |
| Compte rendu interne, décision de scoring | Non (first-party bout en bout) | **Anchoring** : ancrage RFC 3161/OTS — et divulguez le grade : *operator-held, anchored, no second party* |
| Journal d'audit lui-même | Non | Anchoring + cadence (le timer auto-anchor) |

Divulguez le grade dans les payloads et les docs : le règlement (AI Act
art. 12) demande le plus faible exprès — un outil qui nomme son grade est
auditable par sa propre documentation.

## Ce que coûte la réconciliation (nommons la facture)

La réconciliation multi-flux n'est pas gratuite — et un outil qui ne vend
que le bénéfice ne vend pas honnêtement. Les coûts réels :

1. **Un store de plus** — chaque flux avec preuve a son propre journal
   (SQLite + clé). Un fichier, une cadence de sauvegarde, une retention.
2. **Une clé de plus par écrivain** — « a name, not a role » (ADR 021) :
   la rotation et la custody des clés se multiplient par écrivain, pas par
   instance.
3. **Une cadence d'ancrage par flux** — le timer auto-anchor consomme des
   tokens TSA (les TSAs publiques rate-limitent ; qualifiées = facturées).
4. **La latence de réconciliation** — croiser les flux a une fenêtre :
   un gap n'est visible qu'après l'échéance (`expected_by`) ou au rapport.
5. **La complexité du schéma** — invariants, probes négatives, pairing :
   du code à maintenir, testé comme le reste (les probes qui ne mordent
   plus sont des findings).

**Et une ligne qui vaut un paragraphe** (le close du fil sinarezaei, Oct 8) :
l'exécuteur vérifie la **SIGNATURE** du reçu, pas sa présence. Un contrôle où
l'écrivain et l'exécuteur partagent un même domaine de confiance, c'est le test
d'indépendance (ADR 021) une couche plus bas.

Le bénéfice — un désaccord de records qui devient une preuve datée — vaut
ces coûts quand une contrepartie existe. Sans contrepartie, l'ancrage seul
suffit : ne payez pas pour la custody que vous n'avez pas à prouver.
