# NoireBox — Analyse complète du projet

> **Date :** 1er octobre 2026 · **Commit analysé :** `28f9ab9` (main, propre, à jour avec origin)
> **Méthode :** lecture intégrale du code (~4 000 lignes du package + verifier + TSA), des 14 documents,
> des 5 workflows CI, de l'historique git complet, des branches, des données runtime, + suite de tests
> exécutée + journal de production vérifié via MCP. Chiffres et constats vérifiés à la source.
> **Statut de ce document :** base de travail centrale du projet — tout nouveau chantier part d'ici.
>
> **✅ MISE À JOUR 2026-10-04 — la passe de correction est exécutée et validée**
> (voir §11 pour le journal de la passe) : P0-1/P0-2, P1-7/P1-8, P2-10 et le lot P2 sont
> corrigés, les docs sont re-syncés, la release 0.7.0 est préparée (non taggée — tag et
> publish manuels après migration du PyPI trusted publisher), le journal de prod est
> ré-ancré vers un témoin externe. Les items §8 gardent leur marque ⚠️ d'origine avec
> leur statut à jour ; ce qui reste ouvert est listé en §11.
> Pour le rafraîchir : re-exécuter la suite de tests (`NOIREBOX_DB=/tmp/t.db make test`), relire
> CHANGELOG + git log, re-vérifier le journal (section 6).

---

## 1. Synthèse exécutive

NoireBox est la « boîte noire » des agents IA : un journal inaltérable (chaîne SHA-256 + signatures
Ed25519), un guardrail anti-injection FR/EN embarqué, un ancrage horodaté multi-temoins (RFC 3161,
OpenTimestamps/Bitcoin), une attestation exportable vérifiable hors-ligne par un tiers, et une
couche intégration (API REST, SDK Python, MCP, CLI, hooks) — le tout positionné sur la conformité
européenne (RGPD art. 5(2), AI Act art. 12/19/26/55, eIDAS art. 41). Le projet est solo, fait en
12 jours (19 → 29 septembre 2026), sur 3 versions publiées (0.4.0, 0.5.0, 0.6.0) et **13 ADRs**.

**Où on en est vraiment (au 2026-10-01) :**

- ✅ Le cœur est solide et remarquablement documenté (chaque décision non évidente renvoie à un ADR).
- ✅ Journal de production **INTACT** : 4 460 événements, chaîne vérifiée à l'instant (section 6).
- ⚠️ Le travail ADR 012/013 (scellement de trajectoires, journaux par projet, plugins agent) est
  fusionné sur main mais **non released** : pyproject reste à 0.6.0, CHANGELOG sous `[Unreleased]`.
- 🔴 **1 vraie faille de sécurité** dans la feature auth (secret JWT dérivable de la clé publique — §8.1).
- 🔴 **Le code et les docs divergent** sur un point majeur : la 4e vue Flight Deck « TRAFFIC » et le
  curseur `since_seq` sont annoncés (CHANGELOG, SPECS) mais **le PR #18 n'a jamais été fusionné** (§8.2).
- 🟠 Hygiène de release en dérive : 5 numéros de version cohabitent, compte de tests faux partout,
  landing page périmée, journal non ancré depuis 4 jours (§8).

Le prochain jalon structurant est une **release 0.7.0** qui débloque tout : elle force la migration
PyPI, la mise en version cohérente, la réconciliation des docs, et le sort du radar TRAFFIC (§10).

---

## 2. Le produit en une page

**Pitch.** « Your AI agent writes meeting notes that bind your clients. Eighteen months from now —
who can prove what it *exactly* produced, and why? » NoireBox scelle chaque décision d'un agent dans
un journal inaltérable, flag les transcripts empoisonnés avant qu'ils n'atteignent l'agent, et
exporte une attestation que n'importe qui vérifie hors-ligne — sans faire confiance à l'opérateur.

**Positionnement honnête et défendable** (README « Honest positioning ») : Langfuse/LangSmith =
observabilité modifiable après coup, rien de présentable à un auditeur ; Garak/PyRIT/promptfoo =
red-teaming offline, pas de journal ; halo-record/gate-oc-audit = journaux hash-chained pour agents
de code, pas d'attestation tierce, pas de français. La différenciation revendiquée : **le modèle
Certificate Transparency appliqué aux journaux d'agents** (flotte de journaux, une racine signée
TSA, preuves d'inclusion hors-ligne) — « to our knowledge, no other agent-audit tool does this ».

**Marché.** Europe d'abord : le calendrier AI Act post-Digital Omnibus (Reg. (EU) 2026/1744) met
l'obligation de logging art. 12 à **2 décembre 2027** (14 mois), amendes jusqu'à 35 M€ / 7 %.
`docs/COMPLIANCE-EU.md` documente le whitespace marché (vérifié 25/09) : personne ne possède
l'intersection « preuve d'intégrité des logs d'agents IA ». Ambition déclarée : devenir
l'instrument de fait (comme Sigstore), pas une certification.

**Architecture produit (verrouillée par ADRs).** Le journal EST le produit (domain-agnostic,
agent-agnostic, langue-agnostique : un event = un `type` libre + un payload) ; le guardrail n'est
qu'un producteur d'événements parmi d'autres, remplaçable (ADR 003) ; la prévention varie par
stack, **la preuve est universelle**. Un NoireBox par agent/service (un SQLite, une paire de clés,
une chaîne) ; la couche flotte agrège des têtes de chaîne (32 octets), jamais des données.

---

## 3. Ce qui existe — inventaire complet par domaine

### 3.1 Cœur cryptographique (le produit)

| Module | Rôle | Points clés vérifiés |
|---|---|---|
| `noirebox/chain.py` (168 l.) | Chaîne de hachage + Ed25519 | `canonical()` JSON déterministe ; hash = SHA-256 sur {seq, ts, type, payload, prev_hash} ; clé créée `O_CREAT\|O_EXCL` 0600 ; convention maison **None = intact, str = raison** ; genesis = 64 zéros |
| `noirebox/store.py` (148 l.) | SQLite append-only | WAL + retry 50×0.1 s sur le switch de mode ; `BEGIN IMMEDIATE` + lock → **scellement multi-processus sans gap** (testé cross-process) ; timestamps ISO UTC ms ; permissions 0600 y compris sidecars |
| `noirebox/attestation.py` (44 l.) | Attestation signée de l'état | Re-vérifie la chaîne avant de signer ; {head_seq, head_hash, total_events, chain_valid, event_types} + signature Ed25519 |
| `verifier/verifier.py` (212 l.) | Vérificateur tiers autonome | Recalcule toute la chaîne + croise l'attestation + **vérifie chaque token d'ancrage** (racines épinglées `verifier/tsa_roots/` : digicert.pem, freetsa.pem ; politique append-only) ; exit 0/1/2 ; détecte la régénération insider (head cité ≠ chaîne) |

### 3.2 Ancrage horodaté extérieur (ferme le trou « insider avec la clé »)

- **RFC 3161** (ADR 006, v0.3.0) : `POST /api/v1/anchors` — seul le hash de tête sort (zéro GDPR) ;
  token + certificat scellés dans le journal comme événement `anchor` ; ancrage **rétroactif** (un
  ancrage scelle toute la chaîne passée).
- **TSA auto-hébergée** (ADR 007) : `make tsa`, OpenSSL root + leaf (EKU timeStamping critique),
  port 3318, pour déploiements souverains/offline — même périmètre de confiance que l'opérateur, documenté comme tel.
- **Multi-TSA + racines épinglées côté auditeur** (ADR 008) : `NOIREBOX_TSA_PROFILES` (au moins une
  TSA qualifiée eIDAS pour la présomption légale art. 41 + TSAs publiques rotatives) ; l'auditeur
  vérifie contre `verifier/tsa_roots/`, jamais contre un certificat fourni par l'opérateur ;
  **egress allowlist** fail-closed, refus link-local (cloud metadata), pas de redirects. DigiCert +
  FreeTSA validés en live.
- **OpenTimestamps / Bitcoin** (ADR 009) : profil `{"name":"bitcoin","kind":"ots"}` — forgeable
  seulement en refaisant le PoW du réseau ; vérification ~30 µs ; reçus pending enregistrés sans
  jamais faire échouer un export.
- **Merkle flotte** (`noirebox/merkle.py`, 106 l., ADR 008) : arbre à feuilles triées-dédupliquées,
  preuves ~log2(N) vérifiables hors-ligne. **⚠️ Non câblé au produit** : aucune route/CLI ne
  l'utilise ; la vie du hub existe seulement dans `demo/demo_fleet.py` (convention, pas produit).

### 3.3 API, dashboard, intégrations

- **API FastAPI** (`noirebox/main.py`, 220 l.) : 12 routes — health, token (OAuth2 client-credentials
  → JWT 1 h HS256), events POST/GET (limit ≤ 1000), verify (ouverte **par design**, ADR 004),
  activity (heatmap), dashboard, transcripts/scan, attestation + attestation.pdf + attestation/verify,
  export, anchors. Schéma export : `{format_version: 1, service, public_key, events[], attestation}`.
- **Auth optionnelle** (ADR 004, v0.2.0) : activée par `NOIREBOX_CLIENTS=id:secret,…` ; sinon ouverte
  (« la sécurité est un choix de déploiement, jamais un accident ») ; rate limit glissant 60
  req/min/client en mémoire ; comparaison de secret à temps constant. **⚠️ Mais voir la faille §8.1.**
- **Dashboard Flight Deck** (`noirebox/dashboard.py`, 561 l.) : vue HTML/JS/CSS read-only zéro
  dépendance, 3 vues switchables (DECK colonne vertébrale de la chaîne / VAULT enveloppes scellées /
  TAPE ticker), heatmap d'activité type GitHub (modes daily/weekly/cumulative, seuils = quartiles),
  tableau part départ/arrivée (réconciliation), panneau dernier témoin. Refresh 10 s, échappement
  systématique via `esc()`.
- **SDK Python** (`noirebox/client.py`, 49 l.) : mince wrapper httpx (health, log_event, scan,
  verify, attestation, export), timeout 15 s (cold-start ML). **Pas de support du token JWT** —
  inutilisable sur instance authentifiée.
- **Serveur MCP** (`noirebox/mcp_server.py`, 131 l.) : stdio JSON-RPC sans SDK, protocole
  2024-11-05, 4 outils : `noirebox_scan`, `noirebox_log_event`, `noirebox_verify`,
  `noirebox_attestation`. Entrypoint `noirebox-mcp` pour tout client MCP.
- **CLI** (`noirebox/cli.py`, 238 l.) : `serve`, `reconcile`, `audit-pack`, `seal-trajectory`
  (fichier ou `--rollout DIR`, formats `model-io|session-transcript|generic-jsonl|auto`), `hook
  tool-use|session-end`, `seal <type> <json>`, `verify`, `locate`.
- **Hooks génériques** (`noirebox/hookcli.py`, 104 l., ADR 013) : JSON du hook sur stdin → un
  événement scellé ; contrat best-effort (**ne bloque jamais l'agent**, exit 0 toujours, échecs
  bruyants sur stderr, rien de scellé depuis un payload illisible) ; kill-switch `NOIREBOX_HOOK_DISABLE=1` ;
  preview tronquée à 800 caractères (minimisation).

### 3.4 Guardrail embarqué (un plugin de démonstration du contrat)

- **Regex** (`noirebox/guardrail.py`, 104 l.) : 4 familles d'attaques — `instruction_override` (0.9),
  `data_exfiltration` (0.95), `pii_request` (0.8), `tool_abuse` (0.85) ; FR-majoritaire avec un peu
  d'EN ; excerpt ≤ 120 chars + offsets ; tri par position. **⚠️ Pas de paramètre `lang`** — le
  `lang` de l'API est silencieusement ignoré pour `engine="regex"`.
- **ML** (`noirebox/ml_guardrail.py`, 100 l. + `ml/`) : TF-IDF (word 1–2 grams ≤ 20k + char_wb 3–5
  grams ≤ 30k) → LogisticRegression(C=4.0) ; datasets générés **seed 42** (5 400 exemples × FR/EN,
  20 % désaccentués en FR) ; modèles versionnés **293 KB (fr) + 243 KB (en)**, force-inclus dans la
  wheel (recherche : `noirebox/models/` dans la wheel, puis `models/` du repo). Franchise
  documentée : accuracy 1.0 = consistance sur données auto-similaires, la preuve de généralisation
  vit dans les phrases held-out figées dans `tests/test_ml_guardrail.py` (FR **et** EN, zéro faux
  positif sur pièges propres). Un nouvel langue = un générateur de dataset + `make train`.
- **Juge LLM** (tier 2 de l'ADR 001, `llama-guard3:1b` via Ollama) : **toujours en roadmap**, pas commencé.
- **Pipeline gardé** (`noirebox/llm_agent.py`, 125 l.) : scan → scellement `incident` → filtrage
  des lignes compromises par recouvrement d'offset → scellement `llm_call` (texte nettoyé) → LLM
  réel (Ollama qwen2.5:0.5b) → scellement `llm_output`. Scène démontrée : sans NoireBox l'attaque
  réussit (l'email concurrent et le DROP TABLE passent dans « le » résumé), avec NoireBox 4 lignes
  partent avant l'appel.

### 3.5 Vocabulaire AI Act + réconciliation

- **`noirebox/aiact.py` (203 l., ADR 010)** : builders validés pour art. 12(3)(a)–(c) (`ai_use`),
  12(3)(d)/14(5) (`ai_verification`), 55(1)(c)/73 (`ai_incident`) ; **inputs scellés en sha256
  seulement** (minimisation par construction) ; `noirebox audit-pack <dir>` = dossier auditeur
  (export.json + verifier_report.json + `ANNEXE-IV-2f.md` générée depuis les faits du journal).
- **`noirebox/reconcile.py` (206 l., plugin v0.1, issue #3)** : invariants métier sur le journal —
  appariement `policy_decision` ↔ `provider_response` par clé de corrélation, deadlines par
  événement (`expected_by` > `expected_within` > `within`), statuts `matched / late / pending /
  unconfirmed / open_gap / orphan_outcome / unauthorized` ; le rapport est **scellé** comme
  événement `reconciliation` (le journal audite son auditeur) ; CLI `noirebox reconcile
  --fail-on-findings`.

### 3.6 Scellement de trajectoires + journaux par projet (la vague ADR 012/013, non released)

- **ADR 012 — `model_trajectory`** : le flight recorder de l'agent devient preuve. Chaîne de digests
  à engagement d'ordre (`d_i = sha256(d_{i-1} + sha256(canonical(record)))`, seedée sur GENESIS) —
  réordonner les appels accuse ; `truncated_tail` honnête pour session live ; payload = résumé
  seulement (le contenu ne peut pas entrer par construction) ; le sceau nomme son scelleur
  (`source: {tool, version}`) — première brique de l'identité du scelleur ; vérification =
  recomputation ; ligne illisible en milieu de fichier = erreur dure, écriture incomplète en queue =
  rapportée et scellée telle quelle.
- **ADR 013 — formats par forme, pas par produit** : `model-io` / `session-transcript` /
  `generic-jsonl` sniffés par forme ; métadonnées enveloppe seulement ; découverte du journal :
  `NOIREBOX_DB` > plus proche ancêtre `.noirebox/` > création `./.noirebox/journal.db` (0700/0600)
  — **un projet = un journal**. Limite honnête posée : un agent sans hooks/MCP/log ne peut pas être
  enregistré.
- **`noirebox/trajseal.py` (157 l.)** : mode démon `--rollout` — scan throttlé (défaut 10 min),
  glob `model-io-*.jsonl`, **confinement** (symlink sortant du répertoire = refusé), dédup par
  digest de contenu **contre le journal lui-même** (le cache perdu ne peut pas cacher un double
  sceau), cache `<db>.trajstate`.
- **Plugins** : `plugins/noirebox/` (Agent, v0.7.0 : 2 skills, 4 commandes, hook PostToolUse, MCP)
  et `plugins/claude/noirebox/` (Claude Code, v0.7.0 : + hook SessionEnd). Invariant documenté :
  hook + MCP + CLI écrivent **un seul** SQLite avec **une seule** clé.

### 3.7 Écosystème de livraison

- **PyPI** : `pip install noirebox` (0.6.0), extras `[pdf]` (reportlab) et `[ots]` ; workflow
  pypi.yml en **trusted publishing OIDC** (tags `v*`) — ⚠️ **à migrer vers l'org `noirebox` avant
  le prochain tag**, sinon le publish échoue (note CHANGELOG + workflow).
- **Docker/GHCR** : `ghcr.io/noirebox/noirebox`, python:3.12-slim, HEALTHCHECK sur `/api/v1/verify`,
  rebuild hebdo (cron lundi) ; ⚠️ label OCI encore `slabbdev/noirebox` (Dockerfile:4).
- **GitHub Action `noirebox-verify`** (repo séparé, org noirebox) : consommateurs plantent leur CI
  sur l'intégrité du journal (`uses: noirebox/noirebox-verify@v1`, pin `noirebox-ref: v0.6.0`).
- **GitHub Pages** : landing produit EN (`docs/index.html`) + FR (`docs/fr.html`) déployée
  automatiquement (pages.yml).
- **CI (5 workflows)** : `ci.yml` (ruff + **re-entraînement des 2 modèles** [preuve de
  reproducibilité] + pytest, push + PR) ; `security.yml` (Bandit `-ll`, échec MEDIUM+ ; baseline
  316 findings LOW justifiés dans `docs/SECURITY-BASELINE.md`, 0 MEDIUM/0 HIGH) ; `pypi.yml` ;
  `docker-publish.yml` ; `pages.yml`.

### 3.8 Documentation (le point fort du projet)

14 documents, tous à jour sauf contradiction ponctuelle (§8) :

| Document | Contenu |
|---|---|
| `docs/ADRs.md` | **13 ADRs**, tous « decided/implemented » : 001 garde-fou à étages (regex→ML→LLM juge), 002 rejet motivé de Llama Prompt Guard 2, 003 détecteurs tiers = chemin documenté, 004 OAuth2 optionnel par config, 005 PDF preuve humaine / JSON machine, 006 ancrage RFC 3161, 007 TSA auto-hébergée en chaîne root+leaf, 008 multi-TSA + racines épinglées, 009 OTS/Bitcoin, 010 vocabulaire AI Act + audit-pack, 011 provenance du contenu (anti model-collapse, convention + démo, cite Shumailov et al., Nature 631 (2024)), 012 scellement de trajectoire, 013 scellement transcript-agnostique + journaux par projet |
| `docs/SPECS.md` | « Source de vérité — toute divergence code/spec est un bug » ; modèle de données, algo de vérification tiers en 6 étapes strictes, contrat d'incident, 11 routes, benchmarks, limites connues |
| `docs/THREAT-MODEL.md` | STRIDE simplifié, 9 acteurs (injection transcript, insider méthodique, **insider avec la clé** [fermé v0.3.0], attaquant réseau [fermé v0.2.0], attaquant du modèle [probabiliste ⚠️], opérateur malhonnête, auditeur externe, **source mensongère** [hors périmètre, ajouté après le lancement]) ; hors scope v0 assumé : disponibilité, chiffrement des payloads, HA, compromission totale du host |
| `docs/COMPLIANCE-EU.md` | Dossier réglementaire complet post-Digital Omnibus : calendrier AI Act, mapping art. 12/19/26/55/72-73, RGPD 5(2)/15/20/22/30/32/33-34/35, eIDAS art. 41 + QTST françaises, angle CNIL, whitespace marché |
| `docs/VULGARISATION.md` | Explication 10 sections « peinture sèche » prête pour infographies (⚠️ dit 4 000 exemples au lieu de 5 400) |
| `docs/ROADMAP-PLUGINS.md` | Écosystème intégrations : P0/P1 faits (ADR 013, plugin Claude), P2 ouvert (extension VSCode), P3 (matrice docs clients MCP) |
| `docs/SECURITY-BASELINE.md` | Registre Bandit : 316 findings LOW, chaque classe justifiée |
| `deploy/DEPLOIEMENT.md` + `deploy/hf-space-README.md` | 4 chemins de déploiement honnêtes : tunnel cloudflared 0 €, HF Space Docker 0 €, Koyeb/Render, VPS Scaleway/OVH 3–6 €/mois |
| `marketing/showhn-post.md` + `dailydev-post.md` | Packs de lancement Show HN (lundi 28/09) + daily.dev préparés, rebuttals rédigés — **checklists non cochées, aucun post-mortem dans le repo** |

### 3.9 Démos (10 scripts) et corpus

`demo_live.py` (scène flagship 4 actes), `demo_mcp.py`, `demo_ollama.py` (LLM réel),
`demo_fleet.py` (3 boîtes, 1 sceau, 1 falsification), `demo_payout.py` (réconciliation + 2 modes
de défaillance), `demo_provenance.py` (ADR 011), `demo_scan.py`, `demo_tamper.py` (l'explosion de
la chaîne), `demo_trajectory.py` (ADR 012), `bench.py` (sealing 2 000 appends + vérification
médiane de 7 runs sur export 100 événements). Corpus : `corpus/attaques.json` (taxonomie v0),
`transcript_poisonne.json` (REU-2026-0143, 1 attaque par famille) et `transcript_propre.json`
(négatif). Tous locaux sauf Ollama.

---

## 4. Chronologie — 12 jours de construction

| Phase | Dates | Contenu |
|---|---|---|
| Genèse + durcissement | 21–22/09 | Commit initial, CI, Docker/GHCR, badges honnêtes |
| Polish de lancement | 23/09 | Landing page, quickstart PyPI, fix timeout SDK (trouvé par la « simulation d'étranger ») |
| Ère 0.4.0 | 23–24/09 | Réconciliation v0 (issue #3 — demande communautaire), démo payout, PDF en extra, release **0.4.0** |
| Flight Deck + revue sécurité | 25/09 | Dashboard 3 vues, durcissement PR #5 (scellement atomique cross-process), journal red-team |
| Ère ADR 008–010 | 26/09 | Multi-TSA (**v0.5.0**), plugin Agent source, OTS (ADR 009), AI Act (ADR 010), gate Bandit, release **0.6.0** |
| Vague refactor/PR | 26–27/09 | Refactor intent-first (#13), pipeline gardé en CI sans Ollama (#14), ADR 011 provenance (#16), heatmap (#17), acteur « source mensongère » (#19), `make bench` (#20), **migration org noirebox** (#21), re-sync SPECS (#24) |
| Ère ADR 012/013 (non released) | 28–29/09 | Scellement de trajectoire (PR #26), couche intégration + journaux par projet + plugins (PR #28). **Dernier commit : 29/09 — rien depuis.** |

Tags : `v0.4.0`, `v0.5.0`, `v0.6.0`. Le travail 0.7.x (ADRs 012/013, plugins 0.7.0) dort sous
CHANGELOG `[Unreleased]`.

---

## 5. Qualité : tests, CI, benchmarks

- **163 fonctions de test réelles** dans 23 fichiers (compté : `grep -rEh "def test_" tests/*.py | wc -l`).
  Couverture vérifiée module par module, y compris le verifier, MCP, locate, trajseal, hookcli,
  réconciliation, auth+rate-limit+PDF contre serveur réel, TSA réelle locale avec **l'attaque de
  régénération insider**. Skips proprement cloisonnés (Ollama / openssl / `ots` CLI).
- **Suite exécutée le 2026-10-01** (venv Python 3.14 local, `NOIREBOX_DB=/tmp`) : **158 passed,
  4 skipped, 1 failed** — le failed est `test_client.py::test_scan_detects_regex_and_ml_engines`,
  flaky sous charge (échec httpx réseau sur le serveur uvicorn éphémère ; **passe isolément en
  1.9 s**). CI sur Python 3.12 est la référence.
- **Pas de coverage**, pas de matrix Python (≥ 3.11 requis, 3.11 jamais testé), Docker publié sans
  gate CI, pas de retry CI sur les tests sensibles au port/timing.
- **Benchmarks** (`make bench`, SPECS §6, 27/09, M-series) : regex 0.10 ms / 7 lignes ; ML 9.2 ms /
  7 lignes (~1.3 ms/ligne) ; append scellé 0.18 ms ; vérification complète 100 événements 45 ms.
  Les résultats de bench ne sont pas persistés nulle part (impression stdout seulement).
- **Reproducibilité ML** : seed 42 partout, CI re-génère datasets + re-entraîne avant pytest.
  Nuance relevée : la CI ne vérifie pas que les `models/*.joblib` commités correspondent au dataset
  commité (un modèle périmé passerait la CI et casserait chez les consommateurs pip).
- Zéro TODO/FIXME/HACK dans le codebase (le seul « BUG: » est un garde-fou de test attendu-échouant
  dans `demo_fleet.py:70`).

---

## 6. État runtime (vérifié le 2026-10-01 via les outils MCP)

- **Journal de production `data/noirebox.db`** : **INTACT** — `{"valid": true, "nb_events": 4460}`.
  Distribution : `agent_tool_use` 4 412 (le plugin scelle la session Agent en cours), `test` 38
  (⌚ pollué par les tests du radar 27/09), `decision` 4, `anchor` 3, `incident` 2, `llm_output` 1.
- **Ancrages** : seq 517 (26/09, freetsa), seq 1184 + 1247 (27/09, TSA auto-hébergée). **⚠️ 3 212
  événements (4 jours) sans ancrage** — la fenêtre falsifiable est la queue entière depuis le 27/09.
- **Attestation live** (17:21 UTC) : head_seq 4460, `chain_valid: true`, Ed25519 vérifiée.
- `data/redteam.db` (1 657 événements, dernier ancrage 25/09) : journal de la revue sécurité, dormant.
- `dist/` : artifacts 0.4.0 périmés. Attestations/export figés au 24 et 27/09.
- Le plugin installé dans l'environnement Agent local est le cache `dev-noirebox/noirebox 0.1.0`,
  loin derrière le 0.7.0 du repo (état d'environnement, pas du repo).

---

## 7. Ce qui est prévu — roadmap consolidée (toutes sources croisées)

**Checkboxes ouvertes des README (EN/FR identiques) :**
1. **Juge LLM local** pour cas douteux — tier 2 ADR 001 (`llama-guard3:1b` via Ollama) ; aussi
   actor 6 du threat model, « Planned » du CHANGELOG 0.6.0.
2. **Fleet hub** : agrégation programmée de N instances (console, alerting) — le hub est pour
   l'instant une démo + une convention Merkle non câblée.
3. **Prometheus + Grafana**.
4. **HSM/KMS** pour la clé privée (threat model, SPECS §7, SECURITY.md).

**`docs/ROADMAP-PLUGINS.md` :** P2 extension **VSCode** (sidebar, seal/verify/attest,
auto-config MCP Copilot) ; P3 **matrice de docs clients MCP** (Cursor, Windsurf, Gemini CLI,
Cline, Continue…) ; plus tard : intégrations natives proposées aux vendors, conventions de
scellement pour agents CI (GitHub Actions runner-scoped journals).

**Divers relevés dans les docs :** i18n du PDF attestation (conséquence ADR 005) ; endpoints TSA
qualifiées eIDAS en config (ADR 008) ; offre Cloud managée « à partir de 49 €/mois quand elle
sort » + tier Enterprise (SLA/SSO/HSM/QTST) + early access — **annoncées uniquement sur les
landing pages**, nulle part ailleurs ; `NOIREBOX_HOME` portable « queued » (0.6.0) — **⚠️ toujours
pas fait, le hook hardcode toujours `/Users/samlabbe/...`** (§8, P2-12) ; influence sur la future
norme CEN-CENELEC « logging integrity » ; nouvelle langue de détection (l'espagnol donné comme
exemple dans les README).

**Hors périmètre déclaré (ne pas ré-ouvrir sans ADR) :** multi-tenant/sharding/HA ; chiffrement
des payloads au repos ; NoireBox détecteur de texte synthétique (ADR 011) ; certification/conseil
juridique.

---

## 8. Problèmes détectés — priorisé

### 🔴 P0 — sécurité et code ≠ docs (traiter avant toute release)

**P0-1. ✅ CORRIGÉ (commit 2c33b22, ADR 014) — Le secret JWT dérivait de la clé PUBLIQUE — la feature auth est contournée par conception.**
`noirebox/auth.py:28-37` : sans `NOIREBOX_JWT_SECRET`, `_jwt_secret()` = sha256 de `key.public_hex()`.
Or la clé publique est embarquée dans **chaque export et attestation**, et servie sans authentification
sur `GET /api/v1/attestation`. Conséquence : dès que l'auth est activée sans la variable d'env, **n'importe
qui peut dériver le secret HMAC et forger des tokens valables 1 h pour n'importe quel client_id** —
y compris contourner le rate limiter. L'activation de l'auth donne une fausse assurance.
*Fix recommandé :* dériver depuis les octets de la **clé privée** (garde la propriété « unique par
instance, zéro config » sans rien publier), ou refuser de démarrer si `NOIREBOX_CLIENTS` est posé
sans `NOIREBOX_JWT_SECRET` ; + test qui forge un token depuis la clé publique et doit échouer.

**P0-2. ✅ CORRIGÉ (commit 85597c4) — le PR #18 est cherry-pické sur main.** PR #18
(`feat/traffic-radar`, tip `33f4239`/`4db0f69`) n'a **jamais été fusionné** : aucun `radar`/`since`
dans `noirebox/store.py`, `main.py`, `dashboard.py` (vérifié). Pourtant `CHANGELOG.md:68-74` le
décrit sous `[Unreleased]`, et `docs/SPECS.md:99` documente `?since_seq` — la « source de vérité »
documente un paramètre qui n'existe pas. Le journal a même scellé le « Go utilisateur » (seq 1260).
*Décision à prendre :* fusionner le PR (la veille : 38 événements `test` ont pollué le journal de
prod pendant ses tests — ré-importer proprement avec DB isolée) **ou** retirer les mentions.
Dans tous les cas : re-réconcilier CHANGELOG/SPECS avec main.

**P0-3. ⏳ ACTION MANUELLE UTILISATEUR — PyPI trusted publisher pas encore migré vers l'org `noirebox`.** Noté dans le CHANGELOG et
le header de `pypi.yml` : à faire sur pypi.org **avant** de tagger 0.7.0, sinon le publish échoue.

### 🟠 P1 — drift de version, docs mensongères, hygiène de la preuve

**P1-4. ✅ CORRIGÉ (commit c18de9d) — un seul récit de versions (0.7.0).** pyproject **0.6.0** · plugins **0.7.0** ·
`plugins/marketplace.json` **0.5.0** · `dist/` **0.4.0** · `docs/openapi.json` **0.1.0** (et 9
routes au lieu de 11, il manque `/api/v1/activity`). CHANGELOG sans section 0.5.0 alors que le tag
existe. Le fix est la release 0.7.0 (§10).

**P1-5. ✅ CORRIGÉ (commit d8d12ea) — tout re-mesuré le 2026-10-04.** Tests : README « 126 » (×2), landing « 107 »,
CONTRIBUTING « 56+ », **réel 163**. Benchs : landing (0.21/0.23/10.4/22 ms) ≠ SPECS §6
(0.18/0.10/9.2/45 ms) alors qu'elle cite SPECS §6 comme source. Landing « 10 routes » vs 11 réelles.
« 1.8 MB footprint » vs « ~2 MB » (DEPLOIEMENT). VULGARISATION « 4 000 exemples » vs 5 400.
Une passe de sync unique (idéalement générée : nombre de tests injecté depuis pytest, bench depuis
`make bench` persisté) évite la récidive — c'est le 2e drift du compte de tests en 3 jours (119→126→163).

**P1-6. ✅ FAIT (2026-10-04) — ancrage FreeTSA scellé (seq 5594 couvre 5593), verifier tiers : INTACT, 2 tokens contre racines épinglées. Rituel à reprendre régulièrement.** 3 212 événements non ancrés depuis le 27/09 ; les
3 ancrages ont des têtes couvertes jusqu'à seq ~1247. Toute la proposition de valeur (« la fenêtre
falsifiable se réduit à la queue depuis le dernier ancrage ») s'érode chaque jour. Action immédiate :
`POST /api/v1/anchors` vers un témoin externe (freetsa/bitcoin). Nettoyer aussi les 38 événements
`test` : le journal de prod n'est pas une sandbox (et le threat model ne couvre pas la « source
mensongère » — sceller des événements de test en prod affaiblit la valeur du journal pour un auditeur).

**P1-7. ✅ CORRIGÉ (commit f412232) — verifier/ + tsa_roots dans la wheel, testé bout en bout dans un venv propre.** `aiact.py:191` fait
`from verifier.verifier import verify_export` — `verifier/` n'est pas dans la wheel (pyproject
`packages = ["noirebox"]`). Fonctionne depuis le repo, échoue pour l'auditeur qui a fait
`pip install noirebox`. *Fix :* inclure `verifier/` (comme les modèles) ou dupliquer le module de
vérification dans le package.

**P1-8. ✅ CORRIGÉ (commit e3fde6e) — nbFetch + 🔑 token (sessionStorage) + état verrouillé.** Le JS fetch `/api/v1/events` sans
header Authorization (`dashboard.py:468`) ; le 401 fait tomber `events.slice()` et toutes les vues
en « API UNREACHABLE ». *Fix :* endpoint interne de read pour le dashboard, ou injection du token,
ou affichage dégradé assumé.

**P1-9. ⏳ DÉCISION À ASSUMER — métadonnées du journal exposées sans auth.** `/api/v1/verify`, `/activity`, `/attestation`,
`/attestation.pdf`, `/dashboard` n'ont pas `require_auth` — counts, types, head hashes, timestamps
lisibles sans credential (le PDF expose la répartition complète des types). Décision à assumer et
documenter (c'est partiellement voulu : « on ne verrouille jamais la vérification »), ou à protéger.

### 🟡 P2 — consolidation technique (qualité, pas urgence)

- **P2-10. ✅ CORRIGÉ (commit e53d117) — Split-brain de résolution du journal.** `seal`/`verify`/`locate`/hooks → découverte par
  projet (`.noirebox/`) ; `serve`/MCP/`reconcile`/`audit-pack`/`seal-trajectory` → `data/noirebox.db`
  relatif au cwd (`cli.py:91,111,131`, `main.py:34`, `mcp_server.py:112`). Lancer une commande du
  mauvais répertoire crée **silencieusement un autre journal avec une autre clé**. Unifier sur `locate.py`.
- **P2-11. Duplication trajectory/transcripts.** ~60 % de logique dupliquée (deux chaînes de
  digest, deux `verify_*`, deux politiques truncated-tail) entre `trajectory.py` et
  `transcripts.py` ; plus **deux scelleurs** `agent_tool_use` de comportement différent
  (`hookcli.py` best-effort exit 0 vs plugin `seal_tool_use.py` exit 1, preview 800 vs source sans
  version). Factoriser le digest-chain dans un module commun.
- **P2-12. ✅ CORRIGÉ (commit 71a75a0) — Chemins et identités personnelles dans les livrables.** `plugins/noirebox/hooks/seal_tool_use.py:19`
  (`DEFAULT_HOME = "/Users/samlabbe/..."`), `plugins/noirebox/mcp/launch.sh:4`, README plugin,
  `Dockerfile:4` (label `slabbdev/noirebox`). Le `NOIREBOX_HOME` portable est « queued » depuis 0.6.0.
- **P2-13. Fenêtre de rebinding DNS dans le contrôle SSRF** (`anchors.py:66-96`) : httpx re-résout
  le DNS au connect, le claim « closes the rebinding window » est trop fort. Épingler l'IP résolue.
- **P2-14. Verifier fail-open sur outillage manquant** (`verifier.py:51`, `87-98`) : sans openssl
  ou `ots`, les tokens sont comptés OK « reported, not hidden » — un rapport peut dire INTACT avec
  0 token cryptographiquement vérifié. Distinct : séparer `anchors_checked` de
  `anchors_unverified` dans le statut, ou dégrader `valid` selon la politique de l'auditeur.
- **P2-15. Petites robustesses.** Pas de limite de taille sur `EventIn.payload` (schemas.py) ;
  pagination en Python après `store.all()` O(N) (main.py:69) ; JSON 501 du PDF construit en f-string
  fragile (main.py:155) ; `ollama_available()` sans `raise_for_status` (llm_agent.py:36) ; race
  `KeyPair` à la première création concurrente (chain.py:66) ; test flaky `test_client` (port-poll).
- **P2-16. Manques qualité.** Coverage, matrix Python (3.11 jamais testé), smoke test Docker en CI,
  benchs persistés (fichier JSON commité), vérification que les modèles commités = dataset commité,
  SDK sans support du token JWT (inutilisable derrière l'auth).
- **P2-17. Regex guardrail FR-centré** : `lang` ignoré pour `engine="regex"` (silencieux) ;
  les patterns EN existent mais sans paramètre propre.

### 🧹 Hygiène (pas urgent, 30 min)

~14 branches périmées (8 locales `[gone]`, ~9 distantes fusionnées jamais supprimées) ;
2 historiques divergents à racine différente (`private-history` — historique pré-publication, ne
pas fusionner ; `launch-polish`) ; `feat/plugin-trajectory-toggle` obsolète (la feature est
arrivée via #26/#28). `.DS_Store` à la racine (git-ignoré, mais présent). Suite Show HN/daily.dev :
checklists non cochées, aucun post-mortem — tracer ce qui s'est réellement passé pour le
prochain lancement.

---

## 9. État du lancement / marketing

- Packs Show HN (28/09) et daily.dev (27/09) **prêts mais publication non confirmée** : aucune URL,
  aucune checkbox cochée, pas de post-mortem. Indice indirect : le threat model a été enrichi
  (« source mensongère ») suite à une discussion de lancement avec un tiers (Naveen Alavilli).
- Les landing pages (index.html/fr.html) portent des **offres commerciales** (Cloud 49 €/mois,
  Enterprise, early access) absentes de tous les autres documents — à aligner (assumer, ou retirer
  jusqu'à ce qu'une offre existe).
- Le produit tourne sur Pages (auto-déployé) ; boutons de support BMC ; attribution @slabbdev.

---

## 10. Recommandation — le prochain jalon structurant : **release 0.7.0**

Ordre d'opérations proposé (chaque étape débloque la suivante) :

1. **Fixer P0-1** (secret JWT) + test adversarial dédié.
2. **Trancher P0-2** (TRAFFIC radar) : soit fusionner PR #18 proprement (DB de test isolée cette
   fois), soit retirer des docs — puis re-sync CHANGELOG/SPECS.
3. **P1-7** (audit-pack dans la wheel) et **P1-8** (dashboard × auth) — les deux touchent la
   promesse produit.
4. **Passe de sync docs** (P1-5) : compte de tests réel, benchs re-mesurés, landing ré-alignée,
   openapi.json re-généré, VULGARISATION 5 400.
5. **Migrer le PyPI trusted publisher** (P0-3) → tag **v0.7.0** (pyproject 0.7.0, marketplace.json
   0.7.0, CHANGELOG section complète avec lien de compare, un seul récit de versions).
6. **Ancrer la chaîne** vers un témoin externe juste après la release (P1-6) — première pierre
   régulière du rituel d'ancrage.
7. Nettoyage hygiène (branches, Dockerfile label, chemins hardcodés → `NOIREBOX_HOME` portable).
8. Ensuite, la vraie roadmap produit : juge LLM (tier 2 ADR 001), hub de flotte (câbler merkle.py),
   extension VSCode (P2), Prometheus.

---

## Annexe A — Chiffres clés (vérifiés au 2026-10-01)

| Métrique | Valeur |
|---|---|
| Package Python | ~4 000 lignes (24 modules) + verifier 212 l. + TSA 136 l. |
| Tests | **163** (23 fichiers) — suite locale : 158 passed / 4 skipped / 1 flaky |
| ADRs | 13, tous decided/implemented |
| Démos | 10 + 1 harness bench |
| Workflows CI | 5 (ruff+pytest+re-entraînement, Bandit, PyPI OIDC, Docker GHCR, Pages) |
| Findings Bandit | 316 LOW baselinés, 0 MEDIUM, 0 HIGH |
| Modèles ML | 293 KB (fr) + 243 KB (en), datasets 5 400 × 2, seed 42 |
| Journal de prod | 4 460 événements, INTACT, 3 ancrages (dernier 27/09) |
| Versions | pyproject 0.6.0 (publiée) · travail 0.7.x non released |
| Ancienneté | 12 jours de développement (19–29 sept 2026), 1 mainteneur |

## Annexe B — Comment re-vérifier tout ce document

```bash
# État du journal de prod (via MCP ou CLI)
.venv/bin/python -m noirebox.mcp_server   # outil noirebox_verify
# ou :
NOIREBOX_DB=data/noirebox.db .venv/bin/noirebox verify

# Suite de tests sans toucher au journal de prod
NOIREBOX_DB=/tmp/noirebox-test.db make test

# Comptes
grep -rEh "def test_" tests/*.py | wc -l          # 163
grep -rn "since_seq\|radar" noirebox/ | wc -l     # 0 → P0-2 toujours vrai

# Benchs
make bench

# Ancrage de la queue (après configuration des témoins)
export NOIREBOX_TSA_PROFILES='[{"name":"freetsa","url":"https://freetsa.org/tsr"}]'
curl -X POST localhost:8768/api/v1/anchors
```

---

## 11. Journal de la passe du 4 octobre 2026

**Commits (locaux, non pushés — push et tag restent à l'utilisateur) :**

| Commit | Contenu |
|---|---|
| `2c33b22` | security: JWT secret dérivé du matériel privé, jamais des données publiques (ADR 014) + tests adversariaux + race KeyPair |
| `85597c4` | feat: TRAFFIC — le journal comme radar live (cherry-pick du PR #18, CHANGELOG déjà à jour sur main) |
| `f412232` | fix: verifier/ (+ tsa_roots épinglées) embarqué dans la wheel — audit-pack depuis pip, testé dans un venv propre |
| `e53d117` | fix: les commandes d'analyse résolvent le journal comme seal/verify (`locate.resolve_existing_journal`, raffinement ADR 013) + test de régression split-brain |
| `e3fde6e` | fix: dashboard dégrade proprement derrière auth (nbFetch, 🔑 token, état verrouillé) + test |
| `71a75a0` | fix: plugin portable (plus de chemin hardcodé), ollama_available strict, 501 JSON propre, label Dockerfile → org |
| `d8d12ea` | docs: sync unique de tous les chiffres publiés (173 tests, benchs du jour, 11 routes, wheel 0.6 Mo, 5 400 exemples) + openapi.json régénéré (0.7.0) |
| `c18de9d` | chore: release 0.7.0 — pyproject + marketplace à 0.7.0, CHANGELOG daté avec section Fixed + liens compare |

**Validation :** pytest **171 passed / 2 skipped / 0 failed** (skips = Ollama, par design) ·
ruff clean · Bandit gate **0 MEDIUM/HIGH** · verifier tiers sur export frais : **INTACT,
5 596 événements, 4 tokens d'ancrage (2 contre racines épinglées)**, exit 0.

**Runtime :** décision de la passe scellée via MCP (seq 5593) puis ancrage **FreeTSA**
(témoin externe, 6 192 octets de token) scellé seq 5594 — la queue de 3 300+ événements
non ancrés depuis le 27/09 est couverte. 15 branches locales périmées supprimées
(contenu vérifié sur main) ; `private-history` et `launch-polish` conservées (archives à
racine divergente — ne pas fusionner).

**Release 0.7.0 — PUBLIÉE le 2026-10-04.** PyPI trusted publisher migré (confirmé),
main poussée (`9a30eb4`), tag `v0.7.0` posé. Résultats : **PyPI `noirebox 0.7.0`**
(wheel + sdist ; wheel vérifiée : verifier/, tsa_roots épinglées et les 2 modèles ML
embarqués), Docker GHCR `v0.7.0` + `latest`, CI verte (re-entraînement + 173 tests),
Bandit vert, Pages redéployée avec les chiffres re-syncés.

**Passe de consolidation 2026-10-04 (après-midi) — P1-9 + lot P2 exécutés :**
verrou `NOIREBOX_METADATA_AUTH` avec contrat documenté par classe de routes (ADR 004
raffiné) ; pagination SQL (`store.page`) ; digest chain + politique de corruption
dédupliquées dans `noirebox/digests.py` ; claims de sécurité honnêtes (fenêtre rebinding
« rétrécie », pas « fermée », ADR 008 raffiné) ; verifier incapable d'afficher un INTACT
silencieux sans token vérifié (`anchors_in_journal` vs `anchors_checked` + warning
UNPROVEN) ; CI en matrix 3.11/3.12 avec coverage informationnel ; smoke test de l'image
Docker publiée. Validation : **pytest 175 passed / 2 skipped, ruff, Bandit clean** ;
poussé (`d634d92`), CHANGELOG `[Unreleased]` alimenté pour la prochaine 0.8.0.

**Reste ouvert (dans l'ordre) :**
1. P2 restants : câbler merkle.py dans le produit (hub de flotte), regex guardrail
   `lang`, épinglage transport des IPs résolues (le fix complet du rebinding).
2. Roadmap produit : juge LLM (ADR 001 tier 2), extension VSCode, Prometheus/Grafana,
   HSM/KMS.
3. Lancement : confirmer/réaliser Show HN + daily.dev, post-mortem à tracer.
