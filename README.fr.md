<div align="center">

[🇬🇧 English](README.md) · 🇫🇷 Français

# ⬛ NoireBox

**La boîte noire pour agents IA — journal inaltérable, garde-fous, preuve vérifiable.**

[![PyPI](https://img.shields.io/pypi/v/noirebox)](https://pypi.org/project/noirebox/)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://pypi.org/project/noirebox/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Made in France](https://img.shields.io/badge/made%20in-France-blue)](#)

**Un agent IA rédige des comptes rendus qui engagent vos clients.
Qui prouve, dans 18 mois, ce qu'il a *exactement* produit et pourquoi ?**
NoireBox scelle chaque décision dans un journal SHA-256 chaîné + Ed25519,
flague les transcripts piégés avant qu'ils n'atteignent l'agent, et exporte
une attestation que n'importe qui vérifie hors-ligne — **sans vous faire confiance**.

> **Pour n'importe quel agent, en français et en anglais.** Le journal,
> l'API, les outils MCP et le vérificateur sont universels ; chaque langue
> a son détecteur (~250 Ko) entraîné depuis un dataset reproductible (seed 42) — un nouveau
> marché = un générateur de dataset + un ré-entraînement. **Vous avez déjà un
> garde-fou ? Gardez-le** — ce n'est qu'une source d'événements de plus.
> 🇪🇺 Conçu pour le [marché européen (RGPD & AI Act)](#conçu-pour-le-marché-européen-rgpd--ai-act) — développé en France.

> **Statut — octobre 2026.** NoireBox devient un **produit**. Ce dépôt est
> désormais la **maison publique de la documentation** — architecture, threat
> model, ADRs, mapping conformité — et n'héberge plus de code source.
> Le développement continue dans un **dépôt privé**. Chaque release
> open-source jusqu'à **v0.21.0** reste sur
> [PyPI](https://pypi.org/project/noirebox/) et dans les tags git sous
> licence **MIT**, avec le record complet dans le [CHANGELOG](CHANGELOG.md).

[Dernière release ouverte](https://pypi.org/project/noirebox/0.21.0/) ·
[Specs](docs/SPECS.md) · [Threat model](docs/THREAT-MODEL.md) ·
[ADRs](docs/ADRs.md) · [Vulgarisation](docs/VULGARISATION.md) · [CHANGELOG](CHANGELOG.md)

</div>

---

## Statut — le pivot produit

NoireBox a été construit au grand jour : 26 ADRs, un audit externe, une suite
de replay d'attaques publique, 21 releases, chaque décision d'architecture
argumentée en public. Merci à toutes celles et ceux qui l'ont sondé, cassé,
revu — ce record d'audit reste public pour toujours.

Ce qui change à partir d'ici :

- **Ce dépôt ne contient plus que de la documentation** — pas de code source,
  pas de tests, pas de packaging. Il garde les docs d'architecture, le threat
  model, les ADRs, le mapping conformité et le CHANGELOG complet.
- **Le développement a déménagé dans un dépôt privé** — NoireBox devient un
  produit.
- **Rien n'est fermé rétroactivement.** Chaque release jusqu'à v0.21.0 reste
  sur [PyPI](https://pypi.org/project/noirebox/) et dans les tags git,
  sous licence MIT, installable et vérifiable pour toujours.

La documentation ci-dessous décrit la dernière release ouverte (v0.21.0).

## Conçu pour le marché européen (RGPD & AI Act)

Les éditeurs IA européens affrontent une réalité de conformité que leurs
concurrents américains n'ont pas : **prouver** — pas promettre — ce que leurs
systèmes ont fait. NoireBox est construit autour de cette obligation. Et
l'horloge est réelle : le suivi des incidents GPAI est **en vigueur depuis
août 2025** (art. 55(1)(c)), les obligations de transparence s'appliquent
depuis août 2026, et la journalisation high-risk arrive le
**2 décembre 2027** (AI Act tel que modifié par le Digital Omnibus,
Règl. (UE) 2026/1744) — avec des amendes jusqu'à 35 M€ / 7 % du chiffre
d'affaires.

| Exigence | Réponse NoireBox |
|---|---|
| **RGPD art. 5(2)** — responsabilité : le responsable doit *démontrer* la conformité | Journal inaltérable de ce que l'IA a produit, quand, sur quelle entrée |
| **RGPD art. 15/20** — droits des personnes (accès, portabilité) | Export signé de tout ce qui touche une réunion — vérifiable *par l'auditeur de la personne elle-même* |
| **AI Act art. 12 + 19/26(6)** — journalisation automatique, conservée ≥ 6 mois | Chaque décision d'agent scellée au runtime ; l'intégrité du log est cryptographique, pas une promesse |
| **AI Act art. 55(1)(c)** (risque systémique GPAI — en vigueur) | Incidents graves suivis, documentés, signalés — scellés comme événements de première classe (`ai_incident`) |
| **AI Act Annexe IV §2(f)** — documenter les caractéristiques de journalisation | `noirebox audit-pack` : un dossier pour l'auditeur — export + rapport du vérifieur + description de journalisation générée |
| **eIDAS art. 41** — l'horodatage qualifié emporte une présomption légale | Profils d'ancrage pour TSA qualifiées eIDAS (Universign, Certigna…), TSA publiques, et Bitcoin via OpenTimestamps — voir [ADR 008/009](docs/ADRs.md) |
| **AIPD / workflows DPO** | Attestation exportable pour le DPO ; taxonomie d'incidents nourrissant la documentation des risques |
| **Souveraineté** | Auto-hébergé, zéro télémétrie, zéro dépendance cloud, clés Ed25519 sur votre infrastructure — déploie partout (y compris clouds européens) |

> **Périmètre honnête** (nous sommes une brique, pas une certification) :
> NoireBox prouve l'*intégrité* du registre de votre IA. La minimisation des
> payloads reste du côté du déployeur. La custody de clé est livrée dans la
> boîte — la clé vit dans un process dédié (0.15.0) ou sur un token PKCS#11
> (0.16.0) ; le pin *matériel* reste sa décision — voir le
> [threat model](docs/THREAT-MODEL.md). Un outil
> qui survend sa conformité est un passif ; un outil qui énonce son périmètre
> est auditable.

## Pourquoi

- **RGPD** : une plateforme qui affirme « conforme RGPD » doit pouvoir démontrer
  ce que son IA a produit, sur quelles données, et quand.
- **AI Act (art. 12)** : les systèmes à risque doivent tenir des *journaux
  automatiques d'événements*. Aujourd'hui, la quasi-totalité des stacks LLM
  loggent pour le *debug* — pas pour la *preuve*.
- Le trou du marché : les outils d'observabilité (Langfuse, LangSmith…) sont
  faits pour les devs, modifiables a posteriori, et ne produisent rien de
  présentable à un auditeur, un DPO ou un client.

## Positionnement honnête (state of the art)

| Outil | Ce qu'il fait | Ce qu'il ne fait pas |
|---|---|---|
| Langfuse / LangSmith / Helicone | Observabilité, debug, traces LLM | Pas de preuve inaltérable, rien d'exportable pour un audit |
| Garak / PyRIT / promptfoo | Red-team **offline** au niveau modèle | Pas de garde-fou runtime, pas de journal de preuve |
| halo-record / gate-oc-audit | Journal hashé pour agents de *code* | Pas de domaine métier, pas d'attestation tiers, pas de FR |
| **NoireBox** | **Journal inaltérable Ed25519 → ancrage RFC 3161 → attestation exportable + vérificateur autonome** (garde-fou FR/EN embarqué = une source d'événements fongible parmi d'autres ; **ancrage de flotte** : un sceau TSA couvre N journaux) | — |

**NoireBox applique le modèle Certificate Transparency aux journaux d'agents
IA :** beaucoup de journaux, une seule racine signée par un tiers horodateur,
des preuves d'inclusion que n'importe qui vérifie hors-ligne. À notre
connaissance, aucun autre outil d'audit d'agents ne le fait.

## Le cœur, c'est le journal. Le garde-fou, c'est un plugin.

![Architecture NoireBox](docs/architecture.svg)

Zéro ambiguïté sur ce qu'est le produit :

- **Une NoireBox par agent ou par service** — comme un boîtier de vol par
  avion. Une instance = un fichier SQLite, une paire de clés, une chaîne.
  La couche flotte agrège des **preuves** (têtes de chaîne de 32 octets),
  jamais des événements : votre journal ne quitte jamais votre infrastructure.
- **Le journal EST le produit** — chaîne, signatures, stockage append-only,
  ancrage RFC 3161, export, vérificateur autonome. Il est indépendant du
  domaine, de l'agent et de la langue : un événement, c'est un `type` libre
  et un payload, rien de plus. Les modules du journal n'importent AUCUN code
  de détection — supprimez le garde-fou entier, tout continue de fonctionner.
- **La prévention est fongible** — un garde-fou n'est qu'un producteur
  d'événements parmi d'autres. Vous avez déjà Lakera, Llama Guard, votre
  LLM-juge, vos regex ? **Gardez-les.** Journalisez leurs verdicts de la
  même façon (`POST /api/v1/events`, `type: "incident"`) : leurs détections
  deviennent inaltérables et vérifiables par un tiers, au lieu de finir
  dans des logs applicatifs réinscriptibles.
- NoireBox embarque un garde-fou (regex + ML entraîné) comme **exemple
  fonctionnel de ce contrat de plugin** — et par confort si vous n'en avez
  pas. Il est remplaçable par construction ([ADR 003](docs/ADRs.md)).

> La prévention varie selon la stack. La preuve est universelle.

## La dernière release open-source (v0.21.0)

```bash
pip install noirebox==0.21.0          # le moteur ML est embarqué dans le wheel (FR + EN)
pip install "noirebox[pdf]==0.21.0"   # + l'attestation PDF prête pour le DPO (extra optionnel)
noirebox serve                        # API sur http://127.0.0.1:8768/docs
```

Ou avec Docker — Python inutile :

```bash
docker run -p 8768:8768 ghcr.io/noirebox/noirebox:0.21.0
# API + docs OpenAPI sur http://127.0.0.1:8768/docs — données dans ./data
```

Vérifier une exportation comme un tiers (auditeur, DPO, client) : exportez le
journal (`GET /api/v1/export`) et vérifiez-le avec le vérificateur livré dans
la release — ou verrouillez votre propre CI sur l'intégrité du journal avec la
[GitHub Action noirebox-verify](https://github.com/marketplace/actions/noirebox-verify).

> Les prochaines versions arrivent sous forme de produit.

## Horodatage de la chaîne — des témoins extérieurs que vous choisissez (RFC 3161 + Bitcoin)

Le journal prouve l'intégrité, mais *quand* a-t-il été scellé ? Un serveur
qui date lui-même son journal, c'est le suspect qui rédige son procès-verbal.
Et le threat model gardait un trou : un opérateur possédant la clé privée
pouvait **régénérer toute la chaîne** avec de vraies signatures.

L'ancrage ferme le trou — avec des **témoins que vous choisissez, en
couches** ([ADR 006/008/009](docs/ADRs.md)) :

- **TSA qualifiées eIDAS** (Universign, Certigna…) — un horodatage qualifié
  emporte une *présomption légale* (art. 41) : la date et l'intégrité des
  données scellées sont présumées jusqu'à contestation ;
- **TSA publiques** (DigiCert, FreeTSA…) — gratuites, immédiates,
  organisations indépendantes ; l'auditeur vérifie contre des **racines
  épinglées dans le vérificateur publié**, jamais contre un certificat
  fourni par l'opérateur ;
- **OpenTimestamps / Bitcoin** — un reçu qu'aucun opérateur ne peut forger :
  le forger exigerait de refaire la preuve de travail du réseau ; le
  vérifier prend ~30 µs de SHA-256, valable aussi longtemps que Bitcoin.

Un seul événement `anchor` porte tous les témoins. Seul le **hash de tête de
32 octets** quitte l'infrastructure (zéro donnée, zéro exposition RGPD). Et
l'ancrage est **rétroactif** : une seule ancre externe scelle *tout* le
passé de la chaîne — une chaîne régénérée montre une tête que les tokens ne
couvrent pas, démasquée à la vérification sans aucune publication externe
préalable. Ancrez régulièrement et la fenêtre falsifiable se réduit à la
queue depuis la dernière ancre.

```bash
export NOIREBOX_TSA_PROFILES='[
  {"name": "freetsa",  "url": "https://freetsa.org/tsr"},
  {"name": "bitcoin",  "kind": "ots"}]'
export NOIREBOX_TSA_ALLOWED_HOSTS=freetsa.org
curl -X POST localhost:8768/api/v1/anchors   # un appel, deux témoins, tout le passé scellé
noirebox audit-pack ./audit                  # le dossier auditeur : export + rapport + Annexe IV §2(f)
```

Une TSA OpenSSL auto-hébergée est également livrée dans la release pour les
déploiements souverains/hors-ligne — même frontière de confiance que
l'opérateur, documentée comme telle. Le mapping réglementaire complet :
[docs/COMPLIANCE-EU.md](docs/COMPLIANCE-EU.md).

## Le garde-fou embarqué — un plugin, deux moteurs

| Moteur (`engine`) | Taille | Langues | Rôle | Dépendance |
|---|---|---|---|---|
| `regex` | ~0 | FR+EN | cas évidents, coût zéro | aucune |
| `ml` | 243–293 Ko | **fr** & **en** (paramètre `lang`) | paraphrases que le regex rate, local | scikit-learn |
| `llm` | modèle ~2 Go | FR+EN | juge tier-2 pour les cas douteux — verdicts binaires + raison, local | Ollama + `qwen2.5-coder:3b` ([ADR 015](docs/ADRs.md)) |

**Décision d'architecture — [ADR 002](docs/ADRs.md)** : Llama Prompt Guard 2
de Meta (le classifieur de l'industrie, ~90 Mo) a été évalué puis **écarté en
connaissance de cause** : licence gated, torch/transformers en dépendances,
sortie binaire sans taxonomie d'audit. L'ADR documente aussi le **chemin
d'intégration** si vous en avez besoin un jour (adaptateur ≈ 40 lignes
derrière la même interface moteur). L'étage 2 des cas douteux reste un
LLM-juge local — l'évaluation réelle de l'ADR 015 a écarté `llama-guard3:1b`
(il ignore les policies custom et rate l'injection de transcript) ; le défaut
est `qwen2.5-coder:3b` derrière le prompt few-shot de la taxonomie maison.
Zéro nouvelle dépendance Python.

## La scène LLM réelle (Ollama local)

Un **vrai LLM** (qwen2.5:0.5b, 397 Mo, local via Ollama — jamais embarqué,
téléchargé par `ollama pull`) reçoit le transcript piégé.

Résultat mesuré (température 0, reproductible) :
- **Sans NoireBox** : le modèle réécrit lui-même les instructions de
  l'attaquant dans « son » compte rendu — email du concurrent et
  `DROP TABLE utilisateurs` inclus. L'attaque aboutit.
- **Avec NoireBox** : 4 lignes compromises retirées AVANT l'appel, l'incident
  scellé au journal, et la vraie sortie du modèle est propre.

Les recettes de mise en prod (tunnel cloudflared à 0 €, Hugging Face Spaces
permanent, VPS 3–6 €/mois) sont livrées avec la release.

## Le micro-détecteur ML — deux langues, ~250 Ko chacune

Le moteur `ml` est un vrai modèle entraîné par langue : TF-IDF (mots +
caractères) + régression logistique — **293 Ko (FR)** et **243 Ko (EN)** —
entraîné depuis des datasets reproductibles (seed 42). Une nouvelle langue
est un dataset, pas une réécriture : l'entraîneur, le registre et l'API
(`lang: "fr" | "en"`) sont partagés. Ajouter l'espagnol = un générateur de
dataset + un ré-entraînement.

**Honnêteté sur l'évaluation** (le truc qui crédibilise en revue) :
- les jeux de test partagent leurs templates avec l'entraînement →
  accuracy 1.000 mesure la cohérence, pas la généralisation ;
- la preuve de généralisation est ailleurs : des phrases **inédites**
  (argot, fautes, formulations jamais vues) sont figées dans la suite de
  tests de la release — **dans les deux langues** — bonne catégorie
  détectée, **zéro faux positif** sur les phrases saines pièges (« envoie le
  bilan au comptable », « j'ai réinitialisé mon mot de passe ») ;
- la suite inédite EN a attrapé une vraie faiblesse en v1 (« take orders
  from me » à 0,37 de confiance) → dataset enrichi → modèle ré-entraîné →
  suite verte. Cette boucle EST le métier ML, et elle est dans l'historique git ;
- insight métier FR : 20 % du dataset est désaccentué car les transcripts de
  reconnaissance vocale sortent souvent sans accents.

Les deux détecteurs (293 + 243 Ko) et les deux datasets (~1,3 Mo) sont
versionnés dans les tags de release.

## Brancher NoireBox — 3 façons réelles

**1. REST** (n'importe quel langage) — exemple PHP :

```php
// Depuis n'importe quelle application PHP — c'est tout
$resp = $client->request('POST', 'https://noirebox.exemple.fr/api/v1/transcripts/scan', [
    'json' => ['meeting_id' => 'REU-42', 'text' => $transcript, 'engine' => 'ml'],
]);
$incidents = $resp->toArray();
```

**2. SDK Python** (livré dans le wheel) :

```python
from noirebox.client import NoireBoxClient
nb = NoireBoxClient("https://noirebox.exemple.fr")
nb.scan("REU-42", transcript)          # garde-fou avant l'agent
nb.log_event("llm_output", {...})      # sceller la sortie de l'agent
nb.verify()                            # vérifier la chaîne
```

**3. MCP** (protocole des agents — Claude Desktop et tous les clients MCP) :
4 outils exposés (`noirebox_scan`, `noirebox_log_event`, `noirebox_verify`,
`noirebox_attestation`). Configuration (`claude_desktop_config.json`) :

```json
{ "mcpServers": { "noirebox": {
    "command": "python",
    "args": ["-m", "noirebox.mcp_server"] } } }
```

## Cas d'usage — n'importe quel agent qui « décide »

| Agent | Ce que NoireBox apporte |
|---|---|
| Assistant de réunion (scénario de démo) | comptes rendus prouvables + anti-injection par transcript |
| Agent de code | journal inaltérable des actions exécutées (fichiers, commandes) |
| Support client IA | preuve de ce qui a été promis au client, quand, et pourquoi |
| Pipeline RAG juridique / médical | traçabilité des sources utilisées et des sorties produites |
| Copilotes métier (finance, RH…) | attestation exportable pour audit interne / DPO / client |

Le **journal** est universel (événements typés librement). Le **corpus du
garde-fou** livré est spécialisé transcripts FR — l'étendre à un autre
domaine = ajouter des exemples au dataset et ré-entraîner.

## API

| Route | Auth | Rôle |
|---|---|---|
| `POST /api/v1/token` | — | Échange `client_id`/`client_secret` contre un JWT 1 h |
| `POST /api/v1/events` | 🔒 | Enregistre un événement (prompt, sortie, éval…) |
| `GET /api/v1/events` | 🔒 | Liste paginée des événements ; `since_seq` = queue live (curseur) |
| `GET /api/v1/verify` | ouverte | Vérifie la chaîne sur place |
| `GET /api/v1/activity` | ouverte | Comptes d'événements par jour (heatmap du dashboard) |
| `POST /api/v1/transcripts/scan` | 🔒 | Garde-fou : détecte les injections, journalise |
| `GET /api/v1/attestation` | ouverte | Attestation signée de l'état courant |
| `GET /api/v1/attestation.pdf` | ouverte | Attestation en PDF A4 prêt pour un DPO |
| `POST /api/v1/attestation/verify` | ouverte | Vérifie une attestation soumise |
| `POST /api/v1/anchors` | 🔒 | Ancre RFC 3161 : scelle la tête de chaîne à une TSA |
| `GET /api/v1/export` | 🔒 | Export complet auditable |

🔒 = exige `Authorization: Bearer <token>` quand `NOIREBOX_CLIENTS=id:secret,…`
est posé ; **les routes de vérification restent ouvertes par principe** — on ne
verrouille jamais la vérification ([ADR 004](docs/ADRs.md)). Rate limit : 60 req/min/client.
Les routes de métadonnées (`/activity`, `/attestation*`) n'exposent que des agrégats et des
digests (jamais le contenu des payloads) et passent derrière le token avec `NOIREBOX_METADATA_AUTH=1`.

## Plugin embarqué — taxonomie v0

- `instruction_override` — « ignore toutes les instructions », « tu es désormais… »
- `data_exfiltration` — « envoie … à email@… / https://… »
- `pii_request` — « donne les mots de passe / données bancaires »
- `tool_abuse` — « exécute DROP TABLE / rm -rf / curl »

Le corpus est livré avec la release. Architecture par étages :
[ADR 001](docs/ADRs.md).

## La suite de tests de la release (392 tests à v0.21.0)

Cryptographie (falsification, réordonnancement, mauvaise clé), garde-fou
regex et **ML sur phrases inédites en FR et EN**, le pipeline gardé avec un
LLM factice, agent API, serveur MCP, SDK client contre un **vrai serveur
uvicorn** (port éphémère), **auth OAuth2 JWT + rate limiting + attestation
PDF DPO + ancrage RFC 3161 contre une vraie TSA locale (dont l'attaque de
régénération par l'insider)**, les **reçus scellés**, la **custody de la
clé** (keyholder sur socket unix, PKCS#11 sur SoftHSM2) et le contrat
complet du vérificateur tiers. Tout se rejoue en local depuis le tag de la
release.

**La suite SCAR replay est un différentiel, pas juste une suite de tests** —
les quatre fixtures d'attaque du catalogue de Randal L. Schwartz (plus la
race du témoin canari, SCAR-PROC-114) rejouées contre cette couche de
réconciliation, chacune assertant ce qu'elle fait : attrape l'attaque, ou
avoue le gap par écrit. Gradation, format des claims et taxonomie
d'application Level 0/1/2 : [docs/SCAR-BENCH.md](docs/SCAR-BENCH.md).

**Scan statique de sécurité** en CI ([Bandit](https://bandit.readthedocs.io/),
échoue sur MEDIUM et au-dessus) ; chaque finding LOW récurrent est baseliné
avec sa justification dans [docs/SECURITY-BASELINE.md](docs/SECURITY-BASELINE.md)
— aucun bruit silencieux.

**Vous consommez des décisions d'agents IA dans votre pipeline ?** Verrouillez
vos builds sur l'intégrité du journal — le vérificateur existe en GitHub
Action ([Marketplace](https://github.com/marketplace/actions/noirebox-verify)) :

```yaml
- uses: noirebox/noirebox-verify@v1
  with:
    export-path: export.json
    noirebox-ref: v0.16.0  # fige le ref du vérifieur — audits reproductibles
```

## Soutenir

NoireBox est libre et MIT — vérification incluse, pour toujours. Si ça t'a
fait gagner du temps (ou épargné un casse-tête de conformité), un café est
la meilleure façon de le dire :

<a href="https://buymeacoffee.com/samlabbe"><img src="docs/bmc_qr.png" width="160" alt="Buy Me A Coffee — scanne pour soutenir NoireBox"></a>

*Scanne ou clique — [buymeacoffee.com/samlabbe](https://buymeacoffee.com/samlabbe)*

NoireBox est créé et maintenu par [@slabbdev](https://github.com/slabbdev) — construit seul, dans les Vosges.

## Licence

MIT — voir [LICENSE](LICENSE). Les releases passées (jusqu'à v0.21.0)
restent MIT ; la documentation de ce dépôt l'est aussi.
