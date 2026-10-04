# NoireBox — Pack daily.dev (préparé le 2026-09-27, actualisé le 2026-10-04 contre le repo en état 0.8.0)

## Ce que la recherche a établi (docs officielles daily.dev)

Trois chemins pour apparaître sur daily.dev :

1. **Direct Posting** — ouvert à tous, bouton "New Post" depuis n'importe où sur la
   plateforme. Remplace l'ancien système "Community Picks" (2025). Le contenu est
   attribué directement au profil → construit following + réputation. **C'est notre chemin.**
2. **Suggest a Source** — blogs perso ET corporate **exclus** (migration vers Squads
   depuis janv. 2024). Seules les "publications well-known" qualifient (dev.to oui,
   GitHub Pages non). Review manuelle jusqu'à 30 jours. Pas notre chemin.
3. **Squad** — espace communautaire, bon pour la présence continue, portée initiale
   faible. En complément, pas en principal.

Les deux règles qui dictent tout le format :

- **"AI-generated content… or content with AI-typical characteristics" = rejet**
  (content-guidelines officielles). Conséquence : le draft ci-dessous est une base à
  **réécrire à la main dans ta voix** avant publication — pas un copy-paste. C'est
  aussi la règle d'honnêteté habituelle (tu signes, tu réponds aux commentaires).
- **"Content used mainly for self-promotion" = rejet** (+ perte de réputation en cas
  de récidive). Conséquence : l'article est un tutoriel technique qui tient debout
  seul, NoireBox n'apparaît que comme l'implémentation de travail. Jamais d'annonce
  produit, pas de "check out my project" en intro.
- **Anglais uniquement** (contenu non-anglais rejeté). Cohérent avec le playbook.
- Modération : automatisée + review manuelle ; le ranking Popular Feed = lectures
  uniques + upvotes membres + fraîcheur (fenêtre 7 jours). Il faut donc des
  premières heures actives (répondre aux commentaires), comme pour HN.
- Jamais de demande de votes (même logique que HN : détecté, sanctionné).

## Plan de tir coordonné avec le Show HN (lundi 5 oct)

| Heure (Paris) | Action |
|---|---|
| **Dimanche 4 oct soir** ou lundi 8h | Publier l'article sur **dev.to** (nouveau texte, angle différent du Medium — pas de repost, pas de canonical à mettre ; le Medium reste en l'état). dev.to est déjà une source crawlée par daily.dev. |
| Lundi 5 oct ~9h30 | **Direct post** daily.dev : lien vers l'article dev.to + intro de 2 lignes (takeaway technique, pas promo). Modération possible en début de journée → soumettre tôt. |
| Lundi 5 oct ~14h30 | **Show HN** (fenêtre matin US). |
| Plan B | Si la charge lundi est trop lourde (HN = 2-3h de commentaires), décaler le direct post daily.dev à **mardi matin** — l'article n'y perd presque rien (fenêtre de fraîcheur 7 jours). |

Ne jamais poster article + lien repo + HN le même post : un canal = un artefact.

---

## L'ARTICLE (markdown brut, prêt pour dev.to / direct post après humanisation)

```markdown
# Anyone with database access can rewrite your AI agent's logs

Your AI agent already logs everything. Prompts, tool calls, outputs, all neatly
in a table. The problem isn't capturing the data. It's that on the day somebody
important asks "prove this is exactly what the agent produced", your logs are a
confession written about yourself, in a database you control, with no way to
show they were never touched.

I ran into this while building NoireBox, an open-source flight data recorder
for AI agents. This post is the part I'd want to read even if I never touched
that project: what it actually takes to make an agent journal tamper-evident,
and the one attack that breaks the obvious solution.

## Append-only is not tamper-evidence

First instinct: make the log append-only. No UPDATE, no DELETE. Better than
nothing, and it stops the sloppy mistakes.

It stops nothing else. The database admin can edit rows. The server can be
compromised. The application itself, the thing writing the log, can be pointed
at a different file. An append-only flag is a promise made by the same system
you are trying to hold accountable.

The standard fix is old, boring, and it works: a hash chain. Each record
carries the hash of the previous one:

```
h_n = SHA-256(h_{n-1} || payload_n || metadata_n)
```

Edit one row and every hash after it breaks. Sign each new head with Ed25519
and you also know which key was signing at which point. The whole mechanism is
two small files you can read in one sitting: 186 lines for the SHA-256 chain
and Ed25519 signatures, 177 for the append-only SQLite store with BEGIN
IMMEDIATE so two processes can't silently interleave writes. That's the core
of NoireBox.

So: done? Not even close.

## The attack that breaks the obvious solution

Here's the problem I had to design against, and that almost every
"blockchain for logs" pitch quietly skips.

The private key lives on your infrastructure. The operator holds it. An
operator who wants a fake history doesn't need to break any crypto. They
regenerate the whole chain: write the fabricated events, recompute every hash,
re-sign everything, replay the timestamps. The result is a internally
consistent journal, every signature valid, every link intact. Verification
against its own key passes with flying colors.

A chain that verifies against itself proves only that somebody with the key
built it. It cannot tell you *when*. And "when" is the whole game: a seal
created after the fact proves nothing about the state that existed before it.

You need a witness that sits outside the operator's control and saw the hash
value at a point in time.

## Anchoring: timestamps from someone with something to lose

RFC 3161 timestamp authorities do exactly this. You send them a hash, they
sign hash plus time with their own key, and now forging your history means
forging their signature too. Two tiers matter in Europe:

- **Public TSAs** (DigiCert, FreeTSA) are free and immediate. The detail that
  makes them trustworthy is where the trust anchors live: the verifier checks
  against TSA root certificates pinned in its own repository, never against a
  certificate the operator ships with the export. If the operator could choose
  the roots, we'd be back to square one.
- **eIDAS qualified timestamps** carry a legal presumption in the EU
  (art. 41): date and integrity are presumed correct until someone challenges
  them. For AI Act documentation this is the difference between "technical
  measure" and "measure a lawyer accepts".

And then there's the strange one: OpenTimestamps. Your hash gets aggregated
into a Merkle tree that lands in a Bitcoin block. Forging the receipt means
redoing the network's proof of work. Verifying takes microseconds of SHA-256
and it stays valid as long as Bitcoin exists. Zero trust in any organization.

One detail makes all of this GDPR-friendly: only the 32-byte chain head ever
leaves your infrastructure. No payload, no names, no transcript content. The
anchor is a timestamp over an opaque number.

## The retroactivity trick

A natural objection: "fine, I start anchoring today, but my chain already has
six months of history. Who says those events weren't written yesterday?"

They don't need to have been anchored back then. The chain head is a digest of
the entire past, so anchoring *today* seals everything before today. A
regenerated fake chain produces a different head, and the head recorded in the
TSA receipt doesn't match it. Caught at verification time, no matter when the
tampering happened.

Anchor on a schedule and the falsifiable window shrinks to the tail since the
last anchor.

## Many boxes, one seal

The CT-inspired part: when every agent gets its own journal (one journal per
service, like one flight recorder per aircraft), you don't send every journal
to the TSA. You build a Merkle tree over the 32-byte chain heads and anchor
the root. One seal covers N journals, and an inclusion proof for any single
journal is about log2(N) hashes, verifiable offline against the signed root.
Your journals never leave your infrastructure. Only heads do.

## What an auditor actually takes

The export that convinced me this design was right is almost anticlimactic:
one JSON file plus a standalone verifier script. The auditor runs the
verifier, gets exit 0, and the same folder includes the logging description
that AI Act Annexe IV §2(f) asks for. There is also a GitHub Action that gates
a build on journal integrity, so a pipeline consuming an agent's output can
refuse to build when the chain is broken.

Two honest limits, because overselling compliance is how tools become
liabilities. First, this proves integrity, nothing else: payload
minimization and HSM-grade key storage stay your problem. Second, a journal
proves what was recorded, not that the recorder is honest about the world. A
guardrail that journals "incident detected" proves the detection was recorded,
not that detection works.

Which I learned the hard way in a different form: I once wrote a security
baseline document with the finding counts before actually running the scanner.
The numbers were plausible, formatted, and fiction. The corrected version was
produced by running the tool and pasting the reproduction command next to the
results. That distinction, plausible narrative versus reproducible receipt, is
the entire thesis of the tool.

## Try it in two minutes

```bash
pip install noirebox          # 0.8.0, MIT, Python 3.11+, no cloud
noirebox seal note '{"hello": "journal"}'
noirebox verify               # [VALID] — the chain, checked in place
noirebox audit-pack ./audit   # the auditor folder: export, verifier report,
                              # and the AI-Act Annexe IV §2(f) description
```

There's also a Docker image (ghcr.io/noirebox/noirebox), a dashboard where
tampering with a single event visibly explodes the chain, and — since the
0.8.0 release — a local LLM judge (llama-guard3:1b via Ollama) as the third
stage of the transcript guardrail, sealed into the same journal.

The EU AI Act makes automatic event logging mandatory for high-risk systems
from December 2027. Most stacks will check that box with a database table. The
interesting question for the next two years is who can also prove their logs
mean something.

Repo: https://github.com/noirebox/noirebox
```

---

## POST NATIF daily.dev — champ par champ (bouton "New Post")

- **Title** : `Anyone with database access can rewrite your AI agent's logs`
- **Tags** (prendre dans leur picker les plus proches) : AI · Security · Python · DevOps
- **Cover** : 1280×720, fond noir, motif boîte noire, sans texte
- **Body** : L'ARTICLE ci-dessus **sans sa première ligne H1** (le titre a son propre
  champ), plus cette ligne ajoutée tout à la fin, après le lien repo :
  > If you've been through an audit of an AI system, I'm curious what your logs actually looked like.
- Rappel : réécrire à la main dans ta voix avant de coller (règle anti AI-content,
  et c'est toi qui signes les commentaires).

---

## Kit de soumission

### Titres (le n°1 = recommandé, 61 caractères)
1. **Anyone with database access can rewrite your AI agent's logs**
2. Append-only isn't tamper-evidence (and the attack that proves it)
3. The insider attack that breaks hash-chained audit logs
4. Tamper-evident logs for AI agents: hash chains, TSAs, Bitcoin

Interdit : clickbait sans substance (rejet explicite). Le titre doit
correspondre exactement au contenu (règle de modération).

### Tags daily.dev (au moment du post, prendre dans leur picker les plus proches)
`ai` · `security` · `python` · `devops`

### Intro du direct post (2 lignes max, zéro promo — c'est elle qui passe la modération)
> Hash chains stop outsiders. They do nothing against the key holder, who can
> regenerate the entire log with valid signatures. Here's the anchoring layer
> that closes that gap, and why one timestamp retroactively seals the whole chain.

### Cover
1280×720, fond noir, motif "boîte noire" (le ⬛ du branding), **pas de texte
dans l'image** (le titre s'affiche par-dessus), pas de stock-photo "AI robot".
`docs/architecture.svg` peut servir de base si besoin d'une image secondaire.

---

## Variante Squad (post court, ~120 mots, pour 1 Squad max type AI Engineering)

```markdown
Fun threat model I don't see discussed: a hash-chained audit log protects you
from outsiders, but the operator holds the signing key, so they can regenerate
the whole chain from a fake history with every signature valid.

The fix is RFC 3161 anchoring: only the 32-byte chain head goes to a timestamp
authority (or OpenTimestamps/Bitcoin), and since the head digests the entire
past, one anchor retroactively seals everything before it.

I open-sourced the full implementation (MIT): https://github.com/noirebox/noirebox

Question for the thread: do you trust your own agent's logs enough to show
them to a client's auditor today?
```

Règles Squad : un seul Squads post, jamais de cross-post identique, répondre aux
commentaires, pas de re-post du même lien ailleurs la même semaine.

---

## Checklist avant publication

- [ ] Réécrire/ajuster le draft à la main dans ta voix (obligatoire : règle
      anti "AI-typical content" + tu signes les commentaires)
- [ ] dev.to : nouveau post (pas repost du Medium), cover uploadée
- [ ] daily.dev direct post lundi ~9h30 (ou mardi si HN absorbe tout)
- [ ] Répondre aux commentaires 2-3h après chaque post
- [ ] Si "is this AI-written?" tombe : UNE réponse factuelle (même ligne que le
      playbook HN : "Yes, written with AI agents under my direction. The journal
      in the repo is the actual log of those sessions, and the shipped verifier
      lets you check the journal wasn't altered afterwards."), puis laisser le
      verifier parler
- [ ] Ne jamais demander de vote sur aucune plateforme

## Sources (recherche 2026-09-27)

- https://docs.daily.dev/how-to-get-featured (3 chemins, direct posting ouvert à tous)
- https://docs.daily.dev/content-guidelines (AI-content rejeté, self-promo rejetée,
  non-anglais rejeté, blogs perso/corporate exclus des sources)
- https://docs.daily.dev/suggest-new-source (exclusions, review 30 jours)
- https://daily.dev/blog/how-to-get-featured-on-daily-dev (ranking = lectures
  uniques + upvotes + fraîcheur ; dev.to déjà source qualifiée)
