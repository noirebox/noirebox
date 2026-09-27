# Plugin ZCode — NoireBox

Branche NoireBox — le journal inaltérable pour agents IA — directement dans
ZCode : l'agent devient son propre vol enregistré.

## Ce que fait le plugin

| Composant | Rôle |
|---|---|
| Serveur MCP `noirebox` | 4 outils natifs : `noirebox_scan`, `noirebox_log_event`, `noirebox_verify`, `noirebox_attestation` |
| Hook `PostToolUse` (Write/Edit/Bash) | Scelle automatiquement chaque action de l'agent (type `agent_tool_use`) dans le même journal |
| Hook `PostToolUse` — trajectoire (ADR 012) | Scelle aussi le vol enregistré de ZCode lui-même (`model-io-*.jsonl`, un appel LLM par ligne) — digests seuls, jamais le texte des conversations ; session scellée vivante = `truncated_tail` honnête, re-scellée complète au passage suivant |
| Skills `noirebox-journal` / `noirebox-demo` | Savoir sceller/vérifier/attester ; démo guidée en 5 étapes |
| Commandes `/noirebox-seal`, `/noirebox-verify`, `/noirebox-attest`, `/noirebox-scan` | Raccourcis des 4 gestes |

Le serveur MCP et le hook écrivent **le même journal** (même SQLite, même
clé Ed25519) : la chaîne ne fait qu'un.

## Configuration

Le plugin pointe sur un checkout NoireBox local (venv + journal). Deux
variables d'environnement le déplacent :

- `NOIREBOX_HOME` — racine du checkout (défaut :
  `/Users/samlabbe/.zcode/workspace/default/noirebox`) ; le journal vit dans
  `$NOIREBOX_HOME/data/noirebox.db`.
- `NOIREBOX_DB` — chemin SQLite explicite, prioritaire sur `NOIREBOX_HOME`.
- `NOIREBOX_HOOK_DISABLE=1` — désactive tout le scellement automatique
  (actions outils + trajectoire).

Toggles du scellement de trajectoire (ADR 012) — `seal/not-seal` :

- `NOIREBOX_TRAJECTORY_SEAL=0` — suspend le scellement des trajectoires ;
  les scellements d'actions outils continuent.
- `NOIREBOX_TRAJECTORY_INTERVAL_MIN` — minutes entre deux scans du
  répertoire rollout (défaut : 10).
- `NOIREBOX_ROLLOUT_DIR` — où vivent les `model-io-*.jsonl` (défaut :
  `~/.zcode/cli/rollout`).

Sémantique assumée : OFF = pause, les scellements **futurs** s'arrêtent,
ceux du passé restent (append-only, pas d'unseal — c'est le produit).
Ce qui entre au journal : des digests et des compteurs, jamais le contenu ;
« oublier » une session = supprimer son fichier local, il ne reste au
journal que la preuve minimale (N appels, telle heure, tel modèle).

Déplacer le plugin (autre machine, autre chemin de checkout) = poser
`NOIREBOX_HOME` ; rien à éditer dans le plugin.
