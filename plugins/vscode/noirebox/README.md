# NoireBox for VSCode (P2, source)

The flight recorder in the editor: seal decisions, verify the journal,
generate the audit pack — all through the installed `noirebox` CLI, so the
extension stays glue over the single core (ADR 013's per-project journal
convention: `NOIREBOX_DB` wins, else the nearest `.noirebox/`).

## Install

```bash
cd plugins/vscode/noirebox
npx @vscode/vsce package        # → noirebox-0.9.0.vsix
code --install-extension noirebox-0.9.0.vsix
```

Prerequisite: `pip install noirebox` (the CLI on PATH) — the extension
never invents a journal; set `noirebox.db` in settings to point at an
explicit journal.

## Commands

| Command | What it does |
|---|---|
| `NoireBox: Verify the journal` | `noirebox verify` — in-place chain verdict |
| `NoireBox: Seal a decision note` | `noirebox seal decision {...}` — one free-form event |
| `NoireBox: Generate the audit pack` | `noirebox audit-pack ./audit` — export + verifier report + Annexe IV §2(f) |
| `NoireBox: Show the journal path` | `noirebox locate` |

## Honest scope

Source-only by design: the `.vsix` is built by whoever ships it (the
marketplace listing is a distribution decision, not a code decision). The
extension shells out to the CLI — same journal, same key, same chain as
every other integration.
