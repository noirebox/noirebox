# Contributing to NoireBox

Thank you! The project aims to be an example of readable, well-documented code —
contributions follow the same standard.

## Getting started

```bash
git clone https://github.com/<user>/noirebox && cd noirebox
./start.sh          # venv + tests + API on 127.0.0.1:8768/docs
```

## Ground rules

1. **A green test for every bug fix or feature added.** The suite is the source of truth:
   `make test` (189 tests). Security tests on unseen sentences
   (`tests/test_ml_guardrail.py`) are never removed without an ADR.
2. **Zero simulation.** Demos use real mechanisms. If an external component is missing
   (Ollama, etc.), we skip it — we never invent behavior.
3. **Educational docs are not allowed to be shallow**: each module should be explainable in a few
   sentences without jargon — that is a project feature in itself.
4. **Lint is mandatory**: `ruff check .` must pass (CI is active).
5. **Architecture decisions**: any structural change must go through an ADR (`docs/ADRs.md`) before code.

## Pull request format

- Descriptive branch (`feat/...`, `fix/...`), one topic per PR
- Update the CHANGELOG (section *Unreleased*)
- Commit messages in English, imperative mood (`Add...`, `Fix...`)
