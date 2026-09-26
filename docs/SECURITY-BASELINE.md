# Security baseline — every finding, with its disposition

NoireBox runs [Bandit](https://bandit.readthedocs.io/) in CI
([`.github/workflows/security.yml`](../.github/workflows/security.yml)) and
**fails on MEDIUM severity and above**. This file is the honest ledger for
everything the scanner reports below that bar: what it is, why it exists,
why it is accepted. A security tool with silent scanner noise is a
liability; one with a documented ledger is auditable.

**Current state (2026-09-26): 316 findings, 0 MEDIUM, 0 HIGH — all LOW,
in the classes below.** Reproduce with:

```bash
bandit -r noirebox verifier tsa ml -ll -f json   # product code — the CI gate level
bandit -r tests -q -f json                       # tests — reported, not gated
```

| Class | Count | Where | Disposition |
|---|---|---|---|
| **B101** — use of `assert` | 220 | `tests/` | `assert` IS the pytest mechanism; Bandit's own documentation recommends excluding test directories. The CI gate does not scan tests. |
| **B311** — pseudo-random generator | 71 | `ml/gen_dataset.py`, `ml/gen_dataset_en.py` | `random.seed(42)` on line 8 of both files is a **reproducibility requirement**: datasets must be byte-identical on every machine (stated in `.gitignore` and `make train`). They are public training corpora, not secrets — cryptographic randomness would defeat the purpose. |
| **B603** — subprocess call | 5 | `noirebox/anchors.py`, `verifier/verifier.py` | Calling `openssl` (RFC 3161 stamping and verification) IS the product mechanism. List-form arguments, no shell, no string concatenation; the only network target is the operator-configured TSA endpoint behind the egress allowlist (`NOIREBOX_TSA_ALLOWED_HOSTS`, link-local refused after DNS resolution — ADR 008). |
| **B607** — partial executable path | 5 | same files | Same calls: `openssl`, `bash gen_tsa.sh`, `ots`, `git` — all resolved from PATH deliberately, so deployments can pin their own toolchain. No user input reaches the command name. |
| **B404** — `import subprocess` | 3 | same files | Consequence of the above, not a finding of its own. |
| **B105** — "hardcoded password" | 1 | `noirebox/main.py:61` | The flagged string is `"bearer"` — the OAuth2 token type from RFC 6750, part of the response schema. Not a credential. |
| **B105/B107** — "hardcoded password" | 3 | `tests/test_auth_pdf.py` | Deliberate fixtures: `"wrong"` (a token that MUST be rejected) and `"s3cret"` (a throwaway test secret). Their job is to be public. |

**Adding a new accepted finding?** Add its row here in the same PR, with
the why. The CI gate (MEDIUM+) protects against regressions; this file
protects against quiet normalization. A security baseline whose numbers
are not reproducible from the scanner output is worse than no baseline —
regenerate and diff this file whenever the code changes.
