# Réponse à poster sur le fil sunnydachs (HN — markdown brut, prêt à coller)

The consolidated schema pass now exists as ADR 019:
https://github.com/noirebox/noirebox/blob/main/docs/ADRs.md

It folds in what this thread surfaced, with credit where it landed:

- run_id + timestamps, so counting becomes sum-to-n instead of vibes (yours)
- the receipt / check-name pairing imposed by the schema — two different
  keys, not an integrator's promise (your reply)
- clean passes sealed too, with the examined counts inside the receipt —
  sum-to-n from the analyzer to the handoff (yours)
- from the other threads: check_id (predicate + declared inputs + version)
  and evaluator_sha256 — touch the test suite and the receipts die
  (anp2network); the normalized witness — exit code, byte counts, file-tree
  hashes before/after, container digest, canonicalize-then-hash (Ryan Cole);
  negative controls — a verifier that never says false carries no
  information (mayailands); predicate_id anchored on the base branch, so
  the agent can't rewrite the exam (housharenet)

Honest state, so nobody has to take my word: implemented today —
always-sealed reconciliation reports with the examined counts, negative
controls that must bite, the attempt/outcome denominator invariant
(another thread's critique, answered the same way), and a multi-writer
verifier. Tracked as open issues before I claim the rest: the two-key
pairing enforcement is #29, the independence bench is #32.

Implementation-shaped feedback still welcome — the schema is an ADR, not a
graveyard.
