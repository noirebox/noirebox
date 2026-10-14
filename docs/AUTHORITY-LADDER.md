# The authority ladder — who wrote this, answered one rung at a time

*The map of the descent. Every audit of this repository has been the same
move: descend one rung, name what the rung cannot see, then close it with
a test — or name it, precisely, as a premise. Randal's frame, howcani's
method: **the descent is the audit**. Each layer has fewer candidate
writers than the last; at the floor the artifact stops being evidence
about the agent and becomes a statement of trust in the operator — and
the taxonomy exists to prevent pretending it terminates anywhere
stronger.*

The journal proves ORDER and INTEGRITY: a hash chain, externally
anchored, tamper-evident. It deliberately does not know WHO the writer
is — that knowledge lives up this ladder. Each rung below states what it
sees, what it closed, the residue it exposed, and the test that bites.

---

## Rung 0 — the caller's argument

**What it is**: the labels and sets supplied at check time —
`signers=[(k1, "agent"), (k2, "hook")]`, the domain strings, the event
types. Vocabulary, not evidence: the party under audit wrote it.

**What it closed**: nothing — rung 0 is where audits START. The verdict
used to read these labels, which meant an attacker row — identical key
material, one relabelled — moved the verdict.

**Closed by**: v0.2.5 — **the verdict reads keys, not labels**. The
attacker row is pre-registered as an immobility test:
`test_attacker_row_labels_never_move_the_verdict`. Relabelling identical
key material moves nothing; the caller's vocabulary certifies nothing.

**Residue it exposed**: key material ALONE cannot see that two distinct
agent-controlled keys share one owner — and a cross-writer check that
cannot resolve a writer answered "clean" where it should have said
nothing. Both halves went down the ladder.

## Rung 1 — the signature (the store writer)

**What it is**: the Ed25519 signature on each event — the journal's own
key material, resolved by verification, never by name.

**What it closed**: v0.2.4 — the **transport-writer invariant**: a
`deterministic` label is verified only by an attempt sealed by a writer
the agent does not control; absence of one is `unverified_label`, the
failure mode is a missing event, never a missing negative. v0.2.5 — the
unresolved receipt writer is `independence_undecidable`: undecidable is
**never clean** (`test_v025_unresolved_receipt_signer_is_undecidable_not_clean`).

**Residue it exposed**: two distinct keys, one owner — invisible to any
amount of key material (`independence.py` documents the seam). And the
key itself was a file on disk. Both residues live higher up.

## Rung 2 — the sealed registry

**What it is**: the known-writers registry (v0.2.6, `seal_writer` →
`writer/0.1`) — the domain of every writer **declared at registration**,
before any run the writer could influence, and sealed into the journal.
Registry mode resolves keys and domains from the sealed registry: the
caller supplies nothing.

**What it closed**: the caller's labels demoted to decoration — the
REGISTERED domain decides
(`test_writer_registry_overrides_the_callers_labels`); an unregistered
transport writer witnesses nothing; an unregistered receipt writer is
`independence_undecidable`.

**Residue howcani found** ([3hj95](https://dev.to/slabb/a-hash-chain-proves-the-ordering-four-attacks-prove-its-not-enough-59oe#comment-3hj95)):
the assembly was store-derived and `setdefault` made **first-write-wins**
the registrar — the agent could seal its own `writer` entry and win the
vote by arriving first; the operator's honest attestation, arriving
second, sat inert. A correlation rule standing in for an authority rule.

## Rung 3 — the pinned registrar (the floor of EVIDENCE)

**What it is**: `registrar_public_hex` on `reconcile_receipts` (v0.2.7) —
the operator's key, supplied **out-of-band** (ADR 008's TSA-root
pattern), never read from the artifact under audit. The registry
assembles from registrar-sealed entries ONLY — filter at assembly, order
no longer decides. A key the registrar attested under two domains is the
operator contradicting itself: `registry_duplicate_undecidable`, emitted
at assembly, and any row depending on it reads
`independence_undecidable` — never first-wins.

**The registered prediction, run and held**: at the pinned head, the
operator's attestation landing second reads `unverified_label` — not
clean with a finding beside it ("the vote moved; the finding did not
merely report"). The test:
`test_v027_write_race_agent_first_operator_second_reads_unverified`.

**The disclosure row**: `registry_disclosure()` states the registrant and
the evidence grade — grade 3, "anchored self", VOLUNTARY unless a regime
imposes it (ADR 022). Sealed into the report; it never touches
`clean_pass`, because a disclosure is not a violation — it only stops a
clean verdict from pretending to rest on more than the operator's own
custody
(`test_v027_registry_disclosure_states_registrant_and_grade`).

**THE FLOOR.** This is where the descent terminates as EVIDENCE: at this
rung the artifact stops being evidence about the agent and becomes trust
in the operator. The honest output is the grade — and the taxonomy exists
to prevent shipping a stronger-looking one.

**Premise it carried** (howcani, [3hif9](https://dev.to/slabb/a-hash-chain-proves-the-ordering-four-attacks-prove-its-not-enough-59oe#comment-3hif9)):
the operator's key material was still a PEM file or an env var — *"what
stands on it is a premise, not a cipher."* The pin names WHO makes
authority; it does not stop an agent that can read the file from USING
it. That residue is custody, not evidence — one rung down.

## Rung 4 — the keyholder (custody, not evidence)

**What it is**: 0.15.0 — the key material loads ONCE into a dedicated
daemon (`noirebox keyholder`) and never leaves it. The unix socket
(`noirebox-keyholder/0.1`) answers `sign` and `describe`, nothing else —
there is no export op, and an oversized line is dropped by
disconnection. `SocketSigner` duck-types `.sign()` + `.public_hex()`, so
every writer path signs THROUGH the daemon unchanged; Ed25519 is
deterministic, the signatures are byte-identical, and every existing
verifier reads the journal as before. `--allow-uid` gates the peer by
uid and FAILS CLOSED where the peer is not checkable.

**What it closed**: readability of the key bytes. `cat journal.key`
stops being an attack — the bytes are not on any path the agent can
read, and after start the PEM can be removed from the agent-reachable
volume entirely.

**The premise, re-priced**: **reachability of one socket path**
replaces readability of the key bytes. A deployment that wants "the
agent cannot sign" mounts everything EXCEPT the socket. Where agent and
operator share a uid AND the socket, the gate is the filesystem's —
stated, not hidden
(`test_signer_plugs_into_the_store_as_a_drop_in`,
`test_the_material_never_crosses_the_socket`,
`test_uid_gate_enforces`).

**The platform boundary, measured by the 3hkpp probe**: on darwin there
is no peer check at all — `SO_PEERCRED` is Linux-only — so the gate is
**unusable rather than unsafe** (it refuses, fail-closed) and the
premise is carried entirely by the socket's `0600`, **which separates
users, not processes**: row 1 was reachable from another process of the
same uid. Rung 4's residue is rung 3's sentence with one noun changed —
the assertion is no longer "the agent cannot read the key material"
(that half is genuinely closed: no export op, the material never
crosses) but **"the agent does not run as the operator's uid"** — a
deployment property, checkable only where the platform lets you ask.
Which is why the custody mode is a DISCLOSURE field, not something the
artifact can prove: `registry_disclosure(signer_mode=..., uid_gate=...)`
— "enforced" | "off" | "unavailable(<daemon platform>)" |
"undecidable(<reason>)", null when the caller states nothing. The
derivation has been down this ladder too (v0.2.9 — 3hl4l):
`peer_uid_checked` alone answered "could the platform tell" — an UNGATED
daemon on a checkable platform reported it True. And v0.3.0 (3hnok)
found the derivation itself reading PROSE — string-matching
"not the allowed operator" let any error containing the sentence launder
into `enforced`, and the platform in the value was the CALLER's when the
fact belongs to the daemon's host. Now the daemon stamps every refusal
with a machine-readable `error_code` (the not-checkable one carrying the
DAEMON's platform), `SocketSigner.uid_gate()` derives from the code —
never the sentence — and everything it cannot classify reads as the
named state `undecidable(<reason>)`: an old daemon's prose, an unknown
code, a transport failure. Null keeps meaning only "not stated". The
token PIN rides `NOIREBOX_HSM_PIN`, not argv — a CLI-argument PIN sits
in the process table, readable via `ps`.

**Still open**: hardware custody — HSM/PKCS#11 rides the same signer
interface; the key never leaving hardware is the same move one rung
further down.

---

## Where the ladder ends

Below rung 3 there is no crypto left to invoke — only deployment
assertions and the honesty rules that make them auditable:

- **undecidable is never clean** — an unresolved writer, a contested key,
  an uncheckable peer: each reads as a named state, never as silence.
- **a skipped check is reported, never folded into clean**
  (`scope_check_not_run`, `independence NOT RUN`).
- **disclosure is not violation** — the verdict states the registrant and
  the grade; `clean_pass` means "no findings", not "no premises".
- **the premises are on the table** — the next section IS the table.

## The standing premises — the table the next probe reads

| # | premise | what it narrows to | named in |
|---|---|---|---|
| 1 | the registrar pin is supplied out-of-band, by the deployment | the deployment's word on ONE key | ADR 021, §17 amendment |
| 2 | the keyholder's socket is reachable only to those the filesystem + uid gate allow | one path; the gate is platform-bound — Linux checks the peer, darwin has no check at all, so there the 0600 separates USERS, not processes | ADR 020 amendment; 3hkpp |
| 3 | agent and operator do not share uid AND socket | a container/mount assertion — reachability, not readability | ADR 020 amendment |
| 4 | no hardware root under the signing key | HSM/PKCS#11, same signer interface — interface shipped, the silicon still owes the closure | README roadmap |
| 5 | the custody MODE is a disclosure field, not a proof — the journal cannot tell in-process from socket from token | `signer_mode` + `uid_gate` in the disclosure, null when unstated; the gate value reads BOTH daemon facts (off / enforced / unavailable), never `peer_uid_checked` alone | 3hkpp v0.2.8; 3hl4l v0.2.9 |
| 6 | the daemon's ENVIRONMENT is inherited — a same-uid process can read it subject to the kernel's ptrace rules | the PIN lives in the daemon's address space; possession of the address space is a host boundary, not an application property | 3hl4l row 4 |
| 7 | a derived value's meaning is coupled to the wording of the message that carries it | refusals carry `error_code`; the derivation reads the code, never the sentence; the unclassifiable rests at `undecidable(<reason>)` | 3hnok, v0.3.0 — "the strongest token in the vocabulary has the interface's weakest derivation" |

## The receipts

- **The thread**: howcani's descent, each rung probed at the head and
  answered in code — 3h96o (run the validator, seam B) → 3hcbg/3hckg
  (the ceiling) → 3hebj (the probe) → 3hif9 (the floor, "premise not
  cipher") → 3hj95 (the write race, the registered prediction).
- **The ADRs**: 019 (pairing, same-key), 020 (the denominator; the
  keyholder amendment), 021 (independence; the registry, §15; the pin,
  §17), 022 (custody vs anchoring; the grades; "obligation, not
  immunity").
- **The tests**: one per rung closure, named above — each bites at the
  head, not at the description.
