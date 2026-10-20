# NoireBox × Europe — the compliance dossier

*Research as of 25 September 2026, cross-checked 17 October 2026 against the official consolidated French texts: GDPR CELEX 02016R0679 (04.05.2016) and AI Act CELEX 02024R1689 as consolidated 27.07.2026 (including Regulation (EU) 2026/1744). Goal: turn NoireBox into the integrity layer for AI accountability in the EU — not by becoming "an obligation" (no product is), but by becoming the standard instrument for obligations that already exist. Every date and article below was verified against current sources; the Digital Omnibus is factored in.*

---

## 1. Executive summary

The EU now **requires tamper-irrelevant logs — and rewards whoever makes them tamper-evident**.

- The AI Act obliges high-risk systems to **automatically record logs over their lifetime** (art. 12) and deployers/providers to **keep them ≥ 6 months** (art. 19, 26(6)). It checks that logs *exist*. It does **not** check that logs *cannot have been rewritten*. A log the accused can silently rewrite proves nothing — this is the gap the SSRN literature already calls out ("Auditing the Audit Trails", gap between tools and AI Act art. 12 provenance).
- The GDPR (art. 5.2 accountability) requires the controller to **demonstrate** compliance — a self-generated, self-verified journal is weak evidence unless the integrity root sits **outside** the auditee's perimeter.
- eIDAS gives the fix a legal form: a **qualified timestamp** (art. 41) carries a legal presumption of date accuracy and data integrity.

**NoireBox's position, in one sentence:** the tamper-evident journal that closes the AI Act art. 12 / GDPR art. 5.2 evidence gap — hash-chained agent/AI events, anchored by independent third parties (qualified eIDAS TSA for legal weight, public TSAs for immediate free coverage, OpenTimestamps/Bitcoin for trust-minimized long-term), verified by the auditor with roots pinned from public sources, never from the auditee.

---

## 2. The verified calendar (post–Digital Omnibus)

The **Digital Omnibus on AI was adopted as Regulation (EU) 2026/1744** — OJ 24 July 2026, in force **27 July 2026**. It moved the high-risk deadlines and added two prohibitions; it left the transparency and GPAI application dates alone — with **one narrow exception on transparency**: the new **art. 111(4)** (inserted by art. 1(39)(b); recital 38, "a transitional period of four months") gives providers of generative AI systems **already placed on the market before 2 August 2026** until **2 December 2026** to comply with the art. 50(2) marking obligation. Everyone else — every system placed on the market from 2 August 2026, and every art. 50 obligation other than 50(2) — has been in scope since **2 August 2026**. Every date below is the application date set by art. 113 as amended (consolidated text of 27 July 2026), re-verified against the official French consolidation; the art. 111(4) transition was re-verified on 21 October 2026 against the OJ English text.

| Date | What applies | NoireBox angle |
|---|---|---|
| **2 Aug 2025** | GPAI systemic-risk obligations (art. 55): evaluate, mitigate, **"keep track of, document, and report serious incidents"** | **LIVE TODAY** — sealed incident journals are exactly "keep track + document" |
| **2 Feb 2025** | Prohibited practices (art. 5) + AI literacy | LIVE — enforcement needs evidence |
| **2 Aug 2026** | Art. 50 transparency (chatbot disclosure, deepfake/watermark labelling) | **LIVE TODAY** — labelling decisions are events to seal; `marking/0.1` seals the art. 50(2) marking of each generated output, bound to its digest (ADR 030). The only deferral is art. 111(4), next row |
| **2 Dec 2026** | Two new prohibitions (incl. "nudifier"-type apps) enter into force; **end of the art. 111(4) transition** — art. 50(2) marking becomes due for generative systems that were already on the market before 2 Aug 2026 | **Enforcement wave: 2 December 2026** — authorities will demand evidence, and "we marked it" needs a receipt that outlives the file |
| **2 Dec 2027** | **High-risk (Annex III) obligations** — incl. art. 12 logging, art. 19/26(6) log retention ≥ 6 months | **The big wave: 14 months out.** Build now, adopt early |
| **2 Aug 2028** | High-risk embedded in regulated products (Annex I) | Second wave |

Fines are unchanged in substance (art. 99): up to **€35 M / 7 %** of global turnover for prohibited practices; **€15 M / 3 %** tier for most operator obligations (providers, deployers, mandated bodies, transparency); **€7.5 M / 1 %** for supplying inaccurate, incomplete or misleading information to notified bodies or competent authorities. For SMEs including startups each tier caps at the lower of the two amounts (art. 99(6)). The Omnibus hardened enforcement mechanics (reports cite per-day penalties until compliance).

Why the deferral matters to us: the Commission deferred high-risk partly because **CEN-CENELEC JTC 21 harmonized standards aren't ready** — only one standard (EN 18286:2026, QMS) is published; the bulk lands late 2026 onward. **A logging-integrity standard is not yet published — the window to shape what "integrity of logs" means is open now.**

---

## 3. What the law actually says (the obligations NoireBox answers)

### AI Act (Reg. 2024/1689, as amended by 2026/1744)

| Article | Obligation | What it demands from logs |
|---|---|---|
| **Art. 12(1)** | High-risk systems must "technically allow for the **automatic recording of events (logs) over the lifetime of the system**" | Existence, automation, lifetime coverage |
| **Art. 12(2)** | Logs enable traceability: spot risk situations (art. 79(1)), support **post-market monitoring (art. 72)** and **deployer monitoring (art. 26(5))** | Purpose-built event stream |
| **Art. 12(3)** | Minimum contents: (a) **period of each use** (start/end date-time); (b) reference database checked against; (c) input data with a match; (d) **identification of the natural persons involved in verification of results** (art. 14(5)) | Structured fields — a journal event schema maps to this |
| **Art. 11 + Annex IV (2)(f)** | Technical documentation must describe the **logging function and its characteristics** | You must be able to *describe and justify* the logging design — NoireBox becomes a citable component |
| **Art. 19** | Providers keep technical documentation + art. 12 logs **≥ 6 months** | Retention floor |
| **Art. 26(5)–(6)** | Deployers: monitor operation, inform provider; keep logs **≥ 6 months** | Same |
| **Art. 72 / 73** | Post-market monitoring; **serious-incident reporting** to market surveillance authorities. Deadline: **15 days** after knowledge once the causal link is established or reasonably probable (73(2)); **2 days** for wide-scale infractions and art. 3(49)(b) incidents (73(3)); **10 days** in case of a person's death (73(4)). The clock runs from when the provider/deployer *had knowledge* | The deadlines are knowledge-relative: only a timestamped, tamper-evident record can prove *when* you knew — the sealed journal turns a 15-day obligation into a defensible fact |
| **Art. 55(1)(c)** (GPAI systemic risk — **LIVE**) | "keep track of, document, and report, **without undue delay**, serious incidents" | A sealed journal is the cleanest possible "keep track of, document" |
| **Art. 14(5)** | Human oversight: verifiers' actions must be traceable | Seal who verified what, when |
| **Art. 50(2)** (transparency — **LIVE** since 2 Aug 2026; art. 111(4) transition to 2 Dec 2026 for generative systems on the market before 2 Aug 2026) | Providers of systems generating synthetic audio, image, video or text: outputs **marked in a machine-readable format and detectable** as artificially generated or manipulated; three carve-outs (assistive editing, no substantial alteration, authorised by law) | The mark lives in the file and dies with it — the evidence that the marking *happened* must live elsewhere. `marking/0.1` seals it bound to the output's digest, status fails closed, an exemption names its carve-out; `marking_gap` names the output that left unmarked (ADR 030) |

**The gap, stated once and loudly:** every one of these articles presumes the logs are *faithful*. None of them makes falsification *detectable*. The AI Act regulates how logs are produced and kept; it does not regulate whether a methodical insider can rewrite them. That is precisely the NoireBox threat model (`docs/THREAT-MODEL.md`), now closed with external anchoring (ADR 006).

### GDPR (Reg. 2016/679)

- **Art. 5(2) accountability**: the controller must be able to demonstrate compliance. Self-issued evidence with self-held trust roots is weak; **externally anchored, qualified-timestamped evidence is strong**.
- **Art. 30** records of processing, **art. 32** security of processing (integrity!), **art. 33–34** breach notification (72 h — the sealed journal timestamps when the controller *knew*), **art. 22** automated decisions (traceability of the logic), **art. 35** DPIA for high-risk AI (logs feed the assessment).
- **Minimisation, already built**: anchoring sends **only the head hash** out of the infrastructure (ADR 006) — zero personal data leaves. Payload minimisation remains the caller's duty (threat model, out of scope).

### eIDAS (Reg. 910/2014, amended 2024/1183)

- **Art. 41**: a **qualified electronic timestamp** enjoys a legal presumption of the accuracy of the date/time and the integrity of the bound data. This is the only EU-level legal presumption available for "when did this log entry exist" — the legal crown of the anchoring stack.
- French qualified TSA providers (QTST, ANSSI-supervised): **Universign** (`timestamp.universign.eu`), **Certigna/Dhimyotis**, **CertEurope**, **Yousign**, **AR24** — roots pullable from the EU Trusted List ([trustedlist.european-union.eu](https://trustedlist.european-union.eu)), so the auditor's trust anchor is the EU's official list, not our repo's taste.
- RFC 3161 is the wire format everywhere; endpoints are configuration, not code.

### CNIL (the French amplifier)

- **Fiches pratiques IA** (13+ sheets since 2024, usable as a compliance referential for SMEs) + recommandations sur le développement des systèmes d'IA.
- Fiche sécurité **« Tracer les opérations »**: journalisation for anomaly detection and incident response.
- CNIL publishes an open-source **traçabilité tool for open models** (updated 26 Aug 2026); HAS/CNIL joint guide (Mar 2026) for AI in health. The French regulator is *already teaching* traceability — NoireBox is the missing integrity half of that story.

---

## 4. Market whitespace (verified 25 Sept 2026)

Searched for a dominant product at the intersection "tamper-evident AI logs × EU compliance". Result: **no owner**. The space clusters into:

1. **How-tos** (dev.to, Inery "on-chain audit logs", Rends.ai) — content, not product;
2. **Generic SIEM/log integrity** (Splunk et al.) — immutable *storage*, but the root stays inside the vendor/tenant perimeter, no eIDAS legal form;
3. **Academic acknowledgment of the gap** (SSRN "Auditing the Audit Trails": tools fall short of AI Act art. 12 per-prediction provenance);
4. **Sigstore/Rekor, OpenTimestamps** — powerful primitives, dev-oriented, no AI-Act-shaped schema, no GDPR narrative, no auditor workflow.

NoireBox's differentiators, all already in the codebase: agent-native (hooks, MCP server, guardrail → the *events* come from the AI workflow itself), RFC 3161 + eIDAS-ready, offline verifier for the auditor, TOFU→pinning path, FR/EN, sovereign self-host option.

---

## 5. Product shape: what we build (ADR 008–010, v0.3.x → v1.0)

### ADR 008 — Multi-TSA anchoring with pinned roots (the core)

- Config `NOIREBOX_TSA_PROFILES` (JSON list): `{"name", "url" (direct RFC 3161 POST endpoint), "cert_url" (optional; else cert chain extracted from the token — RFC 3161 `certReq`), "kind": "self-hosted" | "public" | "qualified"}`. Legacy `NOIREBOX_TSA_URL` keeps working (single self-hosted profile).
- One `anchor` event carries **all tokens**: flat legacy fields (`tsr`, `tsa_cert_pem`) mirror the **primary** token (first in list = the qualified one) so *old verifiers keep working*; `tokens: [{tsa, tsr, tsa_cert_pem}]` carries the rest for the new verifier.
- Verifier policy: `verifier/tsa_roots/<name>.pem` — if a pinned root exists for the anchor's TSA name, verify against it (strong); else verify against the embedded cert (TOFU, reported as such). Policy is **append-only in practice** (public repo + git history): retired roots stay for past anchors, never deleted. Pin **roots**, let intermediates travel inside the token (they rotate ~yearly; roots live for years).
- Rotation: each anchor = ≥ 1 qualified TSA (legal presumption) + 1 rotating public witness (distribution of trust, no single TSA sees the whole timeline). Anchoring only goes **forward** — coverage gaps are forever; the runbook says never stop.
- Live-validated reference deployments (tested from this machine, `openssl` only): DigiCert `http://timestamp.digicert.com` (token embeds full chain, verifies against public root DigiCert Trusted Root G4), FreeTSA `https://freetsa.org/tsr` (certs: `/files/tsa.crt`, `/files/cacert.pem`, valid to 2040). Qualified endpoints (Universign et al.) are config entries with API access per provider terms.

### ADR 009 — OpenTimestamps layer (compute-grade evidence)

- Optional third witness: `.ots` receipt journaled in the same `anchor` event (base64), stamped via public calendars; pending → Bitcoin-confirmed in ~10 min; verification is **~30 µs of SHA-256** (measured) — expensive to forge, free to verify, no operator to trust, fits 30-year retention without anyone's CA going stale.

### ADR 010 — AI-Act-shaped events ("ai-act" event vocabulary)

- Map art. 12(3) fields onto first-class event types/payload keys: `use_period` (start/end), `reference_db`, `matched_input_hash` (hash, never raw personal data), `human_verifier` (art. 14(5)), `incident` (art. 55(1)(c) / art. 73), `transparency_label` (art. 50 — shipped as `marking/0.1` for the 50(2) marking obligation, ADR 030). Payload hashes give per-prediction provenance without GDPR leakage.
- `noirebox export --audit-pack`: journal export + verifier report + a generated "Annexe IV §2(f) logging characteristics" description of the logging design — the artefact an auditor or notified body asks for.

### Positioning (what we put forward)

Not "we plug into Universign". **"Your AI journal, witnessed by third parties you choose, with legal weight if you want it and compute-grade proof if you need it — verified by your auditor with roots from the EU Trusted List, never from you."** Vendor-neutral, self-hostable, three profiles (`demo` / `public` / `rgpd`), one mechanism.

### The honest limits (stay in the threat model's voice)

- NoireBox is not and cannot "become an obligation" — EU law obliges *behaviours*, not products. The realistic ambition: become the **de facto instrument** cited in DPIAs, Annexe IV documentation and audit packs, like Sigstore did for supply chain.
- No certification claim: NoireBox is not a QTST and gives no legal advice; conformity is the deployer's responsibility. Qualified timestamps are bought from providers; we make them one config line away.
- Self-hosted TSA remains the demo/offline profile — same trust boundary as the operator, documented as such.

---

## 6. Sources (verified 25 Sept 2026)

- AI Act text & articles: artificialintelligenceact.eu (art. 12, 55); consolidated text: eur-lex.europa.eu/eli/reg/2024/1689/oj
- Consolidated French texts cross-checked 17 Oct 2026: GDPR **CELEX 02016R0679** (FR, 04.05.2016) and AI Act **CELEX 02024R1689** (FR, consolidated 27.07.2026, incl. Reg. (EU) 2026/1744 amendments — art. 4 bis, art. 60 bis, art. 75 bis–quinquies, art. 99 d bis, art. 111(2), art. 113)
- Digital Omnibus: Regulation (EU) 2026/1744 — OJ 24 July 2026, in force 27 July 2026 (Annex III → 2 Dec 2027; Annex I → 2 Aug 2028; transparency and GPAI application dates untouched)
- Art. 50(2) transition: Reg. (EU) 2026/1744 art. 1(39)(b) inserting **art. 111(4)** + recital 38 — generative systems placed on the market before 2 Aug 2026 comply with art. 50(2) by 2 Dec 2026; verified 21 Oct 2026 against the OJ English text (eur-lex.europa.eu, OJ:L_202601744)
- European Parliament, "AI Act: deal on simplification measures" (7 May 2026): high-risk obligations from 2 December 2027
- Art. 19/26(6) six-month log retention: ActiveMind, Hannes Snellman, LexLint summaries
- CEN-CENELEC JTC 21: first harmonized standard EN 18286:2026 (22 July 2026, OJ citation pending); bulk expected late 2026+
- eIDAS art. 41 qualified timestamp presumption: eur-lex.europa.eu (910/2014); EU Trusted List: trustedlist.european-union.eu
- TSA endpoints: freetsa.org; timestamp.digicert.com (knowledge.digicert.com); Universign via best-timestamp.com provider directory
- CNIL: cnil.fr — fiches pratiques IA, recommandations développement IA, fiche « Tracer les opérations », outil de traçabilité (26 Aug 2026), guide HAS/CNIL (Mar 2026)
- Whitespace: SSRN "Auditing the Audit Trails"; dev.to/inery.io architecture posts (no dominant product found)
- Live tests performed 25 Sept 2026: DigiCert & FreeTSA RFC 3161 stamping + verification against public roots (OK / tamper → FAILED); OpenTimestamps stamping (4 calendars) + PoW verification cost ≈ 31 µs
