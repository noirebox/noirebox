from __future__ import annotations

import io
from datetime import datetime, timezone

from .attestation import build_attestation
from .chain import KeyPair
from .store import EventStore

INK = (0.06, 0.07, 0.09)
RED = (0.88, 0.02, 0.0)
GREY = (0.45, 0.5, 0.55)

# The attestation speaks the reader's language (ADR 005 consequence): EN for
# the default surface, FR for the DPO who files it in a French case record.
# Values that carry IDENTIFIERS (evidence id, hashes, signatures) stay
# language-independent — they are compared byte for byte, not read.
_STRINGS = {
    "en": {
        "doc_title": "NoireBox - Journal Integrity Attestation - {id}",
        "subject": "Technical integrity attestation of an AI-agent journal",
        "banner": "NOIREBOX — JOURNAL INTEGRITY ATTESTATION",
        "h1": "Tamper-proof journal for AI agents",
        "issued": "Issued on {date} at {time} UTC — Algorithm: {algo}",
        "evidence": "Evidence ID: {id} — Format: PDF 1.4 / A4",
        "chain_status": "Chain status",
        "row_height": "Chain height (sealed events)",
        "row_head": "Head fingerprint (SHA-256)",
        "row_validity": "Validity at time of issuance",
        "intact": "INTACT — signature verified",
        "broken": "BROKEN",
        "breakdown": "Event breakdown",
        "use": "Intended use",
        "use_lines": [
            "Internal technical audit record — keep with the corresponding JSON export.",
            "References: GDPR (EU) 2016/679 and AI Act (EU) 2024/1689, as applicable.",
            "This document evidences the observed integrity; it is neither a certification nor legal advice.",
        ],
        "proof": "Cryptographic proof",
        "proof_pubkey": "Instance public key (Ed25519)",
        "proof_signature": "Signature of this attestation",
        "howto": "How to verify this attestation without trusting the issuer",
        "steps": [
            "1. Get the full export from the issuer (GET /api/v1/export).",
            "2. Run the standalone verifier:  python verifier/verifier.py export.json",
            "3. The verifier recomputes the whole chain offline:",
            "   - exit 0: journal intact, the attestation above is confirmed;",
            "   - exit 1: tampering detected, with the exact event number.",
            "No identifying information is required. Verification never contacts",
            "a server: the proof is arithmetic, not a promise.",
        ],
        "foot1": "NoireBox — the black box for AI agents. The core is open source (MIT) and verification stays free forever.",
        "foot2": "This document attests to the state of the journal at the time of issuance; it is not a third-party certification.",
    },
    "fr": {
        "doc_title": "NoireBox - Attestation d'integrite du journal - {id}",
        "subject": "Attestation d'intégrité technique d'un journal d'agent IA",
        "banner": "NOIREBOX — ATTESTATION D'INTÉGRITÉ DU JOURNAL",
        "h1": "Journal inaltérable pour agents IA",
        "issued": "Émis le {date} à {time} UTC — Algorithme : {algo}",
        "evidence": "Identifiant de preuve : {id} — Format : PDF 1.4 / A4",
        "chain_status": "État de la chaîne",
        "row_height": "Hauteur de chaîne (événements scellés)",
        "row_head": "Empreinte de tête (SHA-256)",
        "row_validity": "Validité au moment de l'émission",
        "intact": "INTACTE — signature vérifiée",
        "broken": "CASSÉE",
        "breakdown": "Répartition des événements",
        "use": "Usage prévu",
        "use_lines": [
            "Enregistrement d'audit technique interne — à conserver avec l'export JSON correspondant.",
            "Références : RGPD (UE) 2016/679 et AI Act (UE) 2024/1689, selon le cas.",
            "Ce document atteste de l'intégrité observée ; il ne vaut ni certification ni conseil juridique.",
        ],
        "proof": "Preuve cryptographique",
        "proof_pubkey": "Clé publique de l'instance (Ed25519)",
        "proof_signature": "Signature de cette attestation",
        "howto": "Comment vérifier cette attestation sans faire confiance à l'émetteur",
        "steps": [
            "1. Obtenez l'export complet auprès de l'émetteur (GET /api/v1/export).",
            "2. Exécutez le vérificateur autonome :  python verifier/verifier.py export.json",
            "3. Le vérificateur recalcule toute la chaîne hors-ligne :",
            "   - exit 0 : journal intact, l'attestation ci-dessus est confirmée ;",
            "   - exit 1 : falsification détectée, avec le numéro exact de l'événement.",
            "Aucune information identifiante n'est requise. La vérification ne contacte",
            "jamais de serveur : la preuve est arithmétique, pas une promesse.",
        ],
        "foot1": "NoireBox — la boîte noire des agents IA. Le cœur est open source (MIT) et la vérification reste gratuite pour toujours.",
        "foot2": "Ce document atteste de l'état du journal au moment de l'émission ; il ne constitue pas une certification par un tiers.",
    },
}


def _reportlab():
    """Imports reportlab lazily — the PDF is an optional extra (`noirebox[pdf]`).

    Keeping reportlab out of the core install drops the heaviest dependency
    from `pip install noirebox`; the DPO-ready PDF is a convenience layered
    on top, and a missing extra is a clean error, not a traceback.
    """
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.units import mm
        from reportlab.pdfgen import canvas
    except ImportError as exc:
        raise RuntimeError(
            "PDF attestation requires the optional dependency reportlab — "
            "install it with: pip install noirebox[pdf]"
        ) from exc
    return A4, mm, canvas


def attestation_pdf(store: EventStore, key: KeyPair, lang: str = "en") -> bytes:
    """Builds the attestation PDF (bytes — FastAPI serves it as-is).

    `lang`: "en" (default) or "fr" — the identifiers (evidence id, hashes,
    signature) are language-independent either way; only the prose changes.
    """
    strings = _STRINGS.get(lang)
    if strings is None:
        raise ValueError(f"unsupported attestation language: {lang!r} (en, fr)")
    A4, mm, canvas = _reportlab()
    att = build_attestation(store, key)
    evidence_id = f"NBX-{att['head_hash'][:16].upper()}"

    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=A4, pdfVersion=(1, 4))
    width, height = A4
    margin = 22 * mm
    c.setTitle(strings["doc_title"].format(id=evidence_id))
    c.setAuthor("NoireBox")
    c.setSubject(strings["subject"])
    c.setKeywords("NoireBox, GDPR, AI Act, audit, integrity, A4, attestation")
    c.setCreator("NoireBox API")

    c.setFillColorRGB(*RED)
    c.rect(0, height - 14 * mm, width, 14 * mm, stroke=0, fill=1)
    c.setFillColorRGB(1, 1, 1)
    c.setFont("Helvetica-Bold", 11)
    c.drawString(margin, height - 9.5 * mm, strings["banner"])

    y = height - 32 * mm
    c.setFillColorRGB(*INK)
    c.setFont("Helvetica-Bold", 20)
    c.drawString(margin, y, strings["h1"])
    y -= 8 * mm
    c.setFont("Helvetica", 10)
    c.setFillColorRGB(*GREY)
    generated = datetime.fromisoformat(att["generated_at"]).astimezone(timezone.utc)
    c.drawString(margin, y, strings["issued"].format(
        date=generated.strftime("%d/%m/%Y"), time=generated.strftime("%H:%M"),
        algo=att["algo"]))
    y -= 6 * mm
    c.setFont("Helvetica", 8.5)
    c.drawString(margin, y, strings["evidence"].format(id=evidence_id))

    y -= 14 * mm
    c.setFillColorRGB(*INK)
    c.setFont("Helvetica-Bold", 12)
    c.drawString(margin, y, strings["chain_status"])
    y -= 8 * mm
    c.setFont("Helvetica", 10)
    rows = [
        (strings["row_height"], str(att["head_seq"])),
        (strings["row_head"], att["head_hash"]),
        (strings["row_validity"],
         strings["intact"] if att["chain_valid"] else strings["broken"]),
    ]
    for label, value in rows:
        c.setFillColorRGB(*GREY)
        c.drawString(margin + 2 * mm, y, label)
        c.setFillColorRGB(*INK)

        shown = value if len(value) <= 56 else value[:53] + "…"
        c.setFont("Courier-Bold", 8.4)
        c.drawRightString(width - margin, y, shown)
        c.setFont("Helvetica", 10)
        y -= 6.5 * mm

    y -= 4 * mm
    c.setFillColorRGB(*INK)
    c.setFont("Helvetica-Bold", 12)
    c.drawString(margin, y, strings["breakdown"])
    y -= 7 * mm
    c.setFont("Helvetica", 10)
    for type_, count in sorted(att["event_types"].items()):
        c.setFillColorRGB(*GREY)
        c.drawString(margin + 2 * mm, y, type_)
        c.setFillColorRGB(*INK)
        c.drawRightString(width - margin, y, str(count))
        y -= 6 * mm

    y -= 3 * mm
    c.setFillColorRGB(*INK)
    c.setFont("Helvetica-Bold", 11)
    c.drawString(margin, y, strings["use"])
    y -= 6 * mm
    c.setFont("Helvetica", 8.5)
    for line in strings["use_lines"]:
        c.setFillColorRGB(*GREY if line.startswith(("References", "Références")) else INK)
        c.drawString(margin + 2 * mm, y, line)
        y -= 4.5 * mm

    y -= 4 * mm
    c.setFillColorRGB(*INK)
    c.setFont("Helvetica-Bold", 12)
    c.drawString(margin, y, strings["proof"])
    y -= 7 * mm
    c.setFont("Helvetica", 9)
    for label, value in [
        (strings["proof_pubkey"], att["public_key"]),
        (strings["proof_signature"], att["signature"]),
    ]:
        c.setFillColorRGB(*GREY)
        c.drawString(margin + 2 * mm, y, label)
        y -= 4.5 * mm
        c.setFillColorRGB(*INK)
        c.setFont("Courier", 7.6)

        for i in range(0, len(value), 62):
            c.drawString(margin + 2 * mm, y, value[i : i + 62])
            y -= 3.8 * mm
        c.setFont("Helvetica", 9)
        y -= 2 * mm

    y -= 2 * mm
    c.setFillColorRGB(*RED)
    c.setFont("Helvetica-Bold", 11)
    c.drawString(margin, y, strings["howto"])
    y -= 6 * mm
    c.setFillColorRGB(*INK)
    c.setFont("Helvetica", 9.5)
    for step in strings["steps"]:
        c.drawString(margin + 2 * mm, y, step)
        y -= 5 * mm

    c.setFillColorRGB(*GREY)
    c.setFont("Helvetica-Oblique", 8)
    c.drawString(margin, 14 * mm, strings["foot1"])
    c.drawString(margin, 10 * mm, strings["foot2"])

    c.showPage()
    c.save()
    return buf.getvalue()
