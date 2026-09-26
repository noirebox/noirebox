from __future__ import annotations

import re
from dataclasses import dataclass


ATTACK_PATTERNS: list[tuple[str, float, list[str]]] = [
    (
        "instruction_override",
        0.9,
        [

            (
                r"ignor\w*\s+(les|toutes?\s+les|tout|ton|ta|le|la|previous|all|your)\s+"
                r"(instructions?|consignes?|règles?|prompt)"
            ),
            r"oublie\s+(tout|ton\s+prompt|tes?\s+instructions|les\s+instructions)",
            r"tu\s+(es|deviens)\s+(désormais|maintenant|dorénavant)",
            r"nouvelles?\s+instructions?",
            r"à\s+partir\s+de\s+maintenant",
            r"\bsystem\s+prompt\b",
        ],
    ),
    (
        "data_exfiltration",
        0.95,
        [

            r"(envoie|transmets?|exfiltr\w+|forward)\s+[^.?!]{0,60}\S+@\S+\.\S+",

            r"(envoie|transmets?|exfiltr\w+)\s+[^.?!]{0,60}(https?://|ftp://)\S+",
            r"(publie|télévers\w+|upload)\s+[^.?!]{0,40}\S+@\S+\.\S+",
        ],
    ),
    (
        "pii_request",
        0.8,
        [


            (
                r"(donne|donnez|révèle\w*|récupère|extrais|list\w+|envoie)\s*"
                r"(?:-)?\s*(?:moi|nous)?\s*[^.?!]{0,50}"
                r"(mots?\s+de\s+passe|passwords?|numéros?\s+de\s+carte|"
                r"IBAN|données?\s+(personnelles|bancaires|sensibles)|salaires?)"
            ),
        ],
    ),
    (
        "tool_abuse",
        0.85,
        [
            r"\brm\s+-rf\b",
            r"\bDROP\s+TABLE\b",
            r"\bDELETE\s+FROM\b",
            r"\bsupprime\s+(toutes?\s+les\s+données|la\s+base|tout\s+le\s+contenu)",
            r"\b(exécute|execute|run)\s+(la\s+commande|cette\s+commande|curl|bash)\b",
        ],
    ),
]


_COMPILED = [
    (cat, weight, [re.compile(p, re.IGNORECASE) for p in patterns])
    for cat, weight, patterns in ATTACK_PATTERNS
]


@dataclass
class Incident:
    """A detection: what, how severe, where in the text."""

    category: str
    score: float
    excerpt: str
    start: int
    end: int

    def as_dict(self) -> dict:
        return {
            "category": self.category,
            "score": self.score,
            "excerpt": self.excerpt,
            "start": self.start,
            "end": self.end,
        }


def scan_transcript(text: str) -> list[Incident]:
    """Scans a text, returns the incidents sorted by position.

    Why sort by position: the audit report must read like the flow of the
    meeting, not in regex order (which is constant per category).
    """
    incidents: list[Incident] = []
    for category, weight, regexes in _COMPILED:
        for regex in regexes:
            for match in regex.finditer(text):
                excerpt = match.group(0).strip()
                if len(excerpt) > 120:
                    excerpt = excerpt[:117] + "…"
                incidents.append(Incident(category, weight, excerpt, match.start(), match.end()))
    incidents.sort(key=lambda i: i.start)
    return incidents
