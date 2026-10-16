"""The tiered scan (ADR 001's full pipeline): regex → ML → judge on doubt.

Design (ADR 016): the cheapest engine sees everything; the judge pays only
for doubt. Stage 1 is the free, deterministic regex; stage 2 is the ML model
with its documented 0.5 threshold; stage 3 escalates ONLY the lines that
both stages left unflagged while the ML did not call confidently clean —
the doubt band [DOUBT_LOW, 0.50) — to the local judge (ADR 015), which
arbitrates them with a binary verdict. A line the ML confidently calls
clean is NOT judged: `engine="llm"` is the choice for full-coverage
judgment, `engine="tiered"` is the choice for automatic escalation.

Degradation is visible, never silent: if doubtful lines exist but the judge
is unavailable, stages 1–2 stand and the count of unarbitrated lines travels
in the payload (`judge_skipped`) — the journal records exactly how much
doubt went unanswered.
"""
from __future__ import annotations

from .guardrail import Incident, scan_transcript
from .llm_judge import judge_available, scan_llm
from .ml_guardrail import predict_line

DOUBT_LOW = 0.20
ML_THRESHOLD = 0.5


def _overlaps(start: int, end: int, spans: list[dict]) -> bool:
    """Same span test the guarded pipeline filters with."""
    return any(span["end"] > start and span["start"] < end for span in spans)


def scan_tiered(text: str, lang: str = "fr") -> tuple[list[dict], dict]:
    """Runs the three stages, returns (incidents, tiering meta).

    Incidents are dicts in the SPECS §4 shape; a stage-2 detection whose
    span a stage-1 regex incident already covers is dropped (the regex is
    the deterministic naming of that line — duplicates would double-count
    one attack in the audit report).
    """
    incidents: list[dict] = [i.as_dict() for i in scan_transcript(text)]
    nb_regex = len(incidents)

    # Stage 2: per-line ML with the doubt band recorded along the way.
    nb_ml = 0
    doubtful: list[dict] = []  # {"start", "end"} spans
    offset = 0
    for raw in text.splitlines():
        start, end = offset, offset + len(raw)
        offset = end + 1
        line = raw.strip()
        if not line:
            continue
        detection = predict_line(line, lang=lang)
        if detection.category == "clean":
            continue
        if detection.score >= ML_THRESHOLD:
            if not _overlaps(start, end, incidents):
                incidents.append({**detection.as_dict(), "start": start, "end": end})
                nb_ml += 1
        elif detection.score >= DOUBT_LOW and not _overlaps(start, end, incidents):
            doubtful.append({"start": start, "end": end})

    # Stage 3: the judge arbitrates the doubt band — nothing else.
    nb_judge = 0
    judge_skipped = 0
    if doubtful:
        if judge_available():
            for inc in scan_llm(text, lang=lang):
                inc_dict = inc.as_dict() if isinstance(inc, Incident) else inc
                if _overlaps(inc_dict["start"], inc_dict["end"], doubtful):
                    incidents.append(inc_dict)
                    nb_judge += 1
        else:
            judge_skipped = len(doubtful)

    meta = {"regex": nb_regex, "ml": nb_ml, "judge": nb_judge,
            "doubtful": len(doubtful), "judge_skipped": judge_skipped}
    return incidents, meta
