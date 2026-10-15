import json
from typing import Literal

from pydantic import BaseModel, Field, field_validator

# NB-06: an event payload is sealed FOREVER — and POST /api/v1/events is
# reachable by any authenticated client. 256 KiB of canonical JSON is two
# orders of magnitude above every legitimate payload the product emits
# (transcript digests, incident lists, anchor tokens) and far below the
# multi-megabyte bodies a hostile client would use to bloat the journal
# and every future export. ScanIn.text carries the same spirit at 200k.
MAX_PAYLOAD_BYTES = 262_144


class EventIn(BaseModel):
    """Body expected by POST /api/v1/events."""

    type: str = Field(min_length=1, max_length=64, examples=["llm_call"])
    payload: dict = Field(default_factory=dict)

    @field_validator("payload")
    @classmethod
    def _bounded(cls, v: dict) -> dict:
        size = len(json.dumps(v, ensure_ascii=False, sort_keys=True).encode("utf-8"))
        if size > MAX_PAYLOAD_BYTES:
            raise ValueError(
                f"payload exceeds the {MAX_PAYLOAD_BYTES}-byte seal budget "
                f"({size} bytes of JSON) — a payload is sealed forever, "
                f"the journal is not a dumping ground")
        return v


class ScanIn(BaseModel):
    """Body expected by POST /api/v1/transcripts/scan."""

    meeting_id: str = Field(min_length=1, max_length=128)
    text: str = Field(min_length=1, max_length=200_000)


    engine: Literal["regex", "ml", "llm", "tiered"] = "regex"

    lang: Literal["fr", "en", "es"] = Field(
        default="fr",
        description="consumed by the ml, llm and tiered engines; the regex "
                    "patterns are bilingual and deliberately ignore it",
    )


class TokenIn(BaseModel):
    """Body expected by POST /api/v1/token (in-house OAuth2 client-credentials)."""

    client_id: str = Field(min_length=1, max_length=64)
    client_secret: str = Field(min_length=1, max_length=256)
