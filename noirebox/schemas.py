from typing import Literal

from pydantic import BaseModel, Field


class EventIn(BaseModel):
    """Body expected by POST /api/v1/events."""

    type: str = Field(min_length=1, max_length=64, examples=["llm_call"])
    payload: dict = Field(default_factory=dict)


class ScanIn(BaseModel):
    """Body expected by POST /api/v1/transcripts/scan."""

    meeting_id: str = Field(min_length=1, max_length=128)
    text: str = Field(min_length=1, max_length=200_000)


    engine: Literal["regex", "ml", "llm"] = "regex"

    lang: Literal["fr", "en"] = "fr"


class TokenIn(BaseModel):
    """Body expected by POST /api/v1/token (in-house OAuth2 client-credentials)."""

    client_id: str = Field(min_length=1, max_length=64)
    client_secret: str = Field(min_length=1, max_length=256)
