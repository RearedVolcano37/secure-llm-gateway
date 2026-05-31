"""
Pydantic models for request validation and response serialization.
"""

from pydantic import BaseModel, Field, field_validator
from typing import Literal


class ChatRequest(BaseModel):
    message: str = Field(
        ...,
        min_length=1,
        max_length=8000,
        description="User message to send to the LLM",
        examples=["Explain how TLS handshakes work"],
    )
    system_prompt: str | None = Field(
        default=None,
        max_length=2000,
        description="Optional system prompt override",
    )
    model: str = Field(
        default="gpt-4o-mini",
        description="LLM model identifier",
        examples=["gpt-4o-mini", "gpt-4o"],
    )
    max_tokens: int = Field(
        default=1024,
        ge=1,
        le=4096,
        description="Maximum tokens in the LLM response",
    )

    @field_validator("message")
    @classmethod
    def message_not_whitespace(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("message cannot be empty or whitespace")
        return v


class ChatResponse(BaseModel):
    request_id: str
    content: str
    model: str
    tokens_used: int
    latency_ms: int


class HealthResponse(BaseModel):
    status: Literal["ok", "degraded", "down"]
    version: str


class LLMResult(BaseModel):
    """Internal model for upstream LLM responses."""
    content: str
    model: str
    tokens_used: int
