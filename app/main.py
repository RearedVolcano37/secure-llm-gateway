"""
Secure LLM Gateway — main FastAPI application.
Wraps any OpenAI-compatible LLM API with auth, rate limiting,
prompt filtering, and audit logging.
"""

from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import time
import uuid

from app.auth import verify_api_key
from app.rate_limiter import RateLimiter
from app.prompt_filter import PromptFilter
from app.audit_logger import AuditLogger
from app.models import ChatRequest, ChatResponse, HealthResponse
from app.llm_client import call_llm

# ── Shared singletons ────────────────────────────────────────────────────────
rate_limiter = RateLimiter(max_requests=20, window_seconds=60)
prompt_filter = PromptFilter()
audit_logger = AuditLogger(log_path="logs/audit.jsonl")


@asynccontextmanager
async def lifespan(app: FastAPI):
    audit_logger.setup()
    yield
    audit_logger.close()


app = FastAPI(
    title="Secure LLM Gateway",
    description="Production-grade security layer for LLM-powered applications",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["POST", "GET"],
    allow_headers=["Authorization", "Content-Type"],
)


# ── Routes ───────────────────────────────────────────────────────────────────

@app.get("/health", response_model=HealthResponse, tags=["System"])
async def health():
    """Liveness probe — no auth required."""
    return HealthResponse(status="ok", version="1.0.0")


@app.post("/v1/chat", response_model=ChatResponse, tags=["Gateway"])
async def chat(
    request: Request,
    body: ChatRequest,
    api_key: str = Depends(verify_api_key),
):
    """
    Secure chat endpoint. Pipeline:
      1. Authenticate (API key)
      2. Rate-limit per key
      3. Scan prompt for injection / policy violations
      4. Forward to upstream LLM
      5. Audit-log full interaction
    """
    request_id = str(uuid.uuid4())
    client_ip = request.client.host
    start_ts = time.time()

    # ── 1. Rate limiting ─────────────────────────────────────────────────────
    allowed, retry_after = rate_limiter.check(api_key)
    if not allowed:
        audit_logger.log(
            request_id=request_id,
            api_key_hint=api_key[:8] + "…",
            client_ip=client_ip,
            prompt=body.message,
            decision="rate_limited",
            latency_ms=0,
        )
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded. Retry after {retry_after}s.",
            headers={"Retry-After": str(retry_after)},
        )

    # ── 2. Prompt filtering ──────────────────────────────────────────────────
    scan = prompt_filter.scan(body.message)
    if scan.blocked:
        audit_logger.log(
            request_id=request_id,
            api_key_hint=api_key[:8] + "…",
            client_ip=client_ip,
            prompt=body.message,
            decision="blocked",
            block_reason=scan.reason,
            latency_ms=0,
        )
        raise HTTPException(
            status_code=400,
            detail={"error": "prompt_rejected", "reason": scan.reason},
        )

    # ── 3. Forward to LLM ───────────────────────────────────────────────────
    llm_response = await call_llm(
        message=body.message,
        system_prompt=body.system_prompt,
        model=body.model,
        max_tokens=body.max_tokens,
    )

    latency_ms = round((time.time() - start_ts) * 1000)

    # ── 4. Audit log ─────────────────────────────────────────────────────────
    audit_logger.log(
        request_id=request_id,
        api_key_hint=api_key[:8] + "…",
        client_ip=client_ip,
        prompt=body.message,
        response=llm_response.content,
        model=llm_response.model,
        tokens_used=llm_response.tokens_used,
        decision="allowed",
        latency_ms=latency_ms,
    )

    return ChatResponse(
        request_id=request_id,
        content=llm_response.content,
        model=llm_response.model,
        tokens_used=llm_response.tokens_used,
        latency_ms=latency_ms,
    )
