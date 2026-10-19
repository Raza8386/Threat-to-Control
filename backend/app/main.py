"""FastAPI app.

Run from backend/:  uvicorn app.main:app --reload --port 8000
Production (Render): APP_ENV=production, TRUST_PROXY=1, ALLOWED_ORIGINS=https://<your-vercel-app>
"""

from __future__ import annotations

import json
import logging
import os
from contextlib import asynccontextmanager
from typing import Literal

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, ConfigDict, Field

from app.config import BACKEND_DIR, settings
from app.llm import get_llm
from app.pipeline import answer_events
from app.retrieve import Retriever
from app.security import SECURITY_HEADERS, DailyBudget, RateLimiter, client_ip, ip_tag

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("api")

PRODUCTION = os.getenv("APP_ENV", "development") == "production"
TRUST_PROXY = os.getenv("TRUST_PROXY", "0") == "1"
STATE: dict = {}


def parse_origins(raw: str) -> list[str]:
    """Comma-separated origins, forgiving of spaces, quotes and a trailing slash (browsers send none)."""
    return [o.strip().strip("'\"").rstrip("/") for o in raw.split(",") if o.strip().strip("'\"")]


ALLOWED_ORIGINS = parse_origins(os.getenv("ALLOWED_ORIGINS", "http://localhost:5173"))
log.info("CORS allowed origins: %s", ", ".join(ALLOWED_ORIGINS))


@asynccontextmanager
async def lifespan(app: FastAPI):
    STATE["retriever"] = Retriever()  # loads BM25 + vectors once
    STATE["limiter"] = RateLimiter(
        per_minute=int(os.getenv("RATE_LIMIT_PER_MIN", "8")), per_day=int(os.getenv("RATE_LIMIT_PER_DAY", "60"))
    )
    STATE["budget"] = DailyBudget(cap_usd=float(os.getenv("DAILY_COST_CAP_USD", "2.00")))
    yield
    STATE.clear()


app = FastAPI(
    title="Threat to Control API",
    lifespan=lifespan,
    # No interactive docs or schema on the public deployment.
    docs_url=None if PRODUCTION else "/docs",
    redoc_url=None,
    openapi_url=None if PRODUCTION else "/openapi.json",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
    allow_credentials=False,
    max_age=600,
)

MAX_BODY_BYTES = 8_192


@app.middleware("http")
async def harden(request: Request, call_next):
    length = request.headers.get("content-length")
    if length and length.isdigit() and int(length) > MAX_BODY_BYTES:
        return JSONResponse({"detail": "Request too large."}, status_code=413)
    response = await call_next(request)
    for k, v in SECURITY_HEADERS.items():
        response.headers.setdefault(k, v)
    response.headers.setdefault("Cache-Control", "no-store")
    if PRODUCTION:
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    return response


class ChatRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")  # reject unexpected fields
    question: str = Field(..., min_length=1, max_length=2000)  # hard cap; the guardrail enforces 1000 chars
    mode: Literal["hybrid", "vector", "bm25"] = "hybrid"


def _sse(event: str, data) -> str:
    return f"event: {event}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"


@app.post("/api/chat")
def chat(req: ChatRequest, request: Request) -> StreamingResponse:
    ip = client_ip(request, TRUST_PROXY)
    allowed, retry = STATE["limiter"].check(ip)
    if not allowed:
        raise HTTPException(429, "Too many questions. Please wait and try again.", headers={"Retry-After": str(retry)})
    budget: DailyBudget = STATE["budget"]
    if not budget.available():
        raise HTTPException(503, "The demo has reached its daily usage limit. Please try again tomorrow.")

    retriever: Retriever = STATE["retriever"]
    # Reserve an estimated cost now and reconcile at "done". If the client disconnects mid-stream the
    # reservation stays counted, because Anthropic still bills the tokens generated.
    reserve = float(os.getenv("REQUEST_COST_RESERVE_USD", "0.02"))
    budget.add(reserve)
    try:
        llm = get_llm(settings.answer_model)
        classifier = get_llm(settings.guardrail_model)
        fallback = get_llm(settings.fallback_for(settings.answer_model))
    except RuntimeError as exc:  # e.g. missing API key
        log.error("LLM not configured: %s", exc)
        budget.add(-reserve)
        raise HTTPException(503, "The answer service is not configured.")

    def stream():
        for event, data in answer_events(req.question, retriever, llm, mode=req.mode, classifier_llm=classifier, fallback_llm=fallback):
            if event == "done":
                budget.add(data.get("cost_usd", 0.0) - reserve)
                log.info("chat ip=%s mode=%s blocked=%s refused=%s fallback=%s ms=%s cost=%.5f", ip_tag(ip), req.mode,
                         data.get("blocked"), data.get("refused", False), bool(data.get("fallback_from")),
                         data.get("latency_ms"), data.get("cost_usd", 0.0))
            yield _sse(event, data)

    return StreamingResponse(stream(), media_type="text/event-stream", headers={"X-Accel-Buffering": "no"})


@app.get("/api/eval/results")
def eval_results():
    path = BACKEND_DIR / "evals" / "results.json"
    if not path.exists():
        raise HTTPException(404, "No eval run yet.")
    return json.loads(path.read_text(encoding="utf-8"))


@app.get("/health")
def health():
    r: Retriever | None = STATE.get("retriever")
    info = {"ok": r is not None}
    if not PRODUCTION:  # do not advertise internals publicly
        info.update(chunks=len(r.chunks) if r else 0, vectors=bool(r and r.has_vectors), answer_model=settings.answer_model)
    return info
