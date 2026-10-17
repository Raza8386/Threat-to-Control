"""FastAPI app.

Run from backend/:  uvicorn app.main:app --reload --port 8000
"""

from __future__ import annotations

import json
import os
from contextlib import asynccontextmanager
from typing import Literal

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from app.config import BACKEND_DIR, settings
from app.llm import get_llm
from app.pipeline import answer_events
from app.retrieve import Retriever

STATE: dict = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    STATE["retriever"] = Retriever()  # loads BM25 + vectors once
    yield
    STATE.clear()


app = FastAPI(title="Threat to Control API", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in os.getenv("ALLOWED_ORIGINS", "http://localhost:5173").split(",") if o.strip()],
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


class ChatRequest(BaseModel):
    question: str = Field(..., max_length=4000)  # hard cap; the guardrail enforces the 1000-char product limit
    mode: Literal["hybrid", "vector", "bm25"] = "hybrid"


def _sse(event: str, data) -> str:
    return f"event: {event}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"


@app.post("/api/chat")
def chat(req: ChatRequest) -> StreamingResponse:
    retriever: Retriever = STATE["retriever"]
    llm = get_llm(settings.answer_model)

    def stream():
        for event, data in answer_events(req.question, retriever, llm, mode=req.mode):
            yield _sse(event, data)

    return StreamingResponse(stream(), media_type="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.get("/api/eval/results")
def eval_results():
    path = BACKEND_DIR / "evals" / "results.json"
    if not path.exists():
        raise HTTPException(404, "No eval run yet. Run: python -m evals.run_evals")
    return json.loads(path.read_text(encoding="utf-8"))


@app.get("/health")
def health():
    r: Retriever | None = STATE.get("retriever")
    return {
        "ok": r is not None,
        "chunks": len(r.chunks) if r else 0,
        "vectors": bool(r and r.has_vectors),
        "answer_model": settings.answer_model,
    }
