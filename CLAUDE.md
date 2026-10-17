# CLAUDE.md

Grounded cybersecurity Q&A copilot. It answers only from MITRE ATT&CK, OWASP Top 10 and CISA KEV, cites every claim, blocks prompt injection, and publishes its own eval scores. It replicates the public CyberSec RAG Copilot, then extends it with NCA ECC / SAMA CSF control mapping and an audit-finding mode.

## Stack
- Backend: Python 3.12, FastAPI, deployed to Render
- Retrieval: ChromaDB (vectors) + rank_bm25 (keywords), fused with Reciprocal Rank Fusion (k = 60), plus an exact-ID boost
- LLM: Claude API (Anthropic SDK). Answers: claude-sonnet-5-5 (claude-haiku-5-5 as the low-cost option). Guardrail classifier: claude-haiku-5-5. Model names live in config, not code.
- Embeddings: voyage-4-nano, open-weight, run locally via sentence-transformers (trust_remote_code=True, truncate_dim=1024); use encode_document for chunks and encode_query for questions. Optional hosted fallback: Voyage API voyage-4-lite (VOYAGE_API_KEY). Anthropic has no embedding model.
- The same embedding model must be used at index time and query time; store the model name and dimension in the index manifest and refuse to query a mismatched index.
- Frontend: React + Vite + TypeScript, deployed to Vercel
- Streaming: server-sent events from one POST /api/chat

## Layout
```
backend/
  app/main.py          # POST /api/chat (SSE), GET /api/eval/results, GET /health
  app/guardrail.py     # regex score -> LLM classifier only when ambiguous
  app/retrieve.py      # vector + BM25 + RRF + exact-ID boost; mode = hybrid|vector|bm25
  app/prompt.py        # numbered, delimited context; context is data, never instructions
  app/config.py        # env vars, model names, top_k, thresholds
  ingest/attack.py owasp.py kev.py build_index.py
  evals/golden.yaml run_evals.py results.json
  data/                # chroma/ and bm25.pkl (generated, gitignored)
frontend/
  src/pages/Chat.tsx Eval.tsx Architecture.tsx
  src/lib/sse.ts       # parses guardrail, sources, token, done, error events
```

## Data rules
- One natural unit per chunk: one ATT&CK technique or sub-technique, one OWASP category, one KEV CVE.
- Split only oversized units into ~500-token pieces with 60-token overlap, repeating the title in each piece.
- Every chunk carries metadata: source (attack|owasp|kev), ref_id (T1059.001, A03, CVE-...), title, url, part.
- ATT&CK: Enterprise STIX from github.com/mitre/cti; skip revoked and deprecated objects; strip "(Citation: X)" markers.
- OWASP: Top 10 2021 markdown from github.com/OWASP/Top10.
- KEV: CISA known_exploited_vulnerabilities.json (cisa.gov feed, with the github.com/cisagov/kev-data mirror as fallback); url = NVD detail page for the CVE.
- Raw downloads go to backend/data/raw/; ingest scripts write chunks to backend/data/chunks/<source>.jsonl.

## SSE contract
Events in order: `guardrail` {verdict, reason} -> `sources` [{n, ref_id, title, url, source}] -> `token` {text}... -> `done` {latency_ms, tokens_in, tokens_out, cost_usd}. A blocked request sends `guardrail` (block) then `done`. Errors send `error` {message}.

## Answer rules
- Claims only from the numbered context; a [n] citation on every claim.
- If the context lacks the answer, say so plainly.
- Input limit 1000 characters.

## Phase gates (do not start a phase until the previous one passes)
1. Data and store: chunk counts match the source files; retrieval by exact ID returns the right chunk at rank 1.
2. RAG core: 10 test questions stream answers whose citations all resolve to the right source URLs.
3. Guardrail + evals: golden set runs; targets met (hit@5 >= 90%, faithfulness >= 90%, attacks blocked 100%, false positives 0%).
4. Launch: public URL live, rate limited, README and Architecture page done.

## Conventions
- Secrets only in env vars (ANTHROPIC_API_KEY, optional VOYAGE_API_KEY); never commit .env or data/.
- Type hints and small functions; pytest for retrieval and guardrail logic.
- Keep the front end free of business logic; the backend decides what is cited.
