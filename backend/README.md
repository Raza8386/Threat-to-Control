# Backend

## Phase 1: build the knowledge base

From this folder, with Python 3.11+:

```bash
python -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -r requirements.txt

python -m ingest.attack        # MITRE ATT&CK Enterprise -> data/chunks/attack.jsonl
python -m ingest.owasp         # OWASP Top 10 2021      -> data/chunks/owasp.jsonl
python -m ingest.kev           # CISA KEV               -> data/chunks/kev.jsonl

python -m ingest.build_index   # BM25 + ChromaDB vectors (downloads voyage-4-nano, ~0.3B params, first run only)
python -m scripts.phase1_check # gate: counts match sources, exact IDs at rank 1
python -m pytest -q            # unit tests
```

Add `--force` to an ingest script to re-download its source (do this for KEV when CISA updates the catalog).

Before the full build, check the speed: `python -m ingest.build_index --speed-test 32` embeds 32 chunks and projects the total time. Sequence length is capped at 768 tokens (`EMBED_MAX_TOKENS`), because uncapped voyage-4-nano runs crawl on CPU.

If the projection is too long for your machine, pick one:

| Option | Set in `.env` / shell | Speed on a laptop CPU | Cost |
| --- | --- | --- | --- |
| voyage-4-nano (default) | `EMBED_BACKEND=nano` | depends on the speed test | free |
| Small local model | `EMBED_BACKEND=local` and `EMBED_MODEL=BAAI/bge-small-en-v1.5` | a few minutes | free |
| Hosted Voyage API | `EMBED_BACKEND=voyage` and `VOYAGE_API_KEY=...` | about 1 minute | small (~600k tokens) |

The query side must use the same model the index was built with; the retriever refuses a mismatch.
`python -m ingest.build_index --bm25-only` builds just the keyword index if you want to test without any model.

## Phase 2: RAG core (streaming answers with citations)

Add your Claude API key to `backend/.env` (never commit it):

```
ANTHROPIC_API_KEY=sk-ant-...
```

Then, from this folder:

```bash
pip install -r requirements.txt
python -m scripts.phase2_check                # gate: 10 questions, every citation resolves to the right source URL
python -m scripts.phase2_check --check-links  # same, and fetches each cited URL
uvicorn app.main:app --reload --port 8000     # API at http://localhost:8000
```

Try the stream from a second terminal (PowerShell: use `curl.exe`):

```bash
curl -N -X POST http://localhost:8000/api/chat -H "Content-Type: application/json" -d "{\"question\": \"How is PowerShell abused and how do I detect it?\"}"
```

Events arrive in order: `guardrail` → `sources` → `token`… → `done` (latency, tokens, cost, cited sources). A blocked question gets `guardrail` then `done`. Full answers from the gate run are saved to `scripts/phase2_report.json`.

Run without a key (offline stand-in model, for wiring checks only): `LLM_BACKEND=fake` (PowerShell: `$env:LLM_BACKEND="fake"`).

Cost: Sonnet 5.5 is $2 / $10 per million input / output tokens; one answer with 6 sources is roughly 3K in + 400 out, about $0.01. Set `ANSWER_MODEL=claude-haiku-5-5` for about 1/20 of that.

## Phase 3: guardrail, security and evals

```bash
pip install -r requirements.txt
python -m pytest -q                                   # 66 unit + security tests, no API calls
python -m evals.run_evals --retrieval-only            # free: hit@5 and MRR for hybrid / vector / bm25
python -m evals.run_evals                             # full gate with the default answer model (~$0.70)
python -m evals.run_evals --models claude-sonnet-5-5,claude-haiku-5-5   # adds a Haiku comparison (~$0.75)
```

The golden set (`evals/golden.yaml`, 60 cases) covers ATT&CK, OWASP, KEV, cross-source, off-topic, direct prompt injection and indirect (poisoned-source) injection. Results go to `evals/results.json`, which `GET /api/eval/results` serves to the Eval page; per-answer detail goes to `evals/answers_detail.json` (git-ignored).

Gate targets: hybrid hit@5 ≥ 90%, faithfulness ≥ 90%, attacks blocked 100% with zero prompt leaks, indirect injection resisted 100%, off-topic refused 100%, false positives 0%.

Security controls and the threat model are in [`SECURITY.md`](../SECURITY.md).

### Layout

| Path | What it does |
| --- | --- |
| `ingest/attack.py` `owasp.py` `kev.py` | Download and chunk each source, one natural unit per chunk |
| `ingest/build_index.py` | BM25 pickle + Chroma collection + `index_manifest.json` |
| `app/retrieve.py` | `Retriever.search(query, mode="hybrid"|"vector"|"bm25")`, RRF k=60, exact-ID boost, one slot for a competitive under-represented source |
| `app/guardrail.py` | Layer 1 regex heuristics; ambiguous cases to a Claude Haiku classifier (fail closed) |
| `app/prompt.py` | System prompt; sources as numbered `<source>` blocks declared as data |
| `app/llm.py` | Claude streaming client with token cost; `FakeLLM` for offline tests |
| `app/pipeline.py` | One question → guardrail, sources, tokens, done; shared by API, gate and evals |
| `app/main.py` | FastAPI: `POST /api/chat` (SSE), `GET /api/eval/results`, `GET /health` |
| `app/embeddings.py` | voyage-4-nano (local), Voyage API, or a hash stand-in for tests |
| `app/text.py` | Tokenizer and ID extraction (T-numbers, CVEs, OWASP A01 to A10) |
| `scripts/phase1_check.py` | Phase 1 gate |
| `scripts/phase2_check.py` | Phase 2 gate |
| `app/security.py` | Rate limiter, daily spend cap, client IP, security headers |
| `evals/golden.yaml` `evals/run_evals.py` | Golden set and the Phase 3 eval runner |
