# Security

Threat to Control is a public, unauthenticated Q&A demo that sends user questions and retrieved text to an LLM. This document lists what can go wrong, what stops it, and how each control is verified.

## Reporting a vulnerability

Please open a private security advisory on GitHub (Security → Report a vulnerability) rather than a public issue.

## Threat model

| # | Threat | Control | Verified by |
| --- | --- | --- | --- |
| 1 | **Direct prompt injection**: user tries to override instructions or extract the system prompt | Layer 1 regex heuristics after Unicode normalisation (blocks look-alike and zero-width obfuscation); ambiguous scores go to a Claude Haiku classifier returning strict JSON | `tests/test_security.py`; golden set `injection` cases (target: 100% blocked) |
| 2 | **Classifier bypass by forcing errors**: attacker makes the layer-2 check time out or return junk | Fail closed: any classifier error or malformed output blocks the request | `test_classifier_fails_closed` |
| 3 | **Indirect prompt injection**: instructions hidden inside a retrieved source | Sources wrapped in numbered `<source>` blocks declared as data; tag-like text inside sources and questions is neutralised so it cannot close the block; system prompt forbids following source instructions | `test_neutralize_*`, `test_poisoned_source_cannot_close_the_block`; golden set `indirect` cases (target: 100% resisted) |
| 4 | **System prompt leakage** | Per-process random canary in the system prompt; an output guard holds back the stream tail and withholds the answer if the canary or prompt phrases appear, before they reach the client | `test_output_guard_*`, `test_pipeline_withholds_leaking_answer`; eval counts leaks (target: 0) |
| 5 | **Hallucinated or mis-cited answers** | Answer only from numbered sources; every claim cited; backend validates citation numbers; "not covered" when sources lack the answer | Phase 2 gate; eval faithfulness and citation accuracy (LLM judge), off-topic refusal |
| 6 | **Denial of wallet**: scripted abuse runs up the Anthropic bill | Per-IP limits (default 8/min, 60/day), daily spend cap (default $2, then 503) with a per-request cost reservation so clients that disconnect mid-stream are still counted, input capped at 1,000 chars, answers capped at 1,024 tokens, request bodies over 8 KB rejected | `test_rate_limit_*`, `test_daily_budget_caps_spend`, `test_budget_reservation_*`, `test_rejects_unknown_fields_and_oversized_body` |
| 7 | **IP spoofing to dodge rate limits** | `X-Forwarded-For` is trusted only when `TRUST_PROXY=1`, and then only its right-most entry (appended by the proxy); client-supplied entries are ignored | `test_forwarded_for_uses_proxy_appended_entry` |
| 8 | **Information disclosure through errors or metadata** | Generic client error messages, details only in server logs; `/docs` and OpenAPI schema disabled and `/health` minimal when `APP_ENV=production`; raw IPs never logged (per-process salted hash tag only); question text never logged | `test_pipeline_reports_llm_errors` |
| 9 | **Cross-site abuse** | CORS allows only configured origins, no credentials; security headers (CSP `default-src 'none'`, `X-Frame-Options: DENY`, `nosniff`, `no-referrer`, HSTS in production); `Cache-Control: no-store` | `test_security_headers_present`, `test_cors_only_allows_configured_origin` |
| 10 | **Unexpected input shapes** | Pydantic model forbids extra fields; mode is an enum | `test_rejects_unknown_fields_and_oversized_body` |
| 11 | **Secret leakage** | API keys only in `backend/.env` (git-ignored) or host environment variables; gitleaks in CI; test scans tracked files for key patterns | `test_no_secrets_committed`, CI `secret-scan` job |
| 12 | **Supply chain: remote model code** | `trust_remote_code` only for an allowlist (voyage-4-nano); pin `EMBED_MODEL_REVISION` to a commit hash in production | `test_remote_code_is_allowlisted` |
| 13 | **Vulnerable dependencies** | `pip-audit` in CI on every push; Dependabot weekly | CI `dependency-audit` job |
| 14 | **Hung upstream holding workers** | Claude client timeout (45 s) and bounded retries | `app/llm.py` |

## Accepted dependency advisories

`pip-audit` reports these against **chromadb 1.5.9** (no fixed version yet). All require Chroma's HTTP server mode:

| Advisory | Summary | Why not exploitable here |
| --- | --- | --- |
| PYSEC-2026-311 / CVE-2026-45829 | Code injection via collections endpoint (pre-auth) | No Chroma server runs; we use the embedded `PersistentClient` inside our own process |
| PYSEC-2026-3814 / CVE-2026-45833 | Code injection via collection update endpoint | Same: endpoint does not exist in embedded mode |
| PYSEC-2026-3813 / CVE-2026-45830 | Missing tenant authorization | No multi-tenant server, no Chroma auth |
| PYSEC-2026-3815 / CVE-2026-45831 | RBAC provider ignores tenant scope | Same |

`tests/test_security_config.py` fails if a Chroma server or HTTP client is ever introduced. Re-check these on every chromadb upgrade and remove the CI suppressions once a fixed version ships.

## Production checklist (Render)

- `APP_ENV=production`, `TRUST_PROXY=1`
- `ALLOWED_ORIGINS=https://<your-vercel-domain>` (exact origin, no wildcard)
- `ANTHROPIC_API_KEY` as a Render secret, never in the repo
- `DAILY_COST_CAP_USD`, `RATE_LIMIT_PER_MIN`, `RATE_LIMIT_PER_DAY` set to what you are willing to pay for
- An Anthropic Console spend limit on the key as a second, provider-side cap
- `EMBED_MODEL_REVISION` pinned if using voyage-4-nano

## Known limitations

- Rate limits and the spend cap are in-memory: per process, reset on restart. Use Redis (e.g. Upstash) if running more than one instance.
- No user authentication: this is a public demo by design.
- An LLM classifier and a judge are probabilistic; the golden set measures them but cannot prove the absence of a bypass.
