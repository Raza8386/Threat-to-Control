# Frontend

React + Vite + TypeScript. Three pages: **Ask** (streaming answers with source-coloured citations and an evidence rail), **Evaluation** (reads `GET /api/eval/results`) and **How it works**.

## Run locally

Start the backend first (`uvicorn app.main:app --port 8000` in `backend/`), then:

```bash
cd frontend
npm install
cp .env.example .env.local      # VITE_API_URL=http://localhost:8000
npm run dev                     # http://localhost:5173
```

The backend only accepts browser requests from origins in `ALLOWED_ORIGINS` (default `http://localhost:5173`).

## Checks

```bash
npm test          # SSE parser, citation linking, markdown safety
npm run build     # typecheck + production build
```

## Security

- Model output is rendered as markdown with raw HTML and images dropped. The only links are citation chips pointing at the retrieved source's canonical URL; any other link the model writes is shown as plain text, so a poisoned source cannot plant a clickable link.
- A `reset` event from the API clears partial text (after a model refusal or a withheld answer).
- `vercel.json` sets a strict CSP (no inline scripts or styles, fonts self-hosted, `connect-src` limited to `*.onrender.com`), `frame-ancestors 'none'`, HSTS and no-referrer. If the API is hosted elsewhere, add its origin to `connect-src`.

## Deploy (Vercel)

Root directory `frontend`, build `npm run build`, output `dist`, env var `VITE_API_URL=https://<your-api>.onrender.com`. Then set `ALLOWED_ORIGINS=https://<your-app>.vercel.app` on the backend.
