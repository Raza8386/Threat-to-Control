# Deploying Threat to Control

The backend (API) runs on **Render** and the website on **Vercel**. Both deploy automatically from GitHub on every push to `main`.

```
Browser ──▶ Vercel (website, static files) ──▶ Render (API: search, ECC mapping, Claude) ──▶ Anthropic API
```

Allow about 20 minutes the first time. You need accounts on render.com and vercel.com (sign in with GitHub) and your Anthropic API key.

## 0. Before you start: cap your spend

Every visitor's question is paid from your Anthropic credit. In the Anthropic Console, go to **Settings → Limits** and set a monthly spend limit, for example $10–20. The app's own $2-a-day cap resets when Render restarts the server; the Console limit cannot be bypassed.

## 1. Backend on Render

1. Go to render.com → **New → Blueprint**, connect GitHub, and pick the **Threat-to-Control** repo. Render reads `render.yaml` from the repo.
2. When asked for the secret values, enter:
   - `ANTHROPIC_API_KEY`: your key.
   - `ALLOWED_ORIGINS`: put `https://example.com` for now. You'll replace it in step 3 once Vercel gives you the real address.
3. Click **Apply**. The build downloads ATT&CK, OWASP and KEV and builds the search index, which takes about 3–5 minutes.
4. When the status is **Live**, open `https://<service-name>.onrender.com/health`. You should see `{"ok":true}`. The service name is shown at the top of the Render page; it is `threat-to-control-api` unless that name was taken.

What `render.yaml` sets up:

- **Plan:** free. It sleeps after about 15 minutes idle, and the first visitor then waits about 30–60 seconds. Switch to `starter` to keep it awake.
- **Search:** keyword (BM25) search only. The local embedding model needs more memory than small Render plans provide; the server uses under 100 MB without it.
- **Answers:** Claude Haiku 5.5, about $0.0007 per answer. Sonnet costs roughly 20 times more.
- **Security:** production mode is on (no API docs, minimal `/health`), and rate limits are 8 questions a minute and 60 a day per visitor, with a $2 daily cap.
- **Fresh data:** every deploy downloads the latest ATT&CK and KEV data, so redeploying refreshes it.

## 2. Website on Vercel

1. Go to vercel.com → **Add New → Project** and import the **Threat-to-Control** repo.
2. Set **Root Directory** to `frontend`. Vercel detects Vite, so the build command is `npm run build` and the output folder is `dist`.
3. Under **Environment Variables**, add:
   - `VITE_API_URL` = `https://<service-name>.onrender.com`, with no trailing slash.
   - `VITE_VECTOR_SEARCH` = `off`. This hides the "Meaning" search option, which needs vectors.
4. Click **Deploy**. Note the address Vercel gives you, for example `https://threat-to-control.vercel.app`.

`frontend/vercel.json` already sets the security headers (strict CSP, no framing, HSTS). The CSP allows API calls to `*.onrender.com`; if you host the API elsewhere, add that origin to `connect-src`.

## 3. Connect the two

In Render, open the service → **Environment** and set `ALLOWED_ORIGINS` to your exact Vercel address, for example `https://threat-to-control.vercel.app`, with no trailing slash and no wildcard. Save, and Render redeploys in about a minute.

## 4. Smoke test (Phase 4 gate)

Open the Vercel address and check:

- [ ] A normal question streams an answer with citation chips, and the evidence rail fills.
- [ ] The **NCA ECC controls** section appears under the answer.
- [ ] The injection sample ("Ignore all previous instructions…") is blocked.
- [ ] Asking 9 questions within a minute gets "Too many questions" on the 9th.
- [ ] `https://<service-name>.onrender.com/docs` returns 404.

If the site says "Can't reach the server", check that `VITE_API_URL` matches the Render address exactly, then that `ALLOWED_ORIGINS` matches the Vercel address exactly. After changing a Vercel variable, use **Redeploy**, because Vite variables are fixed at build time.

## 5. After launch

- **Evaluation page:** it shows "No evaluation has been run" until `backend/evals/results.json` is committed. Run `python -m scripts.run_phase3` locally, then commit and push that file.
- **Hybrid search in production (optional):** build the index with the hosted Voyage API (`EMBED_BACKEND=voyage`, `VOYAGE_API_KEY`) and add `chromadb` to `requirements-deploy.txt`. The index and the query embedder must use the same model.
- **Custom domain:** add it in Vercel, then add it to `ALLOWED_ORIGINS` as well, comma-separated.
- See `SECURITY.md` for the full production checklist.
