# Honeypot Network — stats edge API

Cloudflare Worker that serves the honeypot dashboard data (push model).
The analysis host pushes an aggregated snapshot hourly; the Worker
serves it publicly from KV with a 1-hour edge cache. **the analysis host is never
reached by public traffic.**

```
the analysis host  ──POST /ingest (Bearer secret)──►  Worker ──put──►  KV
                                              ▲
Browser ──GET /stats──────────────────────────┘  (cached 1h at the edge)
```

## One-time setup (your Cloudflare account)

You need a Cloudflare account (free tier is enough).

### Option A — Wrangler CLI

```bash
cd infra/stats-worker
npm i -g wrangler
wrangler login

# 1. create the KV namespace, paste the printed id into wrangler.toml
wrangler kv namespace create HONEYPOT_STATS

# 2. generate a strong ingest token and store it as a Worker secret
#    (keep a copy — you'll paste the SAME value on the analysis host below)
openssl rand -hex 32          # copy the output
wrangler secret put INGEST_TOKEN   # paste it when prompted

# 3. deploy
wrangler deploy
```

Deploy prints the public URL, e.g. `https://honeypot-stats.<you>.workers.dev`.

### Option B — Dashboard (no CLI)

1. **Workers & Pages → Create → Worker** → name it `honeypot-stats` → paste
   the contents of `worker.js` in Quick Edit → **Deploy**.
2. **KV → Create namespace** `HONEYPOT_STATS`. In the Worker →
   **Settings → Bindings → Add → KV namespace**: variable `HONEYPOT_STATS`.
3. **Settings → Variables and Secrets → Add → Secret**: name `INGEST_TOKEN`,
   value = a strong random token (`openssl rand -hex 32`). Keep a copy.

## Wire up the analysis host (push side)

On the analysis host, in the enrich toolset, create `.stats.env` with
the **same** token and the Worker's `/ingest` URL:

```bash
cd <enrich-dir>
cat > .stats.env <<'EOF'
STATS_INGEST_URL=https://honeypot-stats.<you>.workers.dev/ingest
STATS_INGEST_TOKEN=<the-same-token>
EOF
chmod 640 .stats.env
```

Test a one-off push, then confirm the public endpoint:

```bash
.venv/bin/python export-stats.py --push
curl -s https://honeypot-stats.<you>.workers.dev/stats | head -c 200
```

The hourly cron (`export-stats.py --push`) is already installed — once
`.stats.env` exists it starts feeding live data automatically.

## Wire up the site (read side)

Point the dashboard at the Worker by setting the build-time env var
(public URL, safe to commit):

```
NEXT_PUBLIC_HONEYPOT_STATS_URL=https://honeypot-stats.<you>.workers.dev/stats
```

Then redeploy the site. Until then it falls back to the bundled mock at
`/data/honeypot-stats.json`.

## Security properties

- the analysis host has **zero inbound exposure** — outbound push only.
- `/ingest` is gated by a Bearer secret (constant-time compared); body is
  size-limited and JSON-validated before storage.
- `/stats` is read-only, public, edge-cached 1h — CF absorbs all read
  traffic; KV is barely touched.
- Only aggregated data is published (no honeypot IP/hostname, no secrets).
- Tighten CORS from `*` to `https://0xrh0d4m1n.tech` in `worker.js` if you
  ever want to restrict it to your site only.
