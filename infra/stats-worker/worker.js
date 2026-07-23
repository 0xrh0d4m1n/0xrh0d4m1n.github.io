/**
 * Honeypot Network — stats edge API (push model).
 *
 * Routes:
 *   POST /ingest  — the analysis host pushes the latest aggregated snapshot.
 *                   Requires  Authorization: Bearer <INGEST_TOKEN>.
 *                   Stores the body in KV under "latest".
 *   GET  /stats   — public, read-only. Serves the latest snapshot from KV,
 *                   CORS-enabled and edge-cached for one hour.
 *
 * Bindings (see wrangler.toml / dashboard):
 *   HONEYPOT_STATS  — KV namespace
 *   INGEST_TOKEN    — secret (Bearer token for /ingest)
 *
 * The the analysis host host is never reached by public traffic — it only pushes
 * outbound to /ingest. /stats is served entirely from KV + the CF edge cache.
 */

const CACHE_TTL = 3600; // seconds the edge caches /stats
const MAX_BODY = 512 * 1024; // reject snapshots larger than 512 KB

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
};

/** Constant-time string comparison (avoids token timing leaks). */
function safeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: CORS });
    }

    // ── ingest (secret-protected write) ────────────────────────────
    if (url.pathname === "/ingest" && request.method === "POST") {
      const token = (request.headers.get("Authorization") || "").replace(
        /^Bearer\s+/i,
        "",
      );
      if (!env.INGEST_TOKEN || !safeEqual(token, env.INGEST_TOKEN)) {
        return new Response("unauthorized", { status: 401, headers: CORS });
      }
      const body = await request.text();
      if (body.length > MAX_BODY) {
        return new Response("payload too large", { status: 413, headers: CORS });
      }
      try {
        JSON.parse(body); // reject anything that isn't valid JSON
      } catch {
        return new Response("invalid json", { status: 400, headers: CORS });
      }
      await env.HONEYPOT_STATS.put("latest", body, {
        metadata: { updated: Date.now() },
      });
      return new Response("ok", { status: 200, headers: CORS });
    }

    // ── public read ────────────────────────────────────────────────
    if (
      (url.pathname === "/stats" || url.pathname === "/") &&
      request.method === "GET"
    ) {
      const body = await env.HONEYPOT_STATS.get("latest");
      if (!body) {
        return new Response(JSON.stringify({ error: "no data yet" }), {
          status: 503,
          headers: { "Content-Type": "application/json", ...CORS },
        });
      }
      return new Response(body, {
        headers: {
          "Content-Type": "application/json",
          "Cache-Control": `public, max-age=${CACHE_TTL}, s-maxage=${CACHE_TTL}`,
          ...CORS,
        },
      });
    }

    return new Response("not found", { status: 404, headers: CORS });
  },
};
