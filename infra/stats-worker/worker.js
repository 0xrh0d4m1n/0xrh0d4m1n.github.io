/**
 * Honeypot Network — stats edge API (push model).
 *
 * Routes:
 *   POST /ingest      — the analysis host pushes the latest aggregated snapshot.
 *                       Requires  Authorization: Bearer <INGEST_TOKEN>.
 *                       Stores the body in KV under "latest".
 *   GET  /stats       — public, read-only. Serves the latest snapshot from KV,
 *                       CORS-enabled and edge-cached for one hour.
 *   POST /edl/ingest  — pushes the External Dynamic List envelope. Same Bearer.
 *                       Stores it in KV under "edl". SEPARATE key on purpose:
 *                       the dashboard payload must not carry thousands of IPs
 *                       to every browser, and /edl.txt must not pay a JSON
 *                       parse of the whole snapshot on every request.
 *   GET  /edl.txt     — public. One IP per line, text/plain. ETag + 304.
 *   GET  /edl/agg.txt — public. The same list aggregated to /24.
 *
 * KV write budget (free tier: 1000/day) — the reason the two ingests differ:
 *   /ingest      every 2 min  = 720/day   (dashboard needs freshness)
 *   /edl/ingest  hourly       =  24/day   (a blocklist does not)
 *                              ------
 *                                744/day
 *
 * Bindings (see wrangler.toml / dashboard):
 *   HONEYPOT_STATS  — KV namespace
 *   INGEST_TOKEN    — secret (Bearer token for both ingests)
 *
 * The analysis host is never reached by public traffic — it only pushes
 * outbound. Every GET is served from KV + the CF edge cache.
 */

const CACHE_TTL = 3600; // seconds the edge caches /stats
const EDL_TTL = 900; // the EDL is regenerated hourly; 15 min of edge cache
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

    // ── EDL ingest (secret-protected write, hourly) ────────────────
    if (url.pathname === "/edl/ingest" && request.method === "POST") {
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
      let env2;
      try {
        env2 = JSON.parse(body);
      } catch {
        return new Response("invalid json", { status: 400, headers: CORS });
      }
      // A malformed push must never blank a live blocklist: consumers would
      // silently stop blocking and nothing would alert them.
      if (!Array.isArray(env2.ips) || typeof env2.sha256 !== "string") {
        return new Response("missing ips/sha256", { status: 400, headers: CORS });
      }
      await env.HONEYPOT_STATS.put("edl", body, {
        metadata: { updated: Date.now(), count: env2.ips.length },
      });
      return new Response("ok", { status: 200, headers: CORS });
    }

    // ── EDL public read (text/plain, ETag + 304) ───────────────────
    if (
      (url.pathname === "/edl.txt" || url.pathname === "/edl/agg.txt") &&
      request.method === "GET"
    ) {
      const raw = await env.HONEYPOT_STATS.get("edl");
      if (!raw) {
        return new Response("# no data yet\n", {
          status: 503,
          headers: { "Content-Type": "text/plain; charset=utf-8", ...CORS },
        });
      }
      const doc = JSON.parse(raw);
      const agg = url.pathname === "/edl/agg.txt";
      const lines = agg ? doc.agg24 || [] : doc.ips || [];
      // The ETag is content-derived: the publisher hashes the exact bytes of
      // /edl.txt, so an unchanged list reuses the same tag across pushes and a
      // poller gets 304 instead of re-downloading.
      const etag = `"${agg ? "a" : "f"}-${doc.sha256}"`;

      const headers = {
        "Content-Type": "text/plain; charset=utf-8",
        "Cache-Control": `public, max-age=${EDL_TTL}, s-maxage=${EDL_TTL}`,
        ETag: etag,
        "X-HPN-Generated": doc.generated_at || "",
        "X-HPN-Count": String(lines.length),
        "X-HPN-Window-Hours": String(doc.window_h ?? ""),
        "X-HPN-Criteria": JSON.stringify(doc.criteria || {}),
        ...CORS,
      };

      if ((request.headers.get("If-None-Match") || "") === etag) {
        return new Response(null, { status: 304, headers });
      }
      // No comment lines in the body: some firewall parsers choke on them.
      // Everything a human would want lives in the X-HPN-* headers above.
      return new Response(lines.join("\n") + (lines.length ? "\n" : ""), {
        headers,
      });
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
