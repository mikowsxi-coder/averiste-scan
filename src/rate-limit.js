// rate-limit.js — naive per-process rate limit shared by both the local
// dev server and the Vercel function. Best-effort: on Vercel this resets on
// every cold start and isn't shared across concurrent instances, so it
// throttles casual abuse but is not a hard cap. A durable limiter (e.g.
// Upstash Redis) would be needed to make it authoritative under scale.
const hits = new Map();

export function isRateLimited(key, max = 10, windowMs = 60_000) {
  const now = Date.now();
  const arr = (hits.get(key) || []).filter((t) => now - t < windowMs);
  arr.push(now);
  hits.set(key, arr);
  if (hits.size > 5000) {
    for (const [k, v] of hits) {
      if (!v.some((t) => now - t < windowMs)) hits.delete(k);
    }
  }
  return arr.length > max;
}
