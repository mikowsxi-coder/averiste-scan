// net-safety.js — SSRF-safe HTTP client for the scanner's outbound requests.
//
// The scanner fetches attacker-influenced URLs (the target page, its JS
// bundles, redirect targets, whatever Supabase URL it scrapes out of the
// page). A plain hostname check ("is this string 'localhost'?") does not
// stop a domain that *resolves* to an internal IP or cloud metadata address
// (169.254.169.254), and does not stop a redirect from hopping there after
// the check has already passed. This module closes both gaps: it resolves
// DNS itself, rejects private/internal targets, and pins the connection to
// the exact IP it validated so a same-request DNS change can't reopen the
// gap (DNS rebinding). Redirects are followed manually, one hop at a time,
// re-validating at every hop.
import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import dns from 'node:dns';
import { isIP } from 'node:net';

const UA = 'AveristeScan/0.1 (+https://averiste.com/scan; security self-audit)';
const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

function isPrivateV4(ip) {
  return (
    /^0\./.test(ip) ||                                   // "this" network
    /^10\./.test(ip) ||                                  // RFC1918
    /^127\./.test(ip) ||                                 // loopback
    /^169\.254\./.test(ip) ||                             // link-local / cloud metadata
    /^172\.(1[6-9]|2\d|3[0-1])\./.test(ip) ||             // RFC1918
    /^192\.168\./.test(ip) ||                             // RFC1918
    /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./.test(ip) || // CGNAT 100.64.0.0/10
    /^(22[4-9]|23\d)\./.test(ip) ||                       // multicast 224.0.0.0/4
    /^(24\d|25[0-5])\./.test(ip)                          // reserved/broadcast 240.0.0.0/4
  );
}

function isPrivateV6(ip) {
  const lower = ip.toLowerCase();
  if (lower === '::' || lower === '::1') return true; // unspecified / loopback
  if (lower.startsWith('fe80:')) return true;          // link-local
  if (lower.startsWith('fc') || lower.startsWith('fd')) return true; // unique local
  if (lower.startsWith('::ffff:')) {                   // IPv4-mapped
    const v4 = lower.split(':').pop();
    if (isIP(v4) === 4) return isPrivateV4(v4);
  }
  return false;
}

export function isPrivateIp(ip) {
  const version = isIP(ip);
  if (version === 4) return isPrivateV4(ip);
  if (version === 6) return isPrivateV6(ip);
  return true; // couldn't parse it — don't trust it
}

async function resolveValidatedIp(hostname) {
  if (isIP(hostname)) {
    if (isPrivateIp(hostname)) throw new Error(`Refusing to contact ${hostname}: private/internal address.`);
    return hostname;
  }
  let records;
  try {
    records = await dns.promises.lookup(hostname, { all: true, verbatim: true });
  } catch {
    throw new Error(`Could not resolve ${hostname}.`);
  }
  if (!records.length) throw new Error(`Could not resolve ${hostname}.`);
  for (const { address } of records) {
    if (isPrivateIp(address)) {
      throw new Error(`Refusing to contact ${hostname}: resolves to a private/internal address (${address}).`);
    }
  }
  return records[0].address;
}

function collectBody(res, maxBytes = 5_000_000) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    res.on('data', (c) => {
      size += c.length;
      if (size > maxBytes) { res.destroy(); reject(new Error('Response too large.')); return; }
      chunks.push(c);
    });
    res.on('end', () => resolve(Buffer.concat(chunks)));
    res.on('error', reject);
  });
}

function wrapResponse(nodeRes, bodyBuffer) {
  const headers = new Map();
  for (const [k, v] of Object.entries(nodeRes.headers)) {
    headers.set(k.toLowerCase(), Array.isArray(v) ? v.join(', ') : v);
  }
  return {
    status: nodeRes.statusCode,
    headers: { get: (name) => headers.get(String(name).toLowerCase()) ?? null },
    text: async () => bodyBuffer.toString('utf8'),
    json: async () => JSON.parse(bodyBuffer.toString('utf8')),
  };
}

// Drop-in-ish replacement for `fetch(url, opts)` with an added timeout and
// redirect-hop budget. Only the subset of the Response API the scanner
// actually uses (status/headers.get/text/json) is implemented.
export async function safeFetch(urlString, opts = {}, timeoutMs = 8000, redirectsLeft = 5) {
  const url = new URL(urlString);
  if (!/^https?:$/.test(url.protocol)) throw new Error('Only http/https URLs are allowed.');

  const pinnedIp = await resolveValidatedIp(url.hostname);
  const requestFn = url.protocol === 'https:' ? httpsRequest : httpRequest;
  const method = opts.method || 'GET';

  const nodeRes = await new Promise((resolve, reject) => {
    const req = requestFn(
      {
        hostname: pinnedIp,
        servername: url.protocol === 'https:' ? url.hostname : undefined, // keep TLS SNI + cert check on the real name
        port: url.port || (url.protocol === 'https:' ? 443 : 80),
        path: url.pathname + url.search,
        method,
        timeout: timeoutMs,
        headers: { host: url.host, 'user-agent': UA, ...(opts.headers || {}) },
      },
      resolve,
    );
    req.on('timeout', () => req.destroy(new Error('Request timed out.')));
    req.on('error', reject);
    req.end();
  });

  const bodyBuffer = await collectBody(nodeRes);
  const res = wrapResponse(nodeRes, bodyBuffer);

  const location = nodeRes.headers.location;
  if (REDIRECT_STATUSES.has(res.status) && location) {
    if (redirectsLeft <= 0) throw new Error('Too many redirects.');
    const next = new URL(location, url);
    return safeFetch(next.href, opts, timeoutMs, redirectsLeft - 1);
  }
  return res;
}
