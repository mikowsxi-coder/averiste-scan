// scanner.js — orchestrates the read-only surface checks and returns findings.
import {
  safeFetch, scanSecrets, scanSupabaseTables, scanHeaders,
  scanExposedFiles, scanAuthConfig,
} from './checks.js';

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

function normalizeUrl(input) {
  let u = input.trim();
  if (!/^https?:\/\//i.test(u)) u = 'https://' + u;
  const parsed = new URL(u);
  return { href: parsed.href, origin: parsed.origin };
}

// Fast, cheap rejection for obviously internal hostnames, so a bad target
// fails immediately with a clear message. This is a pre-check only — the
// real enforcement is in net-safety.js's safeFetch, which resolves DNS and
// validates the actual IP on every request, including redirects, so a
// hostname that merely *looks* public but resolves internally is still
// blocked.
function isPublicHost(origin) {
  const host = new URL(origin).hostname;
  if (host === 'localhost' || host.endsWith('.local')) return false;
  if (/^(127\.|10\.|192\.168\.|169\.254\.)/.test(host)) return false;
  if (/^172\.(1[6-9]|2\d|3[0-1])\./.test(host)) return false;
  return true;
}

function extractJsUrls(html, origin) {
  const urls = new Set();
  const re = /<script[^>]+src=["']([^"']+)["']/gi;
  let m;
  while ((m = re.exec(html))) {
    try { urls.add(new URL(m[1], origin).href); } catch { /* skip */ }
  }
  return [...urls];
}

export async function runScan(rawUrl) {
  const { href, origin } = normalizeUrl(rawUrl);
  if (!isPublicHost(origin)) {
    throw new Error('Target must be a public host. Internal/localhost addresses are not scanned.');
  }

  const findings = [];
  const meta = { target: href, origin, startedAt: new Date().toISOString(), checks: [] };

  // 1. fetch homepage
  let html = '';
  let headers = new Headers();
  try {
    const res = await safeFetch(href, {}, 10000);
    headers = res.headers;
    html = await res.text();
    meta.checks.push('homepage');
  } catch (e) {
    throw new Error(`Could not reach target: ${e.message}`);
  }

  // 2. headers
  findings.push(...scanHeaders(headers));
  meta.checks.push('security-headers');

  // 3. gather JS bundles + secret scan across html + bundles
  const jsUrls = extractJsUrls(html, origin);
  const discovered = { supabaseUrl: null, anonKey: null, serviceKey: null };

  const htmlSecrets = scanSecrets(html, 'index.html');
  findings.push(...htmlSecrets.findings);
  mergeDiscovered(discovered, htmlSecrets.discovered);

  for (const js of jsUrls.slice(0, 10)) {
    try {
      const res = await fetchWithTimeout(js, {}, 8000);
      if (res.status !== 200) continue;
      const body = await res.text();
      const s = scanSecrets(body, shortName(js));
      findings.push(...s.findings);
      mergeDiscovered(discovered, s.discovered);
    } catch { /* ignore individual bundle */ }
  }
  meta.checks.push('secret-scan');
  meta.supabaseDetected = !!discovered.supabaseUrl;

  // 4. Supabase-specific checks (only if we found creds in the app itself)
  if (discovered.supabaseUrl && discovered.anonKey) {
    findings.push(...await scanSupabaseTables(discovered.supabaseUrl, discovered.anonKey));
    findings.push(...await scanAuthConfig(discovered.supabaseUrl, discovered.anonKey));
    meta.checks.push('supabase-rls', 'supabase-auth');
  }

  // 5. exposed files + source maps
  findings.push(...await scanExposedFiles(origin, jsUrls));
  meta.checks.push('exposed-files');

  // sort + de-dupe
  const seen = new Set();
  const deduped = findings.filter((f) => {
    const k = f.id + '|' + (f.evidence || '');
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
  deduped.sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity]);

  meta.finishedAt = new Date().toISOString();
  meta.summary = summarize(deduped);

  return { meta, findings: deduped };
}

function summarize(findings) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) counts[f.severity]++;
  const score = Math.max(
    0,
    100 - (counts.critical * 30 + counts.high * 15 + counts.medium * 6 + counts.low * 2)
  );
  let grade = 'A';
  if (counts.critical) grade = 'F';
  else if (counts.high) grade = 'D';
  else if (counts.medium) grade = 'C';
  else if (counts.low) grade = 'B';
  return { counts, score, grade, total: findings.length };
}

function mergeDiscovered(into, from) {
  if (from.supabaseUrl && !into.supabaseUrl) into.supabaseUrl = from.supabaseUrl;
  if (from.anonKey && !into.anonKey) into.anonKey = from.anonKey;
  if (from.serviceKey && !into.serviceKey) into.serviceKey = from.serviceKey;
}
function shortName(u) { try { return new URL(u).pathname.split('/').pop() || 'bundle.js'; } catch { return 'bundle.js'; } }
