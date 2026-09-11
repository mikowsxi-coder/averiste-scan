// checks.js — individual surface-level checks. All are READ-ONLY (GET/HEAD).
// Nothing here writes, updates, or deletes data on the target.

const UA = 'AveristeScan/0.1 (+https://averiste.example/scanner; security self-audit)';

async function fetchWithTimeout(url, opts = {}, ms = 8000) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), ms);
  try {
    return await fetch(url, {
      ...opts,
      redirect: 'follow',
      signal: ctrl.signal,
      headers: { 'User-Agent': UA, ...(opts.headers || {}) },
    });
  } finally {
    clearTimeout(t);
  }
}

// ---------------------------------------------------------------------------
// Secret patterns. Each hit becomes a finding. Severity reflects blast radius.
// ---------------------------------------------------------------------------
const SECRET_PATTERNS = [
  { id: 'supabase_url', name: 'Supabase project URL', severity: 'info',
    re: /https:\/\/([a-z0-9]{20})\.supabase\.co/g },
  { id: 'stripe_secret', name: 'Stripe LIVE secret key', severity: 'critical',
    re: /sk_live_[0-9a-zA-Z]{20,}/g },
  { id: 'stripe_restricted', name: 'Stripe restricted key', severity: 'high',
    re: /rk_live_[0-9a-zA-Z]{20,}/g },
  { id: 'openai_key', name: 'OpenAI API key', severity: 'critical',
    re: /sk-(?:proj-)?[A-Za-z0-9_-]{20,}/g },
  { id: 'anthropic_key', name: 'Anthropic API key', severity: 'critical',
    re: /sk-ant-[A-Za-z0-9_-]{20,}/g },
  { id: 'aws_key', name: 'AWS access key ID', severity: 'critical',
    re: /AKIA[0-9A-Z]{16}/g },
  { id: 'google_key', name: 'Google API key', severity: 'high',
    re: /AIza[0-9A-Za-z_-]{35}/g },
  { id: 'github_pat', name: 'GitHub personal access token', severity: 'critical',
    re: /ghp_[0-9A-Za-z]{36}/g },
  { id: 'private_key', name: 'Private key block', severity: 'critical',
    re: /-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/g },
  { id: 'jwt', name: 'JWT (verify role claim)', severity: 'info',
    re: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}/g },
];

function decodeJwtRole(jwt) {
  try {
    const payload = jwt.split('.')[1];
    const json = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    return json.role || null;
  } catch {
    return null;
  }
}

// Pull secrets out of a blob of text (html or js). Returns findings + any
// discovered Supabase creds so later checks can use them.
export function scanSecrets(text, sourceLabel) {
  const findings = [];
  const discovered = { supabaseUrl: null, anonKey: null, serviceKey: null };

  for (const p of SECRET_PATTERNS) {
    const matches = [...text.matchAll(p.re)];
    for (const m of matches) {
      const value = m[0];

      if (p.id === 'supabase_url') {
        discovered.supabaseUrl = value;
        continue; // URL alone is not a leak; recorded for probing
      }

      if (p.id === 'jwt') {
        const role = decodeJwtRole(value);
        if (role === 'service_role') {
          discovered.serviceKey = value;
          findings.push(finding({
            id: 'exposed_service_role',
            severity: 'critical',
            category: 'Exposed secret',
            title: 'Supabase service_role key exposed in frontend',
            evidence: `${sourceLabel}: ${redact(value)} (role=service_role)`,
            description:
              'The service_role key bypasses ALL row-level security. Anyone who reads it has full read/write/delete on the entire database.',
            fix: 'Remove the service_role key from all client code immediately, rotate it in the Supabase dashboard, and use it only in server-side code / edge functions.',
            fixPrompt:
              'A Supabase service_role key is exposed in my frontend bundle. Remove every use of the service_role key from client-side code. All privileged database access must go through a server route or Supabase Edge Function that holds the key as a secret. Replace client calls with the anon key + proper RLS instead.',
            references: ['https://supabase.com/docs/guides/api/api-keys'],
          }));
        } else if (role === 'anon') {
          discovered.anonKey = value;
          // anon key in frontend is expected — not a finding by itself
        }
        continue;
      }

      // generic secret leak
      findings.push(finding({
        id: p.id,
        severity: p.severity,
        category: 'Exposed secret',
        title: `${p.name} exposed in client code`,
        evidence: `${sourceLabel}: ${redact(value)}`,
        description: `A ${p.name} was found in code shipped to the browser. Anything in the frontend bundle is public.`,
        fix: `Rotate this key now, then move it behind a server route so it is never sent to the browser.`,
        fixPrompt: `A ${p.name} is hardcoded in my frontend and shipped to the browser. Move it to a server-side environment variable, call it only from a backend route, and remove it from all client code. Assume the current key is compromised.`,
        references: [],
      }));
    }
  }
  return { findings, discovered };
}

// ---------------------------------------------------------------------------
// Supabase table exposure — the core "basic leak" check.
// READ-ONLY: uses HEAD + Prefer:count=exact so we learn whether a table is
// publicly readable and how many rows it has WITHOUT pulling any row data.
// ---------------------------------------------------------------------------
const COMMON_TABLES = [
  'profiles', 'users', 'accounts', 'customers', 'orders', 'products',
  'posts', 'messages', 'chats', 'todos', 'tasks', 'subscriptions',
  'payments', 'invoices', 'transactions', 'contacts', 'leads', 'waitlist',
  'emails', 'feedback', 'comments', 'files', 'documents', 'notes',
  'events', 'bookings', 'reservations', 'teams', 'organizations',
  'projects', 'settings', 'api_keys', 'secrets', 'tokens', 'sessions',
  'logs', 'admins', 'user_roles',
];

export async function scanSupabaseTables(supabaseUrl, anonKey) {
  const findings = [];
  if (!supabaseUrl || !anonKey) return findings;

  const readable = [];
  const pool = 6;
  let i = 0;

  async function worker() {
    while (i < COMMON_TABLES.length) {
      const table = COMMON_TABLES[i++];
      const url = `${supabaseUrl}/rest/v1/${table}?select=*`;
      try {
        const res = await fetchWithTimeout(url, {
          method: 'HEAD',
          headers: {
            apikey: anonKey,
            Authorization: `Bearer ${anonKey}`,
            Prefer: 'count=exact',
            Range: '0-0',
          },
        }, 6000);
        if (res.status === 200 || res.status === 206) {
          const cr = res.headers.get('content-range'); // e.g. "0-0/1423" or "*/0"
          const count = cr ? cr.split('/').pop() : '?';
          readable.push({ table, count });
        }
      } catch {
        /* table absent / network — ignore */
      }
    }
  }

  await Promise.all(Array.from({ length: pool }, worker));

  for (const { table, count } of readable) {
    const hasRows = count !== '0' && count !== '*/0';
    findings.push(finding({
      id: `rls_open_${table}`,
      severity: hasRows ? 'critical' : 'high',
      category: 'Broken access control',
      title: `Table "${table}" is publicly readable with the anon key`,
      evidence: `HEAD /rest/v1/${table} → 200, row count: ${count} (no row data was fetched)`,
      description:
        `The "${table}" table returns data to anyone using the public anon key. This means row-level security (RLS) is either disabled or too permissive. Any visitor can read this table.`,
      fix:
        `Enable RLS on "${table}" and add policies that restrict rows to their owner (e.g. auth.uid() = user_id). Verify no policy uses "USING (true)" for anon.`,
      fixPrompt:
        `The Supabase table "${table}" is readable by the public anon key, so RLS is off or too open. Enable Row Level Security on "${table}" and write policies so a user can only read their own rows (match auth.uid() to the owner column). Remove any policy that allows the anon or public role to select all rows. Then confirm an unauthenticated request returns zero rows.`,
      references: [
        'https://supabase.com/docs/guides/database/postgres/row-level-security',
      ],
    }));
  }
  return findings;
}

// ---------------------------------------------------------------------------
// Security headers
// ---------------------------------------------------------------------------
const REQUIRED_HEADERS = [
  { key: 'content-security-policy', name: 'Content-Security-Policy', sev: 'medium' },
  { key: 'strict-transport-security', name: 'Strict-Transport-Security', sev: 'medium' },
  { key: 'x-content-type-options', name: 'X-Content-Type-Options', sev: 'low' },
  { key: 'x-frame-options', name: 'X-Frame-Options / frame-ancestors', sev: 'low' },
  { key: 'referrer-policy', name: 'Referrer-Policy', sev: 'low' },
];

export function scanHeaders(headers) {
  const findings = [];
  const csp = headers.get('content-security-policy');
  for (const h of REQUIRED_HEADERS) {
    // frame-ancestors in CSP satisfies X-Frame-Options
    if (h.key === 'x-frame-options' && csp && /frame-ancestors/i.test(csp)) continue;
    if (!headers.get(h.key)) {
      findings.push(finding({
        id: `missing_header_${h.key}`,
        severity: h.sev,
        category: 'Hardening',
        title: `Missing security header: ${h.name}`,
        evidence: `Response did not include ${h.name}.`,
        description: `The ${h.name} header was not set. This weakens defense against a class of common web attacks.`,
        fix: `Add the ${h.name} header at your host/CDN or in your app's response.`,
        fixPrompt: `Add the HTTP security header "${h.name}" to all responses from my app. Use a sensible default value for a modern web app.`,
        references: ['https://owasp.org/www-project-secure-headers/'],
      }));
    }
  }
  return findings;
}

// ---------------------------------------------------------------------------
// Exposed sensitive files + source maps
// ---------------------------------------------------------------------------
const SENSITIVE_PATHS = [
  { path: '/.env', sev: 'critical', sniff: /[A-Z0-9_]+=/ },
  { path: '/.git/config', sev: 'high', sniff: /\[core\]/ },
  { path: '/.git/HEAD', sev: 'high', sniff: /ref:/ },
  { path: '/config.json', sev: 'medium', sniff: /[:{]/ },
  { path: '/app.config.json', sev: 'medium', sniff: /[:{]/ },
];

export async function scanExposedFiles(origin, jsUrls = []) {
  const findings = [];

  for (const f of SENSITIVE_PATHS) {
    try {
      const res = await fetchWithTimeout(origin + f.path, {}, 6000);
      if (res.status === 200) {
        const body = (await res.text()).slice(0, 400);
        if (f.sniff.test(body)) {
          findings.push(finding({
            id: `exposed_file_${f.path}`,
            severity: f.sev,
            category: 'Exposed file',
            title: `Sensitive file reachable: ${f.path}`,
            evidence: `GET ${f.path} → 200; body starts with: ${redact(body.slice(0, 80))}`,
            description: `The file ${f.path} is served publicly and may contain secrets or source history.`,
            fix: `Block access to ${f.path} at your host and remove it from the deployed build.`,
            fixPrompt: `The file ${f.path} is publicly accessible on my deployed app. Make sure it is not included in the build output and is blocked at the host/CDN. If it contained secrets, rotate them.`,
            references: [],
          }));
        }
      }
    } catch { /* ignore */ }
  }

  // source maps next to JS bundles
  for (const js of jsUrls.slice(0, 8)) {
    try {
      const res = await fetchWithTimeout(js + '.map', {}, 6000);
      if (res.status === 200) {
        const body = (await res.text()).slice(0, 200);
        if (/"version"\s*:\s*3/.test(body) || /sourcesContent/.test(body)) {
          findings.push(finding({
            id: `sourcemap_${hash(js)}`,
            severity: 'low',
            category: 'Information disclosure',
            title: 'Source map exposed in production',
            evidence: `GET ${shortUrl(js)}.map → 200 (contains original source)`,
            description: 'A production source map exposes your original, unminified source code to anyone.',
            fix: 'Disable source map generation for production builds, or stop deploying .map files.',
            fixPrompt: 'My production build ships source maps (.map files), exposing my original source. Turn off source map output for production builds and remove any deployed .map files.',
            references: [],
          }));
        }
      }
    } catch { /* ignore */ }
  }
  return findings;
}

// ---------------------------------------------------------------------------
// Supabase auth settings (public endpoint) — informational
// ---------------------------------------------------------------------------
export async function scanAuthConfig(supabaseUrl, anonKey) {
  const findings = [];
  if (!supabaseUrl || !anonKey) return findings;
  try {
    const res = await fetchWithTimeout(`${supabaseUrl}/auth/v1/settings`, {
      headers: { apikey: anonKey },
    }, 6000);
    if (res.status === 200) {
      const cfg = await res.json();
      if (cfg.disable_signup === false) {
        findings.push(finding({
          id: 'signup_open',
          severity: 'info',
          category: 'Configuration',
          title: 'Public sign-up is enabled',
          evidence: 'GET /auth/v1/settings → disable_signup: false',
          description: 'Anyone can create an account. This is often intended, but confirm it matches your product and that new accounts have no elevated access.',
          fix: 'If self-serve sign-up is not intended, disable it in Supabase Auth settings.',
          fixPrompt: 'Confirm whether public sign-up should be enabled in my Supabase project. If not, disable it. If yes, make sure new users get no admin/elevated role by default.',
          references: [],
        }));
      }
    }
  } catch { /* ignore */ }
  return findings;
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------
function finding(o) { return { ...o }; }

function redact(s) {
  if (!s) return s;
  if (s.length <= 12) return s.slice(0, 3) + '***';
  return s.slice(0, 6) + '…' + s.slice(-4);
}
function shortUrl(u) { try { const x = new URL(u); return x.pathname; } catch { return u; } }
function hash(s) { let h = 0; for (const c of s) h = (h * 31 + c.charCodeAt(0)) | 0; return Math.abs(h).toString(36); }

export { fetchWithTimeout };
