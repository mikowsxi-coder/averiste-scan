# Averiste Scan

Surface-level security scanner for AI-built web apps (Lovable, Bolt, v0, Cursor
+ Supabase). It finds the **most common, most damaging** mistakes — exposed
keys, open database tables, exposed files, missing headers — using **read-only**
checks. It never writes, modifies, or deletes anything on the target, and it
reads table **row counts**, never row data.

This is the **superficial tier**: deterministic detection of basic leaks. It is
intentionally *not* a penetration test.

---

## Run it

Requires Node 18+.

```bash
cd averiste-scan
npm install
npm start
# open http://localhost:3000
```

Scan the demo target of your choice (one you own). Enter the URL, tick the
ownership box, hit **Scan my app**.

### Optional: AI-written report

The scan works fully without AI. To also get a written report, set:

```bash
export ANTHROPIC_API_KEY=sk-ant-...
export AVERISTE_MODEL=<a current Claude model id>
npm start
```

The report layer runs the findings JSON through `prompts/report-engine.md` at
**temperature 0.1**. If the keys are absent, the app renders the deterministic
findings on its own.

---

## Architecture

```
 Browser (public/)                 Node server (server.js)
 ┌───────────────┐   POST /api/scan   ┌──────────────────────────┐
 │ scan form     │ ─────────────────▶ │ runScan(url)             │
 │ results cards │                    │  ├─ fetch homepage        │
 └───────────────┘ ◀───────────────── │  ├─ scanHeaders           │
        JSON findings + report         │  ├─ scanSecrets (html+js) │
                                        │  ├─ scanSupabaseTables    │  read-only
                                        │  ├─ scanExposedFiles      │  GET / HEAD
                                        │  └─ scanAuthConfig        │
                                        │ generateReport() [AI opt] │
                                        └──────────────────────────┘
```

- `src/checks.js` — every individual check. All GET/HEAD.
- `src/scanner.js` — orchestrates checks, scores, sorts, de-dupes.
- `src/ai.js` — optional AI report (temp 0.1).
- `prompts/report-engine.md` — the full report-engine system prompt.
- `server.js` — Express, `/api/scan`, ownership gate, rate limit.
- `public/` — the UI.

## Scoring

Score = 100 − (critical×30 + high×15 + medium×6 + low×2), floored at 0.
Grade: any critical → F; else high → D; medium → C; low → B; clean → A.

---

## How the checks work

### Exposed secrets
Fetches the homepage and up to 10 linked JS bundles, runs regexes for Stripe /
OpenAI / Anthropic / AWS / Google / GitHub keys and private-key blocks. JWTs are
decoded to read the `role` claim — a `service_role` key in the frontend is
**critical** (it bypasses all row-level security).

### Open Supabase tables (the core "basic leak")
If a Supabase URL + anon key are found in the app itself, it probes ~40 common
table names with:

```
HEAD /rest/v1/<table>?select=*
Headers: apikey, Authorization: Bearer <anon>, Prefer: count=exact, Range: 0-0
```

A `200` + a `Content-Range` row count means the table is readable by the public
key → RLS is off or too permissive. **We use HEAD + count so we learn the table
is open and how many rows it holds without ever pulling a row.** That is the key
safety design: proof of the leak, none of the data.

### Exposed files
GETs `/.env`, `/.git/config`, `/.git/HEAD`, common config files, and source
maps (`<bundle>.js.map`); flags any that return real content.

### Security headers
Checks for CSP, HSTS, X-Content-Type-Options, frame protection, Referrer-Policy.

---

## Injections — how the deeper tier *would* work (not shipped here)

The superficial tier deliberately does **no** injection. When you build the
paid/deep tier, injection is where the real value is, and it must stay safe:

- **Reflected XSS probe** — append a unique harmless canary to query params, GET
  the page, check whether it comes back **unescaped**. Read-only.
- **Error-based SQLi detection** — append a single quote to a parameter and look
  for database error signatures in the response. Detection only; no data
  extraction, no blind/time-based payloads.
- **BOLA / IDOR (the moat)** — the real test: create two throwaway accounts (A
  and B) *in the user's own project*, seed a canary row as B, then try to read
  / edit / delete it **as A** through the app's API. A hit is confirmed only
  when A gets back B's exact canary value. This is what proves a data-isolation
  break, and it is why it can't be faked.

Safety rails for that tier: only against a project the user has proven they own
(OAuth or a pasted service key for *their* project), seed-your-own-canary,
default read-only, destructive steps opt-in and only on staging, full request
log, hard kill switch.

---

## Legal & safety

- **Ownership is gated.** The API refuses a scan unless `attestOwnership` is
  true. Even so, only run this on apps you own or are authorized to test.
  Scanning apps you don't control can be illegal (CFAA and equivalents).
- Read-only, rate-limited (10 scans/min/IP), internal/localhost hosts blocked,
  secrets redacted in all output.
- A clean scan is **not** a certification. Say so to clients.

---

## 4-week MVP plan

**Week 1 — engine.** Ship the surface checks above (done here). Harden the
Supabase probe, expand the table wordlist, add a couple more key patterns. Test
against 15–20 apps you own or from public showcases (passive checks only).

**Week 2 — report + polish.** Wire the AI report layer, tune the prompt, make
the PDF export of a report. Add email capture so a scan produces a lead.

**Week 3 — proof + content.** Run passive checks across public Lovable/Bolt
showcase apps, aggregate the stats ("X of Y exposed a table"), and turn it into
a launch post. That number is your marketing.

**Week 4 — launch + first users.** Post to relevant communities, DM 20 vibe-coder
founders offering a free scan, and line up the deep-tier (BOLA/IDOR) as the paid
upsell for anyone who fails the surface scan.

Positioning: **"Averiste — security testing for anything built with or powered
by AI."** Chatbots and app scans are the first two products on one engine.
