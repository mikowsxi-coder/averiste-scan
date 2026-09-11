// server.js — zero-dependency Node server: serves the UI and /api/scan.
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join, extname, normalize } from 'node:path';
import { runScan } from './src/scanner.js';
import { generateReport } from './src/ai.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PUBLIC = join(__dirname, 'public');

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
};

// naive per-process rate limit
const hits = new Map();
function rateLimited(ip) {
  const now = Date.now();
  const arr = (hits.get(ip) || []).filter((t) => now - t < 60_000);
  arr.push(now);
  hits.set(ip, arr);
  return arr.length > 10;
}

function send(res, code, body, type = 'application/json; charset=utf-8') {
  res.writeHead(code, { 'content-type': type });
  res.end(typeof body === 'string' ? body : JSON.stringify(body));
}

async function serveStatic(res, urlPath) {
  const clean = normalize(urlPath === '/' ? '/index.html' : urlPath).replace(/^(\.\.[/\\])+/, '');
  const file = join(PUBLIC, clean);
  if (!file.startsWith(PUBLIC)) return send(res, 403, 'Forbidden', 'text/plain');
  try {
    const data = await readFile(file);
    send(res, 200, data, MIME[extname(file)] || 'application/octet-stream');
  } catch {
    send(res, 404, 'Not found', 'text/plain');
  }
}

const server = createServer(async (req, res) => {
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'local';

  if (req.method === 'GET' && req.url === '/healthz') return send(res, 200, { ok: true });

  if (req.method === 'POST' && req.url === '/api/scan') {
    if (rateLimited(ip)) return send(res, 429, { error: 'Too many scans. Wait a minute.' });
    let raw = '';
    req.on('data', (c) => { raw += c; if (raw.length > 262144) req.destroy(); });
    req.on('end', async () => {
      let body;
      try { body = JSON.parse(raw || '{}'); } catch { return send(res, 400, { error: 'Bad JSON.' }); }
      const { url, attestOwnership } = body;
      if (!url || typeof url !== 'string') return send(res, 400, { error: 'Provide a URL.' });
      if (attestOwnership !== true) {
        return send(res, 403, { error: 'You must confirm you own or are authorized to test this app.' });
      }
      try {
        const result = await runScan(url);
        let report = null;
        try { report = await generateReport(result); } catch { /* AI optional */ }
        send(res, 200, { ...result, report });
      } catch (e) {
        send(res, 400, { error: e.message || 'Scan failed.' });
      }
    });
    return;
  }

  if (req.method === 'GET') return serveStatic(res, req.url.split('?')[0]);
  send(res, 405, 'Method not allowed', 'text/plain');
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Averiste Scan running on http://localhost:${PORT}`));
