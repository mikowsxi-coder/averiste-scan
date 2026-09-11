// dev-server.js — zero-dependency Node server for local dev: serves the UI
// and /api/scan without needing the Vercel CLI. Production uses api/scan.js
// instead. Deliberately not named app.js/server.js/index.js at the repo
// root — Vercel's zero-config Express detection claims those names as the
// whole app's entrypoint, which broke the static+api/ deployment shape
// this project actually uses.
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join, extname, normalize } from 'node:path';
import { handleScanRequest } from './src/handle-scan.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PUBLIC = join(__dirname, 'public');
const STATIC_FILES = new Set(['/index.html', '/app.js', '/styles.css']);

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
};

function send(res, code, body, type = 'application/json; charset=utf-8') {
  res.writeHead(code, { 'content-type': type });
  if (typeof body === 'string' || Buffer.isBuffer(body)) return res.end(body);
  res.end(JSON.stringify(body));
}

async function serveStatic(res, urlPath) {
  const clean = normalize(urlPath === '/' ? '/index.html' : urlPath);
  if (!STATIC_FILES.has(clean)) return send(res, 404, 'Not found', 'text/plain');
  const file = join(PUBLIC, clean);
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
    let raw = '';
    req.on('data', (c) => { raw += c; if (raw.length > 262144) req.destroy(); });
    req.on('end', async () => {
      let body;
      try { body = JSON.parse(raw || '{}'); } catch { return send(res, 400, { error: 'Bad JSON.' }); }
      const { status, body: responseBody } = await handleScanRequest(body, ip);
      send(res, status, responseBody);
    });
    return;
  }

  if (req.method === 'GET') return serveStatic(res, req.url.split('?')[0]);
  send(res, 405, 'Method not allowed', 'text/plain');
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Averiste Scan running on http://localhost:${PORT}`));
