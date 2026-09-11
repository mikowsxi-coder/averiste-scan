// handle-scan.js — the /api/scan business logic, shared by the plain-Node
// dev server (server.js) and the Vercel function (api/scan.js) so the two
// thin transport adapters can't drift from each other.
import { runScan } from './scanner.js';
import { generateReport } from './ai.js';
import { isRateLimited } from './rate-limit.js';

export async function handleScanRequest(body, ip) {
  if (isRateLimited(ip)) {
    return { status: 429, body: { error: 'Too many scans. Wait a minute.' } };
  }

  const { url, attestOwnership } = body || {};
  if (!url || typeof url !== 'string') {
    return { status: 400, body: { error: 'Provide a URL.' } };
  }
  if (attestOwnership !== true) {
    return { status: 403, body: { error: 'You must confirm you own or are authorized to test this app.' } };
  }

  try {
    const result = await runScan(url);
    let report = null;
    try { report = await generateReport(result); } catch { /* AI report is optional */ }
    return { status: 200, body: { ...result, report } };
  } catch (e) {
    return { status: 400, body: { error: e.message || 'Scan failed.' } };
  }
}
