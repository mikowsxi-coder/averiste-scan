// api/scan.js — Vercel serverless function for POST /api/scan.
// Thin transport adapter: request parsing in, handleScanRequest does the work.
import { handleScanRequest } from '../src/handle-scan.js';

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    res.status(405).json({ error: 'Method not allowed.' });
    return;
  }
  // Vercel's edge sets/overwrites x-forwarded-for itself, so unlike a
  // self-hosted deployment behind no proxy, this header can't be spoofed
  // by the client here.
  const ip = req.headers['x-forwarded-for'] || 'unknown';
  const { status, body } = await handleScanRequest(req.body, ip);
  res.status(status).json(body);
}
