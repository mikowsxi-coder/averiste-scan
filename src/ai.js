// ai.js — OPTIONAL AI report layer.
// If ANTHROPIC_API_KEY + AVERISTE_MODEL are set, we send the findings JSON to
// the report-engine prompt at temperature 0.1. Otherwise we return null and the
// app renders the deterministic report on its own. The scan never depends on AI.
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));

let SYSTEM_PROMPT = null;
async function loadPrompt() {
  if (SYSTEM_PROMPT) return SYSTEM_PROMPT;
  SYSTEM_PROMPT = await readFile(join(__dirname, '..', 'prompts', 'report-engine.md'), 'utf8');
  return SYSTEM_PROMPT;
}

export async function generateReport(result) {
  const key = process.env.ANTHROPIC_API_KEY;
  const model = process.env.AVERISTE_MODEL; // e.g. a current Claude model id
  if (!key || !model) return null;

  const system = await loadPrompt();
  const body = {
    model,
    max_tokens: 3000,
    temperature: 0.1, // deterministic reporting, per house preference
    system,
    messages: [
      { role: 'user', content: 'Here is the scanner output JSON. Write the report.\n\n' + JSON.stringify(result) },
    ],
  };

  try {
    const res = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-api-key': key,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify(body),
    });
    if (!res.ok) return null;
    const data = await res.json();
    return (data.content || []).map((c) => c.text || '').join('').trim() || null;
  } catch {
    return null;
  }
}
