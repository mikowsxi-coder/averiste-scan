// ai.js — OPTIONAL AI report layer.
// If GROQ_API_KEY + AVERISTE_MODEL are set, we send the findings JSON to
// the report-engine prompt via Groq's OpenAI-compatible chat completions
// API, at temperature 0.1. Otherwise we return null and the app renders the
// deterministic report on its own. The scan never depends on AI.
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
  const key = process.env.GROQ_API_KEY;
  const model = process.env.AVERISTE_MODEL; // e.g. openai/gpt-oss-120b
  if (!key || !model) return null;

  const system = await loadPrompt();
  const body = {
    model,
    temperature: 0.1, // deterministic reporting, per house preference
    max_tokens: 3000,
    messages: [
      { role: 'system', content: system },
      { role: 'user', content: 'Here is the scanner output JSON. Write the report.\n\n' + JSON.stringify(result) },
    ],
  };

  try {
    const res = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        authorization: `Bearer ${key}`,
      },
      body: JSON.stringify(body),
    });
    if (!res.ok) return null;
    const data = await res.json();
    return data.choices?.[0]?.message?.content?.trim() || null;
  } catch {
    return null;
  }
}
