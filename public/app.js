// app.js — front-end logic for Averiste Scan.
const $ = (s) => document.querySelector(s);
document.getElementById('year').textContent = new Date().getFullYear();

const form = $('#scan-form');
const statusEl = $('#status');
const resultsEl = $('#results');
const btn = $('#scan-btn');

const SEV = ['critical', 'high', 'medium', 'low', 'info'];

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  const url = $('#url').value.trim();
  const attest = $('#attest').checked;
  if (!url || !attest) return;

  setStatus('Scanning ' + url + ' … this takes 20–40 seconds.', false);
  resultsEl.hidden = true;
  btn.disabled = true;
  btn.textContent = 'Scanning…';

  try {
    const res = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ url, attestOwnership: attest }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Scan failed.');
    statusEl.hidden = true;
    render(data);
  } catch (err) {
    setStatus(err.message, true);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Scan my app';
  }
});

function setStatus(msg, isError) {
  statusEl.hidden = false;
  statusEl.textContent = msg;
  statusEl.classList.toggle('error', !!isError);
}

function render(data) {
  const { meta, findings, report } = data;
  const s = meta.summary;

  $('#grade').textContent = s.grade;
  const badge = $('#score-badge');
  badge.className = 'score-badge grade-' + s.grade;

  $('#score-line').textContent =
    `Security score ${s.score}/100 — ${s.label} · ${s.total} finding${s.total === 1 ? '' : 's'} across ${meta.checks.length} checks`;

  const pills = $('#sev-pills');
  pills.innerHTML = '';
  for (const sev of SEV) {
    const n = s.counts[sev] || 0;
    const pill = document.createElement('span');
    pill.className = `pill pill-${sev}` + (n === 0 ? ' zero' : '');
    pill.textContent = `${n} ${sev}`;
    pills.appendChild(pill);
  }

  const wrap = $('#findings');
  wrap.innerHTML = '';
  if (!findings.length) {
    const ok = document.createElement('div');
    ok.className = 'finding sev-info';
    ok.innerHTML = `<div class="finding-head"><span class="sev-tag sev-info">clean</span>
      <h3 class="finding-title">No surface issues found</h3></div>
      <p>The surface scan found none of the common leaks. This is a good sign, not a full audit — business logic and multi-user access control were not tested.</p>`;
    wrap.appendChild(ok);
  }
  for (const f of findings) wrap.appendChild(findingCard(f));

  const rb = $('#report-block');
  if (report) {
    $('#report').textContent = report;
    rb.hidden = false;
  } else {
    rb.hidden = true;
  }

  resultsEl.hidden = false;
  resultsEl.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function findingCard(f) {
  const el = document.createElement('div');
  el.className = 'finding sev-' + f.severity;

  const head = document.createElement('div');
  head.className = 'finding-head';
  head.innerHTML =
    `<span class="sev-tag sev-${f.severity}">${f.severity}</span>
     <h3 class="finding-title"></h3>
     <span class="finding-cat"></span>`;
  head.querySelector('.finding-title').textContent = f.title;
  head.querySelector('.finding-cat').textContent = f.category || '';
  el.appendChild(head);

  el.appendChild(para('Why it matters', f.description));

  if (f.evidence) {
    const ev = document.createElement('div');
    ev.className = 'evidence';
    ev.textContent = f.evidence;
    el.appendChild(labelled('Evidence', ev));
  }

  el.appendChild(para('How to fix it', f.fix));

  if (f.fixPrompt) {
    const w = document.createElement('div');
    w.className = 'fixprompt-wrap';
    const lbl = document.createElement('p');
    lbl.innerHTML = '<span class="label">Paste this into your AI tool:</span>';
    const box = document.createElement('div');
    box.className = 'fixprompt';
    box.textContent = f.fixPrompt;
    const btn = document.createElement('button');
    btn.className = 'copy-btn';
    btn.type = 'button';
    btn.textContent = 'Copy fix prompt';
    btn.addEventListener('click', () => {
      navigator.clipboard?.writeText(f.fixPrompt);
      btn.textContent = 'Copied ✓';
      setTimeout(() => (btn.textContent = 'Copy fix prompt'), 1500);
    });
    w.append(lbl, box, btn);
    el.appendChild(w);
  }
  return el;
}

function para(label, text) {
  const p = document.createElement('p');
  p.innerHTML = `<span class="label">${label}:</span> `;
  p.appendChild(document.createTextNode(text || ''));
  return p;
}
function labelled(label, node) {
  const w = document.createElement('div');
  const p = document.createElement('p');
  p.innerHTML = `<span class="label">${label}:</span>`;
  w.append(p, node);
  return w;
}
