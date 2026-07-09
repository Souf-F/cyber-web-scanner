const form = document.getElementById('scan-form');
const input = document.getElementById('target-input');
const btn = document.getElementById('scan-btn');
const terminal = document.getElementById('terminal');
const termBody = document.getElementById('terminal-body');
const results = document.getElementById('results');

const STEPS = [
  'résolution DNS et connexion...',
  'analyse des en-têtes HTTP...',
  'vérification du certificat TLS...',
  'scan des ports courants...',
  'détection des technologies...',
];

function termLine(text, cls = '') {
  const el = document.createElement('div');
  if (cls) el.className = cls;
  el.textContent = `> ${text}`;
  termBody.appendChild(el);
  return el;
}

async function playTerminal() {
  termBody.innerHTML = '';
  terminal.classList.remove('hidden');
  for (const step of STEPS) {
    termLine(step, 'line-dim');
    await new Promise(r => setTimeout(r, 260));
  }
}

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  const target = input.value.trim();
  if (!target) return;

  btn.disabled = true;
  btn.textContent = 'Analyse en cours...';
  results.classList.add('hidden');

  await playTerminal();

  try {
    const res = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target }),
    });
    const data = await res.json();

    if (!res.ok) {
      termLine(`erreur: ${data.error}`, 'line-warn');
    } else {
      termLine('analyse terminée.', '');
      renderResults(data);
    }
  } catch (err) {
    termLine(`erreur réseau: ${err.message}`, 'line-warn');
  } finally {
    btn.disabled = false;
    btn.textContent = "Lancer l'analyse";
  }
});

function badgeClass(level) {
  return { good: 'badge--good', warn: 'badge--warn', bad: 'badge--bad' }[level] || '';
}

function renderResults(data) {
  results.classList.remove('hidden');

  // Score ring
  const score = data.score ?? 0;
  const circumference = 326.7; // 2 * PI * 52 (ring radius)
  const offset = circumference - (circumference * score) / 100;
  const ring = document.getElementById('ring-fg');
  ring.style.strokeDashoffset = offset;
  ring.style.stroke = score >= 75 ? 'var(--green)' : score >= 45 ? 'var(--amber)' : 'var(--red)';

  document.getElementById('score-number').textContent = score;
  document.getElementById('score-target').textContent = data.hostname || data.url;
  document.getElementById('score-label').textContent =
    score >= 75 ? 'Exposition faible' : score >= 45 ? 'Exposition modérée' : 'Exposition élevée';

  // Headers card
  const h = data.headers || {};
  const headersBadge = document.getElementById('headers-badge');
  const headersMeta = document.getElementById('headers-meta');
  const headersList = document.getElementById('headers-list');
  headersMeta.innerHTML = '';
  headersList.innerHTML = '';

  if (h.error) {
    headersBadge.textContent = 'erreur';
    headersBadge.className = 'badge badge--bad';
    headersList.innerHTML = `<li>${h.error}</li>`;
  } else {
    const missing = h.missing?.length || 0;
    headersBadge.textContent = missing === 0 ? 'complet' : `${missing} manquant(s)`;
    headersBadge.className = `badge ${badgeClass(missing === 0 ? 'good' : missing <= 2 ? 'warn' : 'bad')}`;
    headersMeta.innerHTML = `
      <dt>statut</dt><dd>${h.status_code}</dd>
      <dt>serveur</dt><dd>${h.server}</dd>`;
    if (missing === 0) {
      headersList.innerHTML = '<li class="ok">✓ Tous les en-têtes vérifiés sont présents</li>';
    } else {
      headersList.innerHTML = h.missing
        .map(m => `<li><strong>${m.name}</strong>
          <span class="finding-desc">${m.desc}</span>
          <span class="finding-risk">⚠ Risque : ${m.risk}</span>
          <code class="finding-fix">${m.fix}</code>
        </li>`)
        .join('');
    }
  }

  // SSL card
  const s = data.ssl || {};
  const sslBadge = document.getElementById('ssl-badge');
  const sslMeta = document.getElementById('ssl-meta');
  if (s.error) {
    sslBadge.textContent = 'erreur';
    sslBadge.className = 'badge badge--bad';
    sslMeta.innerHTML = `<dt>erreur</dt><dd>${s.error}</dd>`;
  } else {
    const level = !s.valid ? 'bad' : s.days_left < 30 ? 'warn' : 'good';
    sslBadge.textContent = s.valid ? 'valide' : 'expiré';
    sslBadge.className = `badge ${badgeClass(level)}`;
    sslMeta.innerHTML = `
      <dt>émetteur</dt><dd>${s.issuer}</dd>
      <dt>expire le</dt><dd>${s.expires}</dd>
      <dt>jours restants</dt><dd>${s.days_left}</dd>`;
  }

  // Ports card
  const p = data.ports || {};
  const portsBadge = document.getElementById('ports-badge');
  const portsList = document.getElementById('ports-list');
  if (p.error) {
    portsBadge.textContent = 'erreur';
    portsBadge.className = 'badge badge--bad';
    portsList.innerHTML = `<li>${p.error}</li>`;
  } else {
    const openCount = p.open?.length || 0;
    portsBadge.textContent = `${openCount} ouvert(s)`;
    portsBadge.className = `badge ${badgeClass(openCount === 0 ? 'good' : openCount <= 2 ? 'warn' : 'bad')}`;
    portsList.innerHTML = openCount === 0
      ? '<li class="ok">✓ Aucun port courant exposé</li>'
      : p.open.map(o => `<li><strong>Port ${o.port}</strong>${o.service}</li>`).join('');
  }

  // Tech card
  const techList = document.getElementById('tech-list');
  const tech = data.tech || [];
  techList.innerHTML = tech.length
    ? tech.map(t => `<li>${t}</li>`).join('')
    : '<li style="color:var(--text-dim)">Aucune technologie identifiée</li>';
}
