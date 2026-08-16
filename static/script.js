const form = document.getElementById('scan-form');
const input = document.getElementById('target-input');
const consentCheck = document.getElementById('consent-check');
const btn = document.getElementById('scan-btn');
const terminal = document.getElementById('terminal');
const termBody = document.getElementById('terminal-body');
const results = document.getElementById('results');
const exportBtn = document.getElementById('export-btn');
const reportBtn = document.getElementById('report-btn');

let lastScanData = null;
const progressBar  = document.getElementById('scan-progress-bar');
const progressFill = document.getElementById('scan-progress-fill');

// ─── All test checks displayed in terminal ───────────────────────────────────
const TEST_CHECKS = [
  {
    label: 'en-têtes de sécurité (9 vérifiés)',
    eval: d => (d.headers?.missing?.length || 0) === 0 ? 'ok' : 'fail',
    detail: d => d.headers?.error ? 'erreur connexion' : d.headers?.missing?.length ? `${d.headers.missing.length} manquant(s)` : 'tous présents',
  },
  {
    label: 'qualité HSTS (max-age / preload)',
    eval: d => { const h = d.deep_headers?.hsts; return h && h.max_age >= 31536000 && h.include_subdomains ? 'ok' : h ? 'warn' : 'fail'; },
    detail: d => { const h = d.deep_headers?.hsts; return h ? `max-age=${h.max_age}s${h.include_subdomains?' · incl.sub':''}${h.preload?' · preload':''}` : 'HSTS absent'; },
  },
  {
    label: "qualité CSP (unsafe-inline / eval)",
    eval: d => { if (!d.deep_headers?.csp_present) return 'warn'; const bad = (d.deep_headers?.issues||[]).filter(i=>i.type?.startsWith('csp_')); return bad.length ? 'fail' : 'ok'; },
    detail: d => { if (!d.deep_headers?.csp_present) return 'CSP absent'; const bad = (d.deep_headers?.issues||[]).filter(i=>i.type?.startsWith('csp_')); return bad.length ? bad.map(i=>i.type.replace('csp_','')).join(', ') : 'ok'; },
  },
  {
    label: 'headers de debug / info en production',
    eval: d => !(d.deep_headers?.debug_headers?.length) ? 'ok' : 'fail',
    detail: d => d.deep_headers?.debug_headers?.length ? d.deep_headers.debug_headers.map(h=>h.header).join(', ') : 'aucun',
  },
  {
    label: 'certificat TLS/SSL (validité)',
    eval: d => d.ssl?.error ? 'fail' : !d.ssl?.valid ? 'fail' : d.ssl?.days_left < 30 ? 'warn' : 'ok',
    detail: d => d.ssl?.error ? 'erreur TLS' : !d.ssl?.valid ? `expiré (${d.ssl?.expires})` : `valide · ${d.ssl?.days_left}j · ${d.ssl?.issuer}`,
  },
  {
    label: 'protocole TLS (version)',
    eval: d => d.ssl?.weak_protocol ? 'fail' : d.ssl?.error ? 'warn' : 'ok',
    detail: d => d.ssl?.protocol ? `${d.ssl.protocol}${d.ssl.weak_protocol?' (obsolète)':''}` : 'non vérifiable',
  },
  {
    label: 'DNS · enregistrement CAA',
    eval: d => d.dns?.caa?.length ? 'ok' : 'fail',
    detail: d => d.dns?.caa?.length ? `${d.dns.caa.length} autorité(s) configurée(s)` : 'absent · n\'importe quel CA peut émettre',
  },
  {
    label: 'DNS · DNSSEC',
    eval: d => d.dns?.dnssec ? 'ok' : 'warn',
    detail: d => d.dns?.dnssec ? 'signatures actives' : 'non configuré',
  },
  {
    label: 'email · SPF (anti-spoofing)',
    eval: d => d.dns?.spf ? 'ok' : 'fail',
    detail: d => d.dns?.spf ? 'présent' : 'absent · spoofing possible',
  },
  {
    label: 'email · DMARC (anti-phishing)',
    eval: d => d.dns?.dmarc ? 'ok' : 'fail',
    detail: d => d.dns?.dmarc ? 'présent' : 'absent · phishing facilité',
  },
  {
    label: 'cookies (HttpOnly / Secure / SameSite)',
    eval: d => { const bad = (d.cookies?.list||[]).filter(c=>c.issues?.length); return bad.length ? 'fail' : 'ok'; },
    detail: d => { const bad = (d.cookies?.list||[]).filter(c=>c.issues?.length); return bad.length ? `${bad.length}/${d.cookies?.count} non sécurisé(s)` : d.cookies?.count ? `${d.cookies.count} cookie(s) ok` : 'aucun cookie'; },
  },
  {
    label: 'CORS (wildcard / reflection)',
    eval: d => (d.cors?.issues?.length||0) ? 'fail' : 'ok',
    detail: d => d.cors?.issues?.length ? d.cors.issues[0].substring(0,50) : 'ok',
  },
  {
    label: 'redirection HTTP → HTTPS',
    eval: d => d.redirect?.redirects_to_https ? 'ok' : d.redirect?.error ? 'warn' : 'fail',
    detail: d => d.redirect?.redirects_to_https ? `HTTP ${d.redirect.http_status} configurée` : d.redirect?.error ? 'non applicable' : 'non configurée',
  },
  {
    label: 'open redirect (8 paramètres)',
    eval: d => d.open_redirect?.found ? 'fail' : 'ok',
    detail: d => d.open_redirect?.found ? `?${d.open_redirect.param}=evil → vulnérable` : 'ok',
  },
  {
    label: 'ports dangereux (30 analysés)',
    eval: d => { const c = (d.ports?.open||[]).filter(p=>p.risk==='critical'); const h = (d.ports?.open||[]).filter(p=>p.risk==='high'); return c.length ? 'fail' : h.length ? 'warn' : 'ok'; },
    detail: d => { const r = (d.ports?.open||[]).filter(p=>p.risk!=='info'); return r.length ? r.map(p=>`:${p.port}`).join(' ') : 'aucun port dangereux'; },
  },
  {
    label: 'fichiers sensibles (45+ chemins)',
    eval: d => { const c = (d.disclosure?.found||[]).filter(f=>f.risk==='critical'); const h = (d.disclosure?.found||[]).filter(f=>f.risk==='high'); return c.length ? 'fail' : h.length ? 'warn' : 'ok'; },
    detail: d => { const b = (d.disclosure?.found||[]).filter(f=>f.risk!=='info'); return b.length ? b.map(f=>f.path).join(', ').substring(0,60) : 'aucun'; },
  },
  {
    label: 'listage de répertoires',
    eval: d => d.directory_listing?.found?.length ? 'fail' : 'ok',
    detail: d => d.directory_listing?.found?.length ? d.directory_listing.found.join(', ') : 'ok',
  },
  {
    label: 'pages d\'erreur verbeuses',
    eval: d => d.error_disclosure?.found ? 'warn' : 'ok',
    detail: d => d.error_disclosure?.found ? `${d.error_disclosure.pattern||d.error_disclosure.type}` : 'ok',
  },
  {
    label: 'méthodes HTTP (TRACE/PUT/DELETE)',
    eval: d => d.methods?.risky?.length ? 'fail' : 'ok',
    detail: d => d.methods?.risky?.length ? d.methods.risky.join(', ') : 'ok',
  },
  {
    label: 'fuites de secrets (clés API)',
    eval: d => d.source?.leaks?.length ? 'fail' : 'ok',
    detail: d => d.source?.leaks?.length ? `${d.source.leaks.length} fuite(s) : ${d.source.leaks[0].type.substring(0,30)}` : 'ok',
  },
  {
    label: 'SRI · scripts externes',
    eval: d => d.source?.no_sri?.length ? 'warn' : 'ok',
    detail: d => d.source?.no_sri?.length ? `${d.source.no_sri.length} script(s) sans integrity=` : 'ok',
  },
  {
    label: 'commentaires HTML sensibles',
    eval: d => d.source?.suspicious_comments?.length ? 'warn' : 'ok',
    detail: d => d.source?.suspicious_comments?.length ? `${d.source.suspicious_comments.length} trouvé(s)` : 'ok',
  },
  {
    label: 'IPs internes dans les headers',
    eval: d => Object.keys(d.source?.ip_leak_headers||{}).length ? 'warn' : 'ok',
    detail: d => Object.keys(d.source?.ip_leak_headers||{}).join(', ') || 'ok',
  },
  {
    label: 'WAF / CDN',
    eval: d => d.waf?.length ? 'ok' : 'warn',
    detail: d => d.waf?.length ? d.waf.join(', ') : 'aucune protection détectée',
  },
];

// ─── Terminal animation ───────────────────────────────────────────────────────
const SPINNER = ['⠋','⠙','⠹','⠸','⠼','⠴','⠦','⠧','⠇','⠏'];
let _spinnerInterval  = null;
let _progressInterval = null;

function showLoadingTerminal() {
  termBody.innerHTML = '';
  terminal.classList.remove('hidden');

  // Progress bar: reset then animate towards 88% asymptotically
  progressFill.style.transition = 'none';
  progressFill.style.width = '0%';
  progressBar.classList.remove('hidden');
  let pct = 0;
  requestAnimationFrame(() => {
    progressFill.style.transition = 'width 0.3s ease';
  });
  _progressInterval = setInterval(() => {
    pct = Math.min(pct + (88 - pct) * 0.055, 87);
    progressFill.style.width = pct.toFixed(1) + '%';
  }, 200);

  const lineEls = TEST_CHECKS.map(check => {
    const row = document.createElement('div');
    row.className = 'term-line term-line--loading';
    row.innerHTML = `<span class="ts-icon">${SPINNER[0]}</span><span class="ts-label">${check.label}</span><span class="ts-sep"></span>`;
    termBody.appendChild(row);
    return row;
  });

  let frame = 0;
  _spinnerInterval = setInterval(() => {
    frame = (frame + 1) % SPINNER.length;
    lineEls.forEach(row => {
      if (row.classList.contains('term-line--loading')) {
        row.querySelector('.ts-icon').textContent = SPINNER[frame];
      }
    });
  }, 90);

  return lineEls;
}

function completeProgress() {
  clearInterval(_progressInterval);
  progressFill.style.width = '100%';
  setTimeout(() => {
    progressBar.classList.add('hidden');
    progressFill.style.width = '0%';
  }, 550);
}

async function resolveTerminal(lineEls, data) {
  clearInterval(_spinnerInterval);
  for (let i = 0; i < TEST_CHECKS.length; i++) {
    await new Promise(r => setTimeout(r, 45));
    const check = TEST_CHECKS[i];
    const row = lineEls[i];
    let status = 'ok';
    try { status = check.eval(data); } catch (_) {}
    let detail = '';
    try { detail = check.detail(data); } catch (_) {}

    const icon = row.querySelector('.ts-icon');
    row.className = `term-line term-line--${status}`;

    if (status === 'ok') {
      icon.className = 'ts-ok'; icon.textContent = '✓';
    } else if (status === 'fail') {
      icon.className = 'ts-fail'; icon.textContent = '✗';
    } else {
      icon.className = 'ts-warn'; icon.textContent = '⚠';
    }

    if (detail) {
      const sp = document.createElement('span');
      sp.className = 'ts-detail';
      sp.textContent = detail;
      row.appendChild(sp);
    } else {
      // remove the separator placeholder on lines with no detail
      const sep = row.querySelector('.ts-sep');
      if (sep) sep.remove();
    }
    termBody.scrollTop = termBody.scrollHeight;
  }
}

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  const target = input.value.trim();
  if (!target) return;
  if (!consentCheck.checked) {
    consentCheck.closest('.consent-label').style.color = 'var(--red)';
    consentCheck.addEventListener('change', () => {
      consentCheck.closest('.consent-label').style.color = '';
    }, { once: true });
    return;
  }

  btn.disabled = true;
  btn.textContent = 'Analyse en cours...';
  results.classList.add('hidden');

  // Start API fetch and terminal animation concurrently
  const fetchPromise = fetch('/api/scan', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ target }),
  });
  const lineEls = showLoadingTerminal();

  try {
    const res = await fetchPromise;
    const data = await res.json();

    if (!res.ok) {
      clearInterval(_spinnerInterval);
      completeProgress();
      lineEls.forEach(row => {
        row.className = 'term-line term-line--fail';
        const icon = row.querySelector('.ts-icon');
        icon.className = 'ts-fail'; icon.textContent = '✗';
      });
      const errRow = document.createElement('div');
      errRow.className = 'term-line term-line--fail';
      errRow.innerHTML = `<span class="ts-fail">✗</span><span class="ts-label">${data.error || `Erreur ${res.status}`}</span>`;
      termBody.appendChild(errRow);
    } else {
      lastScanData = data;
      completeProgress();
      await resolveTerminal(lineEls, data);
      renderResults(data);
    }
  } catch (err) {
    clearInterval(_spinnerInterval);
    completeProgress();
    const errRow = document.createElement('div');
    errRow.className = 'term-line term-line--fail';
    errRow.innerHTML = `<span class="ts-fail">✗</span><span class="ts-label">erreur réseau : ${err.message}</span>`;
    termBody.appendChild(errRow);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Analyser';
  }
});

exportBtn.addEventListener('click', () => {
  if (!lastScanData) return;
  const blob = new Blob([JSON.stringify(lastScanData, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `sentinel-${lastScanData.hostname}-${Date.now()}.json`;
  a.click();
  URL.revokeObjectURL(url);
});

reportBtn.addEventListener('click', () => {
  if (!lastScanData) return;
  const html = buildReport(lastScanData);
  const blob = new Blob([html], { type: 'text/html;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  window.open(url, '_blank');
});

// ─── Report generation ──────────────────────────────────────────────────────

function collectFindings(data) {
  const findings = [];

  // ── En-têtes ──
  const HEADER_SEV = {
    'Strict-Transport-Security': 'high',
    'Content-Security-Policy': 'high',
    'X-Frame-Options': 'medium',
    'X-Content-Type-Options': 'medium',
    'Referrer-Policy': 'low',
    'Permissions-Policy': 'low',
    'Cross-Origin-Opener-Policy': 'low',
    'Cross-Origin-Resource-Policy': 'low',
    'Cross-Origin-Embedder-Policy': 'low',
  };
  (data.headers?.missing || []).forEach(h => {
    findings.push({
      id: 'HDR', category: 'En-têtes de sécurité',
      title: `Header manquant : ${h.name}`,
      severity: HEADER_SEV[h.name] || 'medium',
      description: h.desc,
      evidence: `L'en-tête "${h.name}" est absent de la réponse HTTP.`,
      impact: h.risk,
      fix: h.fix,
    });
  });

  if (data.headers?.server_verbose) {
    findings.push({
      id: 'INF', category: 'Divulgation d\'informations',
      title: 'En-tête Server verbeux',
      severity: 'low',
      description: 'Le serveur révèle sa technologie et/ou version dans l\'en-tête Server.',
      evidence: `Server: ${data.headers.server}`,
      impact: 'Facilite le ciblage en révélant la stack technique. Un attaquant peut chercher des CVE spécifiques à cette version.',
      fix: 'Masquer ou généraliser la valeur : Server: web. Nginx: server_tokens off; Apache: ServerTokens Prod; ServerSignature Off',
    });
  }

  if (data.headers?.x_powered_by) {
    findings.push({
      id: 'INF', category: 'Divulgation d\'informations',
      title: 'En-tête X-Powered-By exposé',
      severity: 'low',
      description: 'L\'en-tête X-Powered-By révèle le langage/framework utilisé.',
      evidence: `X-Powered-By: ${data.headers.x_powered_by}`,
      impact: 'Permet à un attaquant d\'identifier la technologie backend et de cibler des vulnérabilités connues.',
      fix: 'Supprimer cet en-tête. PHP: expose_php = Off dans php.ini. Express.js: app.disable("x-powered-by")',
    });
  }

  // ── TLS/SSL ──
  if (data.ssl && !data.ssl.error) {
    if (!data.ssl.valid) {
      findings.push({
        id: 'SSL', category: 'Certificat TLS/SSL',
        title: 'Certificat TLS expiré',
        severity: 'critical',
        description: 'Le certificat TLS du serveur est expiré. Les navigateurs affichent une erreur bloquante.',
        evidence: `Expiration : ${data.ssl.expires} (${Math.abs(data.ssl.days_left)} jour(s) écoulés depuis expiration)\nÉmetteur : ${data.ssl.issuer}`,
        impact: 'Le trafic n\'est plus chiffré de manière fiable. Toutes les données transmises sont exposées à une attaque de type Man-in-the-Middle (MITM). Les utilisateurs voient une erreur de sécurité et ne peuvent plus naviguer normalement.',
        fix: 'Renouveler le certificat immédiatement via Let\'s Encrypt (certbot renew), ZeroSSL ou votre CA. Activer le renouvellement automatique (cron job ou systemd timer).',
      });
    } else if (data.ssl.days_left < 30) {
      findings.push({
        id: 'SSL', category: 'Certificat TLS/SSL',
        title: `Certificat TLS bientôt expiré (${data.ssl.days_left} jours)`,
        severity: 'high',
        description: `Le certificat TLS expire dans ${data.ssl.days_left} jours.`,
        evidence: `Expiration : ${data.ssl.expires}\nÉmetteur : ${data.ssl.issuer}`,
        impact: 'Si non renouvelé, le site deviendra inaccessible et les connexions non sécurisées pour tous les utilisateurs.',
        fix: 'Planifier le renouvellement immédiatement. Let\'s Encrypt : certbot renew --pre-hook "systemctl stop nginx" --post-hook "systemctl start nginx"',
      });
    }
    if (data.ssl.weak_protocol) {
      findings.push({
        id: 'SSL', category: 'Certificat TLS/SSL',
        title: `Protocole TLS obsolète actif : ${data.ssl.protocol}`,
        severity: 'high',
        description: `Le serveur accepte des connexions via ${data.ssl.protocol}, un protocole déprécié depuis 2020 (RFC 8996).`,
        evidence: `Protocole négocié lors de l\'analyse : ${data.ssl.protocol}\nCipher suite : ${data.ssl.cipher}`,
        impact: 'Vulnérabilités connues : POODLE (CVE-2014-3566), BEAST (CVE-2011-3389), DROWN. Permet le déchiffrement du trafic historique si la clé privée est compromise.',
        fix: 'Désactiver TLS 1.0 et 1.1, autoriser uniquement TLS 1.2 et TLS 1.3.\nNginx : ssl_protocols TLSv1.2 TLSv1.3;\nApache : SSLProtocol -all +TLSv1.2 +TLSv1.3',
      });
    }
  } else if (data.ssl?.error) {
    findings.push({
      id: 'SSL', category: 'Certificat TLS/SSL',
      title: 'Impossible de vérifier le certificat TLS',
      severity: 'high',
      description: 'La connexion TLS a échoué ou le certificat est invalide.',
      evidence: `Erreur : ${data.ssl.error}`,
      impact: 'Le site n\'offre pas de connexion HTTPS valide. Les données transmises ne sont pas chiffrées.',
      fix: 'Configurer un certificat TLS valide via Let\'s Encrypt ou un CA reconnu.',
    });
  }

  // ── DNS CAA ──
  if (data.dns && !data.dns.caa?.length) {
    findings.push({
      id: 'DNS', category: 'DNS & Sécurité email',
      title: 'Absence d\'enregistrement CAA',
      severity: 'medium',
      description: 'Aucun enregistrement CAA (Certification Authority Authorization) n\'a été trouvé pour ce domaine.',
      evidence: 'Aucune entrée DNS CAA pour ' + data.hostname,
      impact: 'N\'importe quelle autorité de certification peut émettre un certificat TLS pour votre domaine, même à votre insu. Facilite les attaques de type certificate misissuance.',
      fix: 'Ajouter un enregistrement DNS CAA :\n' + data.hostname + ' IN CAA 0 issue "letsencrypt.org"\n' + data.hostname + ' IN CAA 0 issue "digicert.com"\nRemplacer par les CAs que vous utilisez effectivement.',
    });
  }

  // ── DNS standard ──
  if (data.dns) {
    if (!data.dns.spf) {
      findings.push({
        id: 'DNS', category: 'DNS & Sécurité email',
        title: 'Absence d\'enregistrement SPF',
        severity: 'medium',
        description: 'Aucun enregistrement SPF (Sender Policy Framework) n\'a été trouvé pour ce domaine.',
        evidence: 'Aucune entrée TXT commençant par "v=spf1" dans le DNS du domaine.',
        impact: 'N\'importe qui peut forger des emails en se faisant passer pour ce domaine (email spoofing). Utilisé massivement dans les attaques de phishing et d\'ingénierie sociale.',
        fix: 'Ajouter un enregistrement DNS TXT :\n' + data.hostname + ' IN TXT "v=spf1 include:_spf.votre-hote.com ~all"\nRemplacer l\'include par les serveurs autorisés à envoyer des emails.',
      });
    }
    if (!data.dns.dmarc) {
      findings.push({
        id: 'DNS', category: 'DNS & Sécurité email',
        title: 'Absence d\'enregistrement DMARC',
        severity: 'medium',
        description: 'Aucun enregistrement DMARC (Domain-based Message Authentication, Reporting & Conformance) n\'a été trouvé.',
        evidence: 'Aucune entrée TXT "v=DMARC1" dans le sous-domaine _dmarc.' + data.hostname,
        impact: 'Sans DMARC, les serveurs de messagerie destinataires ne savent pas quoi faire des emails qui échouent SPF/DKIM. Facilite les campagnes de phishing usurpant le domaine.',
        fix: '_dmarc.' + data.hostname + ' IN TXT "v=DMARC1; p=reject; rua=mailto:dmarc@' + data.hostname + '"\np=reject pour bloquer, p=quarantine pour mettre en spam, p=none pour surveillance uniquement.',
      });
    }
  }

  // ── Cookies ──
  (data.cookies?.list || []).forEach(ck => {
    if (!ck.issues.length) return;
    const missingFlags = [];
    if (!ck.httponly) missingFlags.push('HttpOnly');
    if (!ck.secure) missingFlags.push('Secure');
    if (!ck.samesite) missingFlags.push('SameSite');
    findings.push({
      id: 'CKI', category: 'Sécurité des cookies',
      title: `Cookie non sécurisé : ${ck.name}`,
      severity: !ck.httponly ? 'medium' : 'low',
      description: `Le cookie "${ck.name}" est configuré sans les attributs de sécurité : ${missingFlags.join(', ')}.`,
      evidence: `Cookie : ${ck.name}\nHttpOnly : ${ck.httponly ? '✓' : '✗'} | Secure : ${ck.secure ? '✓' : '✗'} | SameSite : ${ck.samesite || 'absent'}`,
      impact: ck.issues.join('\n'),
      fix: `Configurer le cookie avec tous les attributs :\nSet-Cookie: ${ck.name}=<valeur>; Path=/; HttpOnly; Secure; SameSite=Strict\nSameSite=Lax si le cookie doit fonctionner avec des liens entrants.`,
    });
  });

  // ── CORS ──
  if ((data.cors?.issues?.length || 0) > 0) {
    const c = data.cors;
    findings.push({
      id: 'CRS', category: 'CORS (Cross-Origin Resource Sharing)',
      title: c.reflects_origin ? 'Injection CORS, origine arbitraire reflétée' : 'Misconfiguration CORS, wildcard',
      severity: c.reflects_origin ? 'critical' : 'high',
      description: 'La politique CORS du serveur est mal configurée et permet à des origines non autorisées d\'accéder aux ressources.',
      evidence: `Access-Control-Allow-Origin: ${c.acao}\nAccess-Control-Allow-Credentials: ${c.credentials}\nTest effectué avec : Origin: https://evil.com`,
      impact: c.issues.join('\n'),
      fix: 'Définir une liste blanche explicite des origines autorisées :\nAccess-Control-Allow-Origin: https://votre-domaine.com\nNe jamais combiner ACAO: * avec Allow-Credentials: true.\nValider l\'origine côté serveur avant de la refléter.',
    });
  }

  // ── Redirect ──
  if (data.redirect && !data.redirect.error && !data.redirect.redirects_to_https) {
    findings.push({
      id: 'TLS', category: 'Transport sécurisé',
      title: 'Absence de redirection HTTP → HTTPS',
      severity: 'medium',
      description: 'Le serveur ne redirige pas automatiquement les connexions HTTP non chiffrées vers HTTPS.',
      evidence: `Requête : GET http://${data.hostname}\nRéponse : HTTP ${data.redirect.http_status}${data.redirect.location ? ' → ' + data.redirect.location : ' (pas de redirection)'}`,
      impact: 'Les utilisateurs qui accèdent au site via HTTP transmettent leurs données (formulaires, cookies, tokens) en clair. Un attaquant sur le même réseau peut intercepter et modifier le trafic (MITM).',
      fix: 'Nginx : return 301 https://$host$request_uri;\nApache : RewriteEngine On\n         RewriteCond %{HTTPS} off\n         RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [R=301,L]',
    });
  }

  // ── Ports ──
  const PORT_IMPACT = {
    23: 'Telnet transmet tous les identifiants et commandes en clair. Exploitation triviale par sniffing réseau.',
    2375: 'Docker daemon HTTP exposé sans authentification. Contrôle total de tous les conteneurs, exécution de commandes root, accès complet au système de fichiers hôte. CVE-2019-5736.',
    3389: 'RDP exposé · vecteur d\'attaque majeur. CVE-2019-0708 (BlueKeep) permet l\'exécution de code à distance sans authentification.',
    6379: 'Redis sans authentification permet l\'exfiltration de toutes les données en cache, l\'écriture de fichiers arbitraires et l\'exécution de commandes via les modules.',
    9200: 'Elasticsearch exposé sans authentification (versions < 8.0). Intégralité de la base de données accessible en lecture/écriture/suppression depuis Internet.',
    11211: 'Memcached exposé sur Internet. Amplification DDoS massive (facteur x50000), accès à toutes les données en cache (sessions, tokens, données utilisateurs).',
    27017: 'MongoDB sans authentification, intégralité de la base de données accessible en lecture/écriture depuis Internet.',
    445: 'SMB exposé sur Internet, vecteur principal de WannaCry (EternalBlue, MS17-010). Permet l\'exécution de code à distance.',
    5601: 'Kibana exposé sur Internet. Interface d\'administration Elasticsearch, consultation et suppression des données. La console Dev Tools permet potentiellement d\'exécuter du code côté serveur.',
    5900: 'VNC exposé, prise de contrôle visuelle complète du système. Souvent sans authentification ou avec un mot de passe faible.',
    3306: 'MySQL exposé directement sur Internet, accès direct aux données, brute-force possible, potentiel d\'injection SQL directe.',
    5432: 'PostgreSQL exposé directement sur Internet, accès direct aux données. Le compte postgres peut exécuter des commandes système (COPY TO/FROM PROGRAM).',
    1433: 'MSSQL exposé, xp_cmdshell peut permettre l\'exécution de commandes Windows. Cible courante de ransomwares.',
    9000: 'Portainer ou SonarQube exposé. Portainer donne un contrôle total sur Docker via une interface web sans nécessiter de CLI. SonarQube peut révéler le code source.',
    21: 'FTP transmet identifiants et données en clair. Vulnérable au sniffing et aux attaques MITM.',
    25: 'SMTP mal configuré peut être exploité comme relais de spam (open relay) ou pour énumérer les comptes.',
    22: 'SSH exposé sur Internet · surface d\'attaque pour le brute-force d\'identifiants. Assurer une authentification par clé uniquement.',
    53: 'DNS exposé, risque de DNS amplification DDoS, transfert de zone, et énumération du domaine.',
    2181: 'Zookeeper exposé sans authentification. Contrôle complet de la coordination de cluster (ZNodes, watches), manipulation possible de Kafka, HBase et autres applications distribuées.',
    3000: 'Interface Grafana exposée. Révèle des dashboards de métriques internes, des sources de données (Prometheus, bases de données), potentiellement des credentials de connexion.',
    5984: 'CouchDB exposé sans authentification. Accès admin possible via /_config/admins/. Toutes les bases de données lisibles et modifiables depuis Internet.',
    8888: 'Jupyter Notebook exposé. Exécution de code Python arbitraire dans le contexte du serveur, accès complet au système de fichiers et aux commandes shell.',
    9090: 'Prometheus exposé. Accès aux métriques internes de l\'infrastructure (CPU, RAM, latences, targets de scraping) révélant l\'architecture réseau interne.',
    15672: 'Interface de management RabbitMQ exposée. Accès aux files de messages, manipulation des échanges/queues, potentiellement des credentials d\'applications en clair.',
  };
  (data.ports?.open || []).forEach(p => {
    if (p.risk === 'info') return;
    findings.push({
      id: 'PRT', category: 'Ports exposés',
      title: `Port ${p.port} (${p.service}) exposé sur Internet`,
      severity: p.risk === 'critical' ? 'critical' : p.risk === 'high' ? 'high' : 'medium',
      description: `Le port ${p.port}/${p.service} est accessible depuis Internet sans restriction.`,
      evidence: `${data.ports?.ip}:${p.port} , état : OUVERT\nService : ${p.service} | Niveau de risque : ${p.risk.toUpperCase()}`,
      impact: PORT_IMPACT[p.port] || `Service ${p.service} exposé publiquement sans contrôle d\'accès.`,
      fix: `Restreindre le port ${p.port} avec un pare-feu (iptables, ufw, groupe de sécurité cloud) :\nufw deny ${p.port}\nOu restreindre à des IPs de confiance uniquement :\nufw allow from <IP_admin> to any port ${p.port}\nUtiliser un VPN pour les accès administrateur.`,
    });
  });

  // ── Fichiers sensibles ──
  const DISC_IMPACT = {
    '/.git/HEAD': 'L\'intégralité du code source peut être téléchargée via "git clone". Exposition de clés API, mots de passe en dur, historique des commits, architecture interne.',
    '/.env': 'Exposition des variables d\'environnement : clés API (Stripe, AWS, Twilio...), mots de passe de base de données, secrets JWT, tokens OAuth.',
    '/.env.local': 'Exposition de la configuration d\'environnement local, souvent identique à la production.',
    '/.env.production': 'Exposition de la configuration de production, clés et secrets actifs.',
    '/phpinfo.php': 'Divulgation de la configuration PHP complète : version, modules, chemins système, variables $_SERVER, configuration php.ini.',
    '/.htpasswd': 'Exposition des hachages de mots de passe Apache. Attaque hors-ligne par brute-force possible (hashcat, john).',
    '/backup.zip': 'Archive potentiellement accessible contenant le code source, les données et la configuration du site.',
    '/backup.sql': 'Dump SQL potentiellement accessible, intégralité de la base de données (utilisateurs, mots de passe, données sensibles).',
    '/db.sql': 'Dump SQL potentiellement accessible, intégralité de la base de données.',
    '/swagger.json': 'Documentation complète de l\'API exposée publiquement, liste tous les endpoints, paramètres et modèles de données. Facilite la découverte de vulnérabilités API.',
    '/openapi.json': 'Spécification OpenAPI exposée, cartographie complète de l\'API accessible à tous.',
    '/admin': 'Interface d\'administration détectée et accessible depuis Internet.',
    '/administrator': 'Interface d\'administration détectée et accessible depuis Internet.',
  };
  (data.disclosure?.found || []).forEach(f => {
    if (f.risk === 'info') return;
    findings.push({
      id: 'DIS', category: 'Divulgation d\'informations',
      title: f.label,
      severity: f.risk === 'critical' ? 'critical' : f.risk === 'high' ? 'high' : 'medium',
      description: `Le chemin ${f.path} est accessible publiquement (HTTP ${f.status}).`,
      evidence: `URL : https://${data.hostname}${f.path}\nStatut HTTP : ${f.status}${f.snippet ? '\nExtrait de contenu :\n' + f.snippet.substring(0, 300) : ''}`,
      impact: DISC_IMPACT[f.path] || `Accès non autorisé à ${f.path} potentiellement exposé.`,
      fix: `Supprimer le fichier de la racine web ou restreindre l\'accès :\nNginx : location ~ ${f.path.replace('.', '\\.')} { deny all; return 404; }\nApache : <Files "${f.path.replace('/', '')}">\\n  Require all denied\\n</Files>`,
    });
  });

  // ── Méthodes HTTP ──
  const METHOD_INFO = {
    TRACE: {
      sev: 'high',
      desc: 'La méthode TRACE est activée. Elle renvoie la requête HTTP complète telle que reçue par le serveur.',
      impact: 'Attaque XST (Cross-Site Tracing) permettant de voler des cookies HttpOnly via JavaScript. Contourne les protections XSS.',
      fix: 'Désactiver TRACE sur le serveur.\nNginx : ajouter dans le bloc server :\nif ($request_method = TRACE) { return 405; }\nApache : TraceEnable Off',
    },
    TRACK: {
      sev: 'high',
      desc: 'La méthode TRACK est activée (variante de TRACE spécifique à IIS).',
      impact: 'Mêmes risques que TRACE, exfiltration de cookies et contournement de protections XSS.',
      fix: 'Désactiver TRACK dans la configuration IIS ou via règles de pare-feu applicatif.',
    },
    PUT: {
      sev: 'high',
      desc: 'La méthode HTTP PUT est autorisée sans restriction.',
      impact: 'Permet l\'upload de fichiers arbitraires sur le serveur (webshell, malware). Accès complet au système si combiné avec une mauvaise configuration.',
      fix: 'Restreindre PUT aux endpoints API qui en ont besoin, avec authentification obligatoire.\nNginx : if ($request_method = PUT) { return 405; }\nSauf sur les routes API protégées.',
    },
    DELETE: {
      sev: 'medium',
      desc: 'La méthode HTTP DELETE est autorisée sans restriction apparente.',
      impact: 'Permet potentiellement la suppression de ressources côté serveur sans authentification.',
      fix: 'Restreindre DELETE aux endpoints API authentifiés uniquement.',
    },
  };
  (data.methods?.risky || []).forEach(method => {
    const info = METHOD_INFO[method] || {
      sev: 'medium',
      desc: `La méthode HTTP ${method} est autorisée.`,
      impact: `Méthode non standard potentiellement dangereuse.`,
      fix: `Désactiver ou restreindre la méthode ${method}.`,
    };
    findings.push({
      id: 'MTH', category: 'Méthodes HTTP',
      title: `Méthode HTTP dangereuse active : ${method}`,
      severity: info.sev,
      description: info.desc,
      evidence: `Requête OPTIONS → Allow: ${(data.methods?.allowed || []).join(', ')}`,
      impact: info.impact,
      fix: info.fix,
    });
  });

  // ── Source analysis ──
  if (data.source) {
    (data.source.leaks || []).forEach(l => {
      findings.push({
        id: 'SRC', category: 'Analyse du code source',
        title: `Secret exposé dans le code source : ${l.type}`,
        severity: 'critical',
        description: `Une clé/secret a été détecté dans le code source HTML de la page.`,
        evidence: `Extrait (partiellement masqué) : ${l.snippet}`,
        impact: 'Clé active détectée publiquement. Un attaquant peut immédiatement l\'exploiter pour accéder aux services associés (cloud, paiement, base de données...). Cette clé doit être révoquée en urgence.',
        fix: 'Supprimer immédiatement cette clé du code source. Révoquer et régénérer la clé auprès du fournisseur. Stocker les secrets en variables d\'environnement côté serveur uniquement, jamais dans le frontend.',
      });
    });
    if ((data.source.no_sri || []).length > 0) {
      findings.push({
        id: 'SRC', category: 'Analyse du code source',
        title: `${data.source.no_sri.length} script(s) externe(s) sans Subresource Integrity`,
        severity: 'medium',
        description: 'Des scripts chargés depuis des CDN tiers ne possèdent pas d\'attribut integrity= (SRI).',
        evidence: `Scripts sans SRI :\n${data.source.no_sri.slice(0,3).join('\n')}`,
        impact: 'Si le CDN ou un script tiers est compromis, du code malveillant peut être injecté dans votre page sans que le navigateur ne le détecte.',
        fix: 'Générer les hashes SRI sur https://www.srihash.org\n<script src="url" integrity="sha384-..." crossorigin="anonymous"></script>',
      });
    }
    (data.source.suspicious_comments || []).forEach(c => {
      findings.push({
        id: 'SRC', category: 'Analyse du code source',
        title: `Commentaire HTML sensible : ${c.label}`,
        severity: 'medium',
        description: 'Un commentaire HTML contient des informations potentiellement sensibles visibles par n\'importe quel visiteur via le code source.',
        evidence: `Commentaire : ${c.text}`,
        impact: 'Les commentaires HTML sont visibles de tous. Des informations sur l\'infrastructure, les identifiants ou les chemins internes facilitent la reconnaissance d\'un attaquant.',
        fix: 'Supprimer les commentaires de développement avant la mise en production. Utiliser un bundler (webpack, vite) qui les supprime automatiquement en mode production.',
      });
    });
    const ipKeys = Object.keys(data.source.ip_leak_headers || {});
    ipKeys.forEach(hdr => {
      findings.push({
        id: 'SRC', category: 'Analyse du code source',
        title: `IP interne exposée dans l'en-tête ${hdr}`,
        severity: 'low',
        description: `L'en-tête de réponse ${hdr} révèle une adresse IP de l'infrastructure interne.`,
        evidence: `${hdr}: ${data.source.ip_leak_headers[hdr]}`,
        impact: 'Révèle l\'architecture réseau interne. Un attaquant peut utiliser ces adresses pour cibler l\'infrastructure en cas d\'autre vulnérabilité (SSRF, RFI).',
        fix: `Supprimer ou filtrer cet en-tête au niveau du proxy/load balancer.\nNginx : proxy_hide_header ${hdr};\nApache : Header unset ${hdr}`,
      });
    });
  }

  // ── Open redirect ──
  if (data.open_redirect?.found) {
    findings.push({
      id: 'ORD', category: 'Redirection ouverte',
      title: `Open redirect sur le paramètre ?${data.open_redirect.param}=`,
      severity: 'medium',
      description: 'Le serveur redirige vers n\'importe quelle URL fournie dans le paramètre sans validation.',
      evidence: `Paramètre vulnérable : ${data.open_redirect.param}\nTest : ${data.open_redirect.param}=https://evil-sentinel-test.com → redirection confirmée`,
      impact: 'Un attaquant peut créer un lien https://votre-domaine.com?redirect=https://malware.com pour contourner les filtres anti-phishing des messageries et navigateurs, en profitant de la réputation du domaine légitime.',
      fix: 'Valider côté serveur que la destination de redirection fait partie d\'une liste blanche de domaines autorisés.\nJamais rediriger vers une URL fournie directement par l\'utilisateur sans validation stricte.',
    });
  }

  // ── Deep headers ──
  if (data.deep_headers) {
    (data.deep_headers.debug_headers || []).forEach(d => {
      findings.push({
        id: 'DBG', category: 'Headers de débogage',
        title: `Header de debug exposé : ${d.header}`,
        severity: d.severity === 'critical' ? 'critical' : d.severity === 'high' ? 'high' : 'medium',
        description: d.desc,
        evidence: `${d.header}: ${d.value}`,
        impact: 'Le mode debug en production expose des informations sensibles : requêtes SQL, variables de session, configuration, chemins internes. Utilisé pour escalader des vulnérabilités.',
        fix: `Désactiver le mode debug en production.\nSymfony : APP_ENV=prod, APP_DEBUG=false dans .env.production\nLaravel : APP_DEBUG=false dans .env\nSupprimer l'en-tête via la config ou un middleware de sécurité.`,
      });
    });
    (data.deep_headers.issues || []).filter(i => i.severity !== 'info').forEach(i => {
      findings.push({
        id: 'HDR', category: 'Qualité des en-têtes',
        title: i.title,
        severity: i.severity,
        description: i.desc,
        evidence: `En-tête concerné : ${i.type.startsWith('hsts') ? 'Strict-Transport-Security' : 'Content-Security-Policy'}`,
        impact: i.type === 'csp_unsafe_inline'
          ? 'La protection XSS de la CSP est entièrement neutralisée. Tout script inline peut s\'exécuter, rendant la CSP inutile contre les injections XSS.'
          : i.type === 'csp_unsafe_eval'
          ? 'eval() et Function() peuvent être utilisés pour exécuter du code arbitraire injecté via des données.'
          : 'Le navigateur n\'est pas pleinement protégé contre le downgrade HTTP.',
        fix: i.fix,
      });
    });
  }

  // ── Directory listing ──
  (data.directory_listing?.found || []).forEach(path => {
    findings.push({
      id: 'DIR', category: 'Divulgation d\'informations',
      title: `Listage de répertoire actif : ${path}`,
      severity: 'high',
      description: `Le répertoire ${path} liste publiquement son contenu (Apache "Index of /" ou équivalent).`,
      evidence: `URL : https://${data.hostname}${path}\nRéponse HTTP 200 contenant un listing de fichiers`,
      impact: 'Un attaquant peut parcourir les fichiers du serveur : configurations, backups, uploads privés, code source. Point de départ classique d\'une reconnaissance approfondie.',
      fix: `Désactiver le listage de répertoires :\nNginx : autoindex off; (dans le bloc server/location)\nApache : Options -Indexes\nOu bloquer via : location ${path} { return 403; }`,
    });
  });

  // ── Error page disclosure ──
  if (data.error_disclosure?.found) {
    findings.push({
      id: 'ERR', category: 'Divulgation d\'informations',
      title: `Pages d'erreur verbeuses : ${data.error_disclosure.type || 'erreur technique exposée'}`,
      severity: 'medium',
      description: 'Le serveur révèle des détails techniques internes dans ses messages d\'erreur (trace de pile, chemin système, version).',
      evidence: `Pattern détecté : ${data.error_disclosure.pattern || data.error_disclosure.type}`,
      impact: 'Les messages d\'erreur verbeux (chemins, versions, traces) aident un attaquant à comprendre l\'architecture et à identifier des vecteurs d\'attaque ciblés.',
      fix: 'Configurer des pages d\'erreur génériques en production.\nPHP : display_errors = Off dans php.ini\nDjango : DEBUG = False\nNe jamais exposer de stack traces en production.',
    });
  }

  const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  findings.sort((a, b) => (order[a.severity] ?? 4) - (order[b.severity] ?? 4));
  return findings;
}

function buildReport(data) {
  const findings = collectFindings(data);
  const date = new Date().toLocaleDateString('fr-FR', { year: 'numeric', month: 'long', day: 'numeric' });
  const time = new Date().toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' });

  const counts = {
    critical: findings.filter(f => f.severity === 'critical').length,
    high:     findings.filter(f => f.severity === 'high').length,
    medium:   findings.filter(f => f.severity === 'medium').length,
    low:      findings.filter(f => f.severity === 'low').length,
  };
  const score = data.score ?? 0;
  const scoreColor = score >= 75 ? '#276749' : score >= 45 ? '#744210' : '#742A2A';
  const scoreLabel = score >= 80 ? 'Faible' : score >= 60 ? 'Modérée' : score >= 40 ? 'Significative' : score >= 20 ? 'Élevée' : 'Critique';

  function sevBadge(sev) {
    const map = {
      critical: ['CRITIQUE', '#742A2A', '#FFF5F5', '#FC8181'],
      high:     ['ÉLEVÉ',    '#7B341E', '#FFFAF0', '#F6AD55'],
      medium:   ['MOYEN',    '#744210', '#FFFFF0', '#F6E05E'],
      low:      ['FAIBLE',   '#2A4365', '#EBF8FF', '#63B3ED'],
      info:     ['INFO',     '#2D3748', '#F7FAFC', '#A0AEC0'],
    };
    const [label, textColor, bg, border] = map[sev] || map.info;
    return `<span style="background:${bg};color:${textColor};border:1px solid ${border};padding:3px 10px;border-radius:4px;font-size:11px;font-weight:700;font-family:'Courier New',monospace;letter-spacing:0.06em;white-space:nowrap">${label}</span>`;
  }

  const findingsHtml = findings.map((f, i) => {
    const colorMap = { critical: '#E53E3E', high: '#DD6B20', medium: '#D69E2E', low: '#3182CE', info: '#718096' };
    const color = colorMap[f.severity] || '#718096';
    return `
    <div style="margin-bottom:28px;border:1px solid #E2E8F0;border-radius:8px;overflow:hidden;page-break-inside:avoid">
      <div style="background:#1A202C;padding:14px 20px;display:flex;justify-content:space-between;align-items:flex-start;gap:12px">
        <div style="flex:1">
          <div style="font-size:11px;color:#718096;font-family:'Courier New',monospace;margin-bottom:4px">
            F-${String(i + 1).padStart(3, '0')} &nbsp;·&nbsp; ${f.category}
          </div>
          <div style="font-size:15px;font-weight:600;color:#fff">${f.title}</div>
        </div>
        <div style="flex-shrink:0;margin-top:2px">${sevBadge(f.severity)}</div>
      </div>
      <div style="background:#fff">
        ${[
          ['Description', f.description, '#2D3748', false],
          ['Preuve',      f.evidence,    '#2D3748', true],
          ['Impact',      f.impact,      '#742A2A', false],
          ['Remédiation', f.fix,         '#22543D', true],
        ].map(([label, value, textColor, mono], idx) => `
        <div style="display:grid;grid-template-columns:130px 1fr;border-top:1px solid #E2E8F0">
          <div style="padding:10px 14px;background:#F7FAFC;font-size:12px;font-weight:600;color:#4A5568;border-right:1px solid #E2E8F0">${label}</div>
          <div style="padding:10px 14px;font-size:13px;color:${textColor};${mono ? 'font-family:"Courier New",monospace;font-size:12px;' : ''}white-space:pre-wrap;word-break:break-word">${value}</div>
        </div>`).join('')}
      </div>
    </div>`;
  }).join('');

  const wafInfo = (data.waf || []).length > 0
    ? `Protection WAF/CDN détectée : ${data.waf.join(', ')}.`
    : 'Aucun WAF ou CDN détecté devant l\'application.';

  const techInfo = (data.tech || []).length > 0
    ? `Technologies identifiées : ${data.tech.join(', ')}.`
    : '';

  return `<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Rapport Sentinel · ${data.hostname} · ${date}</title>
<style>
  @page { margin: 2cm 2.5cm; size: A4; }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, sans-serif; font-size: 13.5px; color: #1A202C; line-height: 1.6; background: #fff; }
  h2 { font-size: 17px; font-weight: 700; color: #1A202C; padding-bottom: 8px; border-bottom: 2px solid #4FD1C5; margin-bottom: 20px; margin-top: 0; }
  .section { margin-bottom: 44px; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th, td { padding: 9px 13px; border: 1px solid #E2E8F0; text-align: left; }
  th { background: #F7FAFC; font-weight: 600; color: #4A5568; }
  @media print {
    .no-print { display: none !important; }
    body { print-color-adjust: exact; -webkit-print-color-adjust: exact; }
    .section { page-break-inside: avoid; }
  }
</style>
</head>
<body>

<!-- Barre d'impression -->
<div class="no-print" style="background:#1A202C;padding:10px 24px;display:flex;justify-content:space-between;align-items:center;position:sticky;top:0;z-index:100">
  <span style="color:#8592A8;font-family:'Courier New',monospace;font-size:12px">◆ SENTINEL · Rapport d'analyse · ${data.hostname}</span>
  <button onclick="window.print()" style="background:#4FD1C5;color:#062220;border:none;padding:8px 22px;border-radius:6px;font-weight:700;cursor:pointer;font-size:13px">⎙ Imprimer / Sauvegarder en PDF</button>
</div>

<!-- Page de garde -->
<div style="background:linear-gradient(160deg,#0B1220 0%,#162035 60%,#1A2744 100%);color:#fff;padding:56px 52px 44px;margin-bottom:44px">
  <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:24px;flex-wrap:wrap">
    <div>
      <div style="font-family:'Courier New',monospace;font-size:11px;color:#4FD1C5;letter-spacing:0.12em;margin-bottom:10px">◆ SENTINEL SECURITY SCANNER</div>
      <h1 style="font-size:30px;font-weight:700;line-height:1.2;margin-bottom:6px">Rapport d'Analyse<br>de Sécurité Web</h1>
      <p style="color:#8592A8;font-size:14px">Analyse externe automatisée · Black-box</p>
    </div>
    <div style="background:rgba(255,255,255,0.07);border:1px solid rgba(255,255,255,0.12);border-radius:10px;padding:18px 26px;text-align:center;min-width:140px">
      <div style="font-size:11px;color:#8592A8;font-family:'Courier New',monospace;letter-spacing:0.08em;margin-bottom:6px">SCORE GLOBAL</div>
      <div style="font-size:52px;font-weight:700;font-family:'Courier New',monospace;color:${score >= 75 ? '#3FCF8E' : score >= 45 ? '#F0B429' : '#EF5B5B'};line-height:1">${score}</div>
      <div style="font-size:13px;color:#8592A8;font-family:'Courier New',monospace;margin-top:4px">/100 · ${scoreLabel}</div>
    </div>
  </div>

  <div style="margin-top:36px;padding-top:28px;border-top:1px solid rgba(255,255,255,0.1);display:grid;grid-template-columns:repeat(3,1fr);gap:20px">
    <div>
      <div style="font-size:10px;color:#8592A8;font-family:'Courier New',monospace;letter-spacing:0.1em;margin-bottom:4px">CIBLE ANALYSÉE</div>
      <div style="font-size:16px;font-weight:600">${data.hostname}</div>
      <div style="font-size:12px;color:#4FD1C5;font-family:'Courier New',monospace">${data.url}</div>
    </div>
    <div>
      <div style="font-size:10px;color:#8592A8;font-family:'Courier New',monospace;letter-spacing:0.1em;margin-bottom:4px">DATE D'ANALYSE</div>
      <div style="font-size:15px;font-weight:600">${date}</div>
      <div style="font-size:12px;color:#8592A8">${time}</div>
    </div>
    <div>
      <div style="font-size:10px;color:#8592A8;font-family:'Courier New',monospace;letter-spacing:0.1em;margin-bottom:4px">VULNÉRABILITÉS</div>
      <div style="font-size:15px;font-weight:600">${findings.length} trouvée(s)</div>
      <div style="font-size:12px;color:#8592A8">sur 16 catégories · 24 vérifications</div>
    </div>
  </div>
</div>

<div style="padding:0 52px;max-width:950px;margin:0 auto">

<!-- Résumé exécutif -->
<div class="section">
  <h2>1. Résumé exécutif</h2>
  <p style="color:#4A5568;margin-bottom:22px">
    L'analyse externe de <strong>${data.hostname}</strong> a été conduite le ${date} via l'outil Sentinel.
    Cette évaluation black-box simule la perspective d'un attaquant non authentifié opérant depuis Internet public.
    Le score global obtenu est de <strong style="color:${scoreColor}">${score}/100</strong>, correspondant à un niveau d'exposition <strong>${scoreLabel.toLowerCase()}</strong>.
    ${findings.length === 0 ? 'Aucune vulnérabilité externe significative n\'a été identifiée.' : `Au total, <strong>${findings.length} vulnérabilité(s)</strong> ont été identifiées.`}
  </p>

  <!-- Compteurs sévérité -->
  <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:24px">
    ${[
      ['CRITIQUE', counts.critical, '#FFF5F5', '#E53E3E', '#C53030'],
      ['ÉLEVÉ',    counts.high,     '#FFFAF0', '#DD6B20', '#C05621'],
      ['MOYEN',    counts.medium,   '#FFFFF0', '#D69E2E', '#B7791F'],
      ['FAIBLE',   counts.low,      '#EBF8FF', '#3182CE', '#2B6CB0'],
    ].map(([label, count, bg, accent, textColor]) => `
    <div style="background:${bg};border:1px solid ${accent}30;border-radius:8px;padding:16px 12px;text-align:center">
      <div style="font-size:36px;font-weight:700;color:${accent};font-family:'Courier New',monospace;line-height:1">${count}</div>
      <div style="font-size:10px;font-weight:700;color:${textColor};font-family:'Courier New',monospace;letter-spacing:0.1em;margin-top:4px">${label}</div>
    </div>`).join('')}
  </div>

  ${counts.critical > 0 ? `
  <div style="background:#FFF5F5;border-left:4px solid #E53E3E;padding:14px 18px;border-radius:0 8px 8px 0;margin-bottom:12px">
    <strong style="color:#C53030;font-size:14px">⚠ Action immédiate requise</strong><br>
    <span style="font-size:13px;color:#742A2A">${counts.critical} vulnérabilité(s) critique(s) identifiée(s). Ces problèmes exposent le site à un risque immédiat d'exploitation et doivent être corrigés en priorité absolue, avant toute autre action.</span>
  </div>` : ''}
  ${counts.high > 0 ? `
  <div style="background:#FFFAF0;border-left:4px solid #DD6B20;padding:14px 18px;border-radius:0 8px 8px 0;margin-bottom:12px">
    <strong style="color:#C05621;font-size:14px">⚠ Correction prioritaire</strong><br>
    <span style="font-size:13px;color:#7B341E">${counts.high} vulnérabilité(s) de niveau élevé nécessitent une correction rapide sous 72 heures.</span>
  </div>` : ''}
  ${counts.critical === 0 && counts.high === 0 && counts.medium === 0 ? `
  <div style="background:#F0FFF4;border-left:4px solid #38A169;padding:14px 18px;border-radius:0 8px 8px 0">
    <strong style="color:#276749;font-size:14px">✓ Bonne posture de sécurité externe</strong><br>
    <span style="font-size:13px;color:#22543D">Aucune vulnérabilité critique ou élevée détectée. Continuer à surveiller et appliquer les recommandations mineures.</span>
  </div>` : ''}
</div>

<!-- Synthèse -->
<div class="section">
  <h2>2. Synthèse par catégorie</h2>
  <table>
    <tr>
      <th style="width:220px">Catégorie</th>
      <th style="width:100px">Statut</th>
      <th>Observations</th>
    </tr>
    ${[
      ['En-têtes de sécurité',
        !(data.headers?.missing?.length) ? 'ok' : data.headers.missing.length <= 2 ? 'warn' : 'bad',
        data.headers?.error ? 'Connexion impossible' :
        data.headers?.missing?.length === 0 ? 'Tous les en-têtes vérifiés sont présents' :
        `${data.headers?.missing?.length} en-tête(s) manquant(s) : ${(data.headers?.missing || []).map(h => h.name).join(', ')}`
      ],
      ['Certificat TLS/SSL',
        data.ssl?.error ? 'bad' : !data.ssl?.valid ? 'bad' : data.ssl?.days_left < 30 ? 'warn' : data.ssl?.weak_protocol ? 'warn' : 'ok',
        data.ssl?.error ? `Erreur : ${data.ssl.error}` :
        !data.ssl?.valid ? `Certificat expiré (${data.ssl?.expires})` :
        `Valide, expire le ${data.ssl?.expires} (${data.ssl?.days_left}j) · ${data.ssl?.protocol} · ${data.ssl?.issuer}`
      ],
      ['DNS & Sécurité email',
        (!data.dns?.spf && !data.dns?.dmarc) ? 'bad' : (!data.dns?.spf || !data.dns?.dmarc) ? 'warn' : 'ok',
        `SPF : ${data.dns?.spf ? '✓ présent' : '✗ absent'} · DMARC : ${data.dns?.dmarc ? '✓ présent' : '✗ absent'}${(data.dns?.mx?.length || 0) > 0 ? ' · MX : ' + data.dns.mx[0] : ''}`
      ],
      ['Cookies',
        !(data.cookies?.list?.length) ? 'ok' :
        data.cookies.list.some(c => c.issues.length > 0) ? 'warn' : 'ok',
        data.cookies?.count === 0 ? 'Aucun cookie Set-Cookie détecté' :
        `${data.cookies?.count} cookie(s) · ${data.cookies?.list?.filter(c => c.issues.length > 0).length || 0} avec des problèmes de configuration`
      ],
      ['CORS',
        (data.cors?.issues?.length || 0) === 0 ? 'ok' : data.cors?.reflects_origin ? 'bad' : 'warn',
        data.cors?.error ? `Erreur : ${data.cors.error}` :
        (data.cors?.issues?.length || 0) === 0 ? 'Aucune misconfiguration détectée' :
        data.cors?.issues?.join(' | ') || 'Misconfiguration détectée'
      ],
      ['Redirection HTTP→HTTPS',
        data.redirect?.error ? 'ok' : data.redirect?.redirects_to_https ? 'ok' : 'warn',
        data.redirect?.error ? 'Non applicable' :
        data.redirect?.redirects_to_https ? `Redirection ${data.redirect.http_status} vers HTTPS configurée` :
        `HTTP ${data.redirect?.http_status} , pas de redirection vers HTTPS`
      ],
      ['Ports exposés',
        !(data.ports?.open?.length) ? 'ok' :
        data.ports.open.some(p => p.risk === 'critical') ? 'bad' :
        data.ports.open.some(p => p.risk === 'high') ? 'warn' : 'ok',
        data.ports?.error ? `Erreur : ${data.ports.error}` :
        data.ports?.open?.length === 0 ? 'Aucun port sensible exposé' :
        `${data.ports?.open?.length} port(s) ouvert(s) : ${(data.ports?.open || []).map(p => `${p.port}/${p.service}`).join(', ')}`
      ],
      ['Fichiers sensibles',
        !(data.disclosure?.found?.filter(f => f.risk !== 'info').length) ? 'ok' :
        data.disclosure?.found?.some(f => f.risk === 'critical') ? 'bad' : 'warn',
        data.disclosure?.found?.filter(f => f.risk !== 'info').length === 0 ? 'Aucun fichier sensible accessible' :
        `${data.disclosure?.found?.filter(f => f.risk !== 'info').length} fichier(s) détecté(s) : ${(data.disclosure?.found || []).filter(f=>f.risk!=='info').map(f=>f.path).join(', ')}`
      ],
      ['Méthodes HTTP',
        !(data.methods?.risky?.length) ? 'ok' : 'warn',
        data.methods?.error ? 'Non déterminé' :
        data.methods?.risky?.length === 0 ? 'Aucune méthode dangereuse active' :
        `Méthodes dangereuses actives : ${data.methods?.risky?.join(', ')}`
      ],
      ['WAF / CDN',
        'ok',
        (data.waf || []).length === 0 ? 'Aucun WAF/CDN détecté' : `Détecté : ${data.waf?.join(', ')}`
      ],
    ].map(([cat, status, obs]) => {
      const statusInfo = { ok: ['#276749','#F0FFF4','✓'], warn: ['#B7791F','#FFFFF0','⚠'], bad: ['#C53030','#FFF5F5','✗'] }[status] || ['#4A5568','#F7FAFC','·'];
      return `<tr>
        <td style="font-weight:600">${cat}</td>
        <td style="background:${statusInfo[1]};color:${statusInfo[0]};font-weight:700;font-family:'Courier New',monospace;font-size:12px;text-align:center">${statusInfo[2]}</td>
        <td style="color:#4A5568;font-size:12px">${obs}</td>
      </tr>`;
    }).join('')}
  </table>
</div>

<!-- Périmètre -->
<div class="section">
  <h2>3. Périmètre et méthodologie</h2>
  <p style="color:#4A5568;margin-bottom:16px">
    Cette analyse a été réalisée depuis un point externe (Internet public), sans authentification préalable, simulant la perspective d'un attaquant non privilégié.
    ${wafInfo} ${techInfo}
  </p>
  <table>
    <tr><th style="width:220px">Module</th><th>Éléments vérifiés</th></tr>
    ${[
      ['En-têtes de sécurité','9 en-têtes vérifiés : HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP, CORP, COEP · qualité HSTS (max-age ≥ 1 an, includeSubDomains, preload) · qualité CSP (unsafe-inline, unsafe-eval)'],
      ['Certificat TLS/SSL','Validité, date d\'expiration, jours restants, émetteur, version du protocole (TLS 1.0/1.1 déprécié), suite de chiffrement'],
      ['DNS & Sécurité email','5 enregistrements : SPF (anti-spoofing), DMARC (anti-phishing), MX, CAA (autorités de certification autorisées), DNSSEC (signatures cryptographiques)'],
      ['Cookies','Attributs HttpOnly, Secure, SameSite sur chaque Set-Cookie de la réponse'],
      ['CORS','Access-Control-Allow-Origin (wildcard *, réflexion d\'origine arbitraire), Access-Control-Allow-Credentials'],
      ['Redirections HTTP','Vérification HTTP→HTTPS (301/302/307/308) + test open redirect sur 8 paramètres courants (redirect, url, next, return, goto, dest…)'],
      ['Ports exposés','30 ports : FTP(21), SSH(22), Telnet(23), SMTP(25), DNS(53), POP3(110), IMAP(143), SMB(445), MSSQL(1433), Zookeeper(2181), Docker(2375), Grafana(3000), MySQL(3306), RDP(3389), PostgreSQL(5432), Kibana(5601), VNC(5900), CouchDB(5984), Redis(6379), HTTP-Alt(8080/8443), Jupyter(8888), Portainer(9000), Prometheus(9090), Elasticsearch(9200), Memcached(11211), RabbitMQ(15672), MongoDB(27017)'],
      ['Fichiers sensibles','46+ chemins : .git/HEAD, .env, .env.production, .ssh/id_rsa, .netrc, .npmrc, .bash_history, credentials.json, actuator/env, backup.zip/sql, phpinfo.php, .htpasswd, phpmyadmin, WEB-INF/web.xml, access.log, error.log, config.yml, debug.php, test.php, Dockerfile, docker-compose.yml, swagger.json, .idea/workspace.xml, CHANGELOG.md…'],
      ['Listage de répertoires','12 répertoires sondés : /images/, /uploads/, /static/, /assets/, /files/, /backup/, /tmp/, /logs/, /data/, /media/, /public/ — détection de la directive autoindex Apache/Nginx'],
      ['Pages d\'erreur verbeuses','4 payloads injectés (SQLi, path traversal) — détection de stack traces PHP/Python/Java, erreurs SQL, chemins système internes exposés'],
      ['Analyse du code source','15 patterns de clés API (AWS AKIA, Stripe sk_live, Google AIza, GitHub ghp/gho, Slack xox, SendGrid SG., Twilio, Firebase…), scripts sans Subresource Integrity, commentaires HTML sensibles, IPs internes dans les headers'],
      ['Headers de debug','17 headers : X-Debug-Token, X-Debug-Token-Link, X-DebugBar-Link, X-Application-Context, X-OWA-Version, X-AspNet-Version, Server-Timing, X-Generator, X-Drupal-Cache, X-Varnish, X-Rack-Cache, X-Runtime, X-Litespeed-Cache, X-Envoy-Upstream-Service-Time, X-Kong-Upstream-Latency, X-RateLimit-Limit…'],
      ['Méthodes HTTP','Analyse de l\'en-tête Allow via OPTIONS → TRACE (-8pts), TRACK (-8pts), PUT (-5pts), DELETE (-3pts)'],
      ['WAF / CDN','Signatures de 8 solutions : Cloudflare, AWS CloudFront/WAF, Akamai, Imperva/Incapsula, ModSecurity, Sucuri, F5 BIG-IP, Fastly'],
      ['Technologies','Fingerprinting de 25+ frameworks et CMS : WordPress, Drupal, Joomla, Laravel, Django, Next.js, React, Angular, Vue, Svelte, Nuxt, Bootstrap, Tailwind, Google Analytics, GTM…'],
    ].map(([mod, desc]) => `<tr><td style="font-weight:600;font-family:'Courier New',monospace;font-size:12px">${mod}</td><td style="color:#4A5568;font-size:12px">${desc}</td></tr>`).join('')}
  </table>
</div>

<!-- Analyse détaillée -->
<div class="section">
  <h2>4. Analyse détaillée des vulnérabilités</h2>
  ${findings.length === 0
    ? '<div style="background:#F0FFF4;border:1px solid #9AE6B4;border-radius:8px;padding:28px;text-align:center;color:#276749"><div style="font-size:24px;margin-bottom:8px">✓</div><strong>Aucune vulnérabilité significative détectée</strong><br><span style="font-size:13px;color:#2F855A">Le site présente une bonne posture de sécurité externe lors de cette analyse.</span></div>'
    : findingsHtml}
</div>

${findings.length > 0 ? `
<!-- Recommandations prioritaires -->
<div class="section">
  <h2>5. Recommandations prioritaires</h2>
  <p style="color:#4A5568;margin-bottom:18px">Actions classées par ordre de priorité selon le niveau de risque :</p>
  <ol style="padding-left:0;list-style:none">
    ${findings.slice(0, 8).map((f, i) => {
      const colors = { critical: '#E53E3E', high: '#DD6B20', medium: '#D69E2E', low: '#3182CE' };
      const color = colors[f.severity] || '#718096';
      return `
    <li style="margin-bottom:12px;padding:14px 18px 14px 20px;background:#F7FAFC;border-radius:6px;border-left:4px solid ${color};display:flex;gap:14px;align-items:flex-start">
      <span style="font-family:'Courier New',monospace;font-size:12px;font-weight:700;color:#A0AEC0;margin-top:1px;white-space:nowrap">${String(i + 1).padStart(2, '0')}</span>
      <div style="flex:1">
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:4px;flex-wrap:wrap">
          <strong style="font-size:13px">${f.title}</strong> ${sevBadge(f.severity)}
        </div>
        <p style="font-size:12px;color:#4A5568;margin-bottom:4px">${f.fix.split('\n')[0]}</p>
      </div>
    </li>`;
    }).join('')}
  </ol>
</div>` : ''}

<!-- Conclusion -->
<div class="section">
  <h2>${findings.length > 0 ? '6' : '5'}. Conclusion</h2>
  <p style="color:#4A5568;line-height:1.8;margin-bottom:16px">
    L'analyse externe de <strong>${data.hostname}</strong>, conduite le ${date}, a retourné un score de sécurité de <strong style="color:${scoreColor}">${score}/100</strong> (exposition ${scoreLabel.toLowerCase()}).
    ${counts.critical > 0 ? `<strong style="color:#C53030">${counts.critical} vulnérabilité(s) critique(s)</strong> nécessitent une intervention immédiate. ` : ''}
    ${counts.high > 0 ? `<strong style="color:#C05621">${counts.high} vulnérabilité(s) de niveau élevé</strong> doivent être corrigées sous 72 heures. ` : ''}
    ${counts.medium > 0 ? `${counts.medium} vulnérabilité(s) de niveau moyen sont à traiter dans les deux semaines. ` : ''}
    ${findings.length === 0 ? 'Aucune vulnérabilité critique n\'a été détectée lors de cette analyse. La posture de sécurité externe est satisfaisante.' : 'Le traitement des vulnérabilités listées dans ce rapport permettra d\'améliorer significativement la posture de sécurité externe du site.'}
  </p>
  <div style="background:#F7FAFC;border:1px solid #E2E8F0;border-radius:8px;padding:16px 20px;font-size:12px;color:#718096;line-height:1.7">
    <strong style="color:#4A5568">Avertissement légal :</strong> Ce rapport a été généré automatiquement par l'outil Sentinel à des fins éducatives et de sensibilisation.
    Il ne remplace pas un audit de sécurité réalisé par des professionnels qualifiés (PASSI, OSCP, CEH, CISSP).
    Les résultats doivent être interprétés par une personne compétente en sécurité informatique.
    Toute analyse doit être réalisée sur des systèmes dont vous êtes propriétaire ou pour lesquels vous disposez d'une autorisation écrite explicite.
    Sentinel · Développé par Soufiane Filali.
  </div>
</div>

<!-- Pied de page -->
<div style="margin-top:36px;padding:20px 0;border-top:1px solid #E2E8F0;display:flex;justify-content:space-between;align-items:center;font-size:11px;color:#A0AEC0;font-family:'Courier New',monospace">
  <span>◆ SENTINEL SECURITY SCANNER</span>
  <span>${data.hostname} · ${date} · ${time}</span>
  <span>CONFIDENTIEL</span>
</div>

</div>
</body>
</html>`;
}

// ─── Render helpers ─────────────────────────────────────────────────────────

function bc(level) {
  return { good: 'badge--good', warn: 'badge--warn', bad: 'badge--bad' }[level] || '';
}

function scoreLabel(score) {
  if (score >= 80) return 'Exposition faible';
  if (score >= 60) return 'Exposition modérée';
  if (score >= 40) return 'Exposition significative';
  if (score >= 20) return 'Exposition élevée';
  return 'Exposition critique';
}

function riskClass(risk) {
  return { critical: 'risk-critical', high: 'risk-high', medium: 'risk-medium', info: 'risk-info' }[risk] || '';
}

function renderResults(data) {
  results.classList.remove('hidden');

  const score = data.score ?? 0;
  const circumference = 326.7;
  const offset = circumference - (circumference * score) / 100;
  const ring = document.getElementById('ring-fg');
  ring.style.strokeDashoffset = offset;
  ring.style.stroke = score >= 75 ? 'var(--green)' : score >= 45 ? 'var(--amber)' : 'var(--red)';
  document.getElementById('score-number').textContent = score;
  document.getElementById('score-target').textContent = data.hostname || data.url;
  document.getElementById('score-label').textContent = scoreLabel(score);

  renderHeaders(data.headers || {});
  renderSSL(data.ssl || {});
  renderDNS(data.dns || {});
  renderCookies(data.cookies || {});
  renderCORS(data.cors || {});
  renderRedirect(data.redirect || {});
  renderPorts(data.ports || {});
  renderDisclosure(data.disclosure || {}, data.directory_listing || {});
  renderMethods(data.methods || {});
  renderWAF(data.waf || []);
  renderSourceAnalysis(data.source || {});
  renderOpenRedirect(data.open_redirect || {});
  renderDeepHeaders(data.deep_headers || {});
  renderTech(data.tech || []);

  results.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function renderHeaders(h) {
  const badge = document.getElementById('headers-badge');
  const meta  = document.getElementById('headers-meta');
  const list  = document.getElementById('headers-list');
  meta.innerHTML = ''; list.innerHTML = '';
  if (h.error) { badge.textContent='erreur'; badge.className='badge badge--bad'; list.innerHTML=`<li>${h.error}</li>`; return; }
  const missing = h.missing?.length || 0;
  badge.textContent = missing === 0 ? 'complet' : `${missing} manquant(s)`;
  badge.className = `badge ${bc(missing === 0 ? 'good' : missing <= 2 ? 'warn' : 'bad')}`;
  let metaHtml = `<dt>statut</dt><dd>${h.status_code}</dd><dt>serveur</dt><dd>${h.server}${h.server_verbose ? ' <span class="tag-warn">verbose</span>' : ''}</dd>`;
  if (h.x_powered_by) metaHtml += `<dt>X-Powered-By</dt><dd class="tag-warn">${h.x_powered_by}</dd>`;
  meta.innerHTML = metaHtml;
  list.innerHTML = missing === 0 ? '<li class="ok">✓ Tous les en-têtes vérifiés sont présents</li>'
    : h.missing.map(m => `<li><strong>${m.name}</strong><span class="finding-desc">${m.desc}</span><span class="finding-risk">⚠ Risque : ${m.risk}</span><code class="finding-fix">${m.fix}</code></li>`).join('');
}

function renderSSL(s) {
  const badge = document.getElementById('ssl-badge');
  const meta  = document.getElementById('ssl-meta');
  if (s.error) { badge.textContent='erreur'; badge.className='badge badge--bad'; meta.innerHTML=`<dt>erreur</dt><dd>${s.error}</dd>`; return; }
  const level = !s.valid ? 'bad' : s.days_left < 30 ? 'warn' : 'good';
  badge.textContent = s.valid ? 'valide' : 'expiré';
  badge.className = `badge ${bc(level)}`;
  meta.innerHTML = `<dt>émetteur</dt><dd>${s.issuer}</dd><dt>expire le</dt><dd>${s.expires}</dd><dt>jours restants</dt><dd>${s.days_left}</dd><dt>protocole</dt><dd>${s.protocol||'·'}${s.weak_protocol?' <span class="tag-warn">obsolète</span>':''}</dd><dt>cipher</dt><dd>${s.cipher||'·'}</dd>`;
}

function renderDNS(d) {
  const badge    = document.getElementById('dns-badge');
  const meta     = document.getElementById('dns-meta');
  const list     = document.getElementById('dns-list');
  const advanced = document.getElementById('dns-advanced');
  meta.innerHTML = ''; list.innerHTML = ''; advanced.innerHTML = '';
  const issues = [];
  if (!d.spf)  issues.push("SPF absent, spoofing email possible");
  if (!d.dmarc) issues.push("DMARC absent, phishing facilité");
  if (!d.caa?.length) issues.push("CAA absent, n'importe quel CA peut émettre un certificat");
  badge.textContent = issues.length === 0 ? 'sécurisé' : `${issues.length} problème(s)`;
  badge.className = `badge ${bc(issues.length===0?'good':issues.length<=2?'warn':'bad')}`;
  let m = `<dt>SPF</dt><dd>${d.spf?'<span class="ok-inline">✓</span> présent':'<span class="bad-inline">✗</span> absent'}</dd>`;
  m += `<dt>DMARC</dt><dd>${d.dmarc?'<span class="ok-inline">✓</span> présent':'<span class="bad-inline">✗</span> absent'}</dd>`;
  if (d.mx?.length) m += `<dt>MX</dt><dd>${d.mx[0]}${d.mx.length>1?` +${d.mx.length-1}`:''}</dd>`;
  meta.innerHTML = m;
  if (d.spf)  list.innerHTML += `<li><strong>SPF</strong><span class="finding-desc mono-sm">${d.spf}</span></li>`;
  if (d.dmarc) list.innerHTML += `<li><strong>DMARC</strong><span class="finding-desc mono-sm">${d.dmarc}</span></li>`;
  issues.forEach(i => { list.innerHTML += `<li><span class="finding-risk">⚠ ${i}</span></li>`; });
  if (!list.innerHTML) list.innerHTML = '<li class="ok">✓ SPF et DMARC configurés</li>';
  let adv = `<dt>CAA</dt><dd>${d.caa?.length?`<span class="ok-inline">✓</span> ${d.caa.length} entrée(s)`:'<span class="bad-inline">✗</span> absent'}</dd>`;
  adv += `<dt>DNSSEC</dt><dd>${d.dnssec?'<span class="ok-inline">✓</span> actif':'<span class="tag-warn">non détecté</span>'}</dd>`;
  advanced.innerHTML = adv;
  if (d.caa?.length) {
    d.caa.forEach(r => { list.innerHTML += `<li><strong>CAA</strong><span class="finding-desc mono-sm">${r}</span></li>`; });
  }
}

function renderCookies(c) {
  const badge = document.getElementById('cookies-badge');
  const list  = document.getElementById('cookies-list');
  list.innerHTML = '';
  const cookies = c.list || [];
  if (!cookies.length) { badge.textContent='aucun'; badge.className='badge'; list.innerHTML='<li class="ok">Aucun cookie Set-Cookie détecté</li>'; return; }
  const withIssues = cookies.filter(ck => ck.issues.length > 0).length;
  badge.textContent = withIssues === 0 ? `${cookies.length} sécurisé(s)` : `${withIssues} problème(s)`;
  badge.className = `badge ${bc(withIssues===0?'good':'warn')}`;
  list.innerHTML = cookies.map(ck => `
    <li class="cookie-item">
      <div class="cookie-name">${ck.name}</div>
      <div class="cookie-flags">
        <span class="flag ${ck.httponly?'flag-ok':'flag-bad'}">HttpOnly</span>
        <span class="flag ${ck.secure?'flag-ok':'flag-bad'}">Secure</span>
        <span class="flag ${ck.samesite?'flag-ok':'flag-bad'}">SameSite${ck.samesite?'='+ck.samesite:''}</span>
      </div>
      ${ck.issues.map(i=>`<span class="finding-risk">⚠ ${i}</span>`).join('')}
    </li>`).join('');
}

function renderCORS(c) {
  const badge = document.getElementById('cors-badge');
  const meta  = document.getElementById('cors-meta');
  const list  = document.getElementById('cors-list');
  meta.innerHTML = ''; list.innerHTML = '';
  if (c.error) { badge.textContent='erreur'; badge.className='badge badge--bad'; meta.innerHTML=`<dt>erreur</dt><dd>${c.error}</dd>`; return; }
  const issues = c.issues || [];
  badge.textContent = issues.length===0 ? 'ok' : `${issues.length} problème(s)`;
  badge.className = `badge ${bc(issues.length===0?'good':'bad')}`;
  meta.innerHTML = `<dt>ACAO</dt><dd>${c.acao}</dd><dt>Credentials</dt><dd>${c.credentials?'<span class="tag-warn">true</span>':'false'}</dd>${c.methods?`<dt>Méthodes</dt><dd>${c.methods}</dd>`:''}`;
  list.innerHTML = issues.length===0 ? '<li class="ok">✓ Aucune misconfiguration CORS détectée</li>'
    : issues.map(i=>`<li><span class="finding-risk">⚠ ${i}</span></li>`).join('');
}

function renderRedirect(r) {
  const badge = document.getElementById('redirect-badge');
  const meta  = document.getElementById('redirect-meta');
  meta.innerHTML = '';
  if (r.error) { badge.textContent='inconnu'; badge.className='badge'; meta.innerHTML=`<dt>note</dt><dd>${r.error}</dd>`; return; }
  const ok = r.redirects_to_https;
  badge.textContent = ok ? 'sécurisé' : 'non redirigé';
  badge.className = `badge ${bc(ok?'good':'bad')}`;
  meta.innerHTML = `<dt>HTTP statut</dt><dd>${r.http_status}</dd><dt>→ HTTPS</dt><dd>${ok?'<span class="ok-inline">✓ oui</span>':'<span class="bad-inline">✗ non</span>'}</dd>${r.location?`<dt>Location</dt><dd>${r.location}</dd>`:''}`;
  if (!ok) meta.innerHTML += `<dt style="grid-column:1/-1;margin-top:4px" class="finding-risk">⚠ Le trafic HTTP n'est pas forcé vers HTTPS</dt>`;
}

function renderPorts(p) {
  const badge = document.getElementById('ports-badge');
  const list  = document.getElementById('ports-list');
  list.innerHTML = '';
  if (p.error) { badge.textContent='erreur'; badge.className='badge badge--bad'; list.innerHTML=`<li>${p.error}</li>`; return; }
  const open = p.open || [];
  const risky = open.filter(o => o.risk==='critical'||o.risk==='high').length;
  badge.textContent = `${open.length} ouvert(s)`;
  badge.className = `badge ${bc(open.length===0?'good':risky>0?'bad':'warn')}`;
  list.innerHTML = open.length===0 ? '<li class="ok">✓ Aucun port courant exposé</li>'
    : open.map(o=>`<li class="port-item"><span class="port-number">:${o.port}</span><span class="port-service">${o.service}</span><span class="risk-tag ${riskClass(o.risk)}">${o.risk}</span></li>`).join('');
}

function renderDisclosure(d, dl) {
  const badge = document.getElementById('disclosure-badge');
  const list  = document.getElementById('disclosure-list');
  list.innerHTML = '';
  const found = d.found || [];
  const dirFound = dl?.found || [];
  const critical = found.filter(f=>f.risk==='critical').length;
  const total = found.length + dirFound.length;
  badge.textContent = total===0 ? 'propre' : `${total} trouvé(s)`;
  badge.className = `badge ${bc(total===0?'good':critical>0?'bad':'warn')}`;

  if (total === 0) {
    list.innerHTML = '<li class="ok">✓ Aucun fichier sensible ou listage de répertoire détecté</li>';
    return;
  }
  list.innerHTML = found.map(f=>`
    <li>
      <div class="disclosure-row"><strong>${f.path}</strong><span class="risk-tag ${riskClass(f.risk)}">${f.risk}</span></div>
      <span class="finding-desc">${f.label} · HTTP ${f.status}</span>
      ${f.snippet?`<code class="finding-fix">${f.snippet.replace(/</g,'&lt;').substring(0,120)}...</code>`:''}
    </li>`).join('');
  dirFound.forEach(path => {
    list.innerHTML += `<li>
      <div class="disclosure-row"><strong>${path}</strong><span class="risk-tag risk-high">high</span></div>
      <span class="finding-desc">Listage de répertoire actif · Index of / visible</span>
      <code class="finding-fix">Nginx : autoindex off; · Apache : Options -Indexes</code>
    </li>`;
  });
}

function renderMethods(m) {
  const badge = document.getElementById('methods-badge');
  const body  = document.getElementById('methods-body');
  body.innerHTML = '';
  if (m.error) { badge.textContent='inconnu'; badge.className='badge'; body.innerHTML=`<p class="dim-note">${m.error}</p>`; return; }
  const risky = m.risky || [];
  badge.textContent = risky.length===0 ? 'ok' : `${risky.length} dangereux`;
  badge.className = `badge ${bc(risky.length===0?'good':'bad')}`;
  const allowed = m.allowed || [];
  if (!allowed.length) { body.innerHTML='<p class="dim-note">Aucune méthode déclarée via Allow.</p>'; return; }
  body.innerHTML = `<div class="method-tags">${allowed.map(method=>`<span class="method-tag ${risky.includes(method)?'method-tag--danger':''}">${method}</span>`).join('')}</div>`;
  if (risky.length) body.innerHTML += `<p class="finding-risk" style="margin-top:10px">⚠ Méthodes dangereuses : ${risky.join(', ')}</p>`;
}

function renderWAF(waf) {
  const badge = document.getElementById('waf-badge');
  const list  = document.getElementById('waf-list');
  const none  = document.getElementById('waf-none');
  list.innerHTML = '';
  if (!waf.length) { badge.textContent='aucun'; badge.className='badge'; none.classList.remove('hidden'); return; }
  badge.textContent=`${waf.length} détecté(s)`; badge.className='badge badge--good'; none.classList.add('hidden');
  list.innerHTML = waf.map(w=>`<li>${w}</li>`).join('');
}

function renderSourceAnalysis(s) {
  const badge = document.getElementById('source-badge');
  const list  = document.getElementById('source-list');
  list.innerHTML = '';
  const leaks    = s.leaks    || [];
  const noSri    = s.no_sri   || [];
  const comments = s.suspicious_comments || [];
  const ipLeaks  = s.ip_leak_headers || {};
  const ipKeys   = Object.keys(ipLeaks);
  const total = leaks.length + (noSri.length > 0 ? 1 : 0) + comments.length + ipKeys.length;
  badge.textContent = total === 0 ? 'propre' : `${total} problème(s)`;
  badge.className = `badge ${bc(total === 0 ? 'good' : leaks.length > 0 ? 'bad' : 'warn')}`;
  if (total === 0) { list.innerHTML = '<li class="ok">✓ Aucune fuite dans le code source détectée</li>'; return; }
  leaks.forEach(l => {
    list.innerHTML += `<li>
      <strong>Fuite de secret détectée</strong>
      <span class="finding-desc">${l.type}</span>
      <span class="finding-risk">⚠ Valeur partielle : ${l.snippet}</span>
      <code class="finding-fix">Supprimer immédiatement du code source. Révoquer et régénérer cette clé. Utiliser des variables d'environnement côté serveur.</code>
    </li>`;
  });
  if (noSri.length > 0) {
    list.innerHTML += `<li>
      <strong>${noSri.length} script(s) externe(s) sans Subresource Integrity</strong>
      <span class="finding-desc">Scripts chargés depuis des CDN tiers sans attribut integrity=. Si le CDN est compromis, du code malveillant peut être injecté.</span>
      <span class="finding-risk">⚠ ${noSri[0].substring(0,80)}${noSri.length>1?' +'+( noSri.length-1)+' autre(s)':''}</span>
      <code class="finding-fix">&lt;script src="..." integrity="sha384-..." crossorigin="anonymous"&gt;</code>
    </li>`;
  }
  comments.forEach(c => {
    list.innerHTML += `<li>
      <strong>Commentaire HTML sensible</strong>
      <span class="finding-desc">${c.label}</span>
      <span class="finding-risk">⚠ Extrait : ${c.text.replace(/</g,'&lt;')}</span>
      <code class="finding-fix">Supprimer les commentaires de développement avant la mise en production.</code>
    </li>`;
  });
  ipKeys.forEach(hdr => {
    list.innerHTML += `<li>
      <strong>IP interne exposée dans les headers</strong>
      <span class="finding-desc">L'en-tête <code>${hdr}</code> révèle une adresse IP de l'infrastructure interne.</span>
      <span class="finding-risk">⚠ ${hdr}: ${ipLeaks[hdr]}</span>
      <code class="finding-fix">Supprimer ou filtrer cet en-tête au niveau du proxy/load balancer. Nginx : proxy_hide_header ${hdr};</code>
    </li>`;
  });
}

function renderOpenRedirect(r) {
  const badge = document.getElementById('redirect-open-badge');
  const body  = document.getElementById('redirect-open-body');
  body.innerHTML = '';
  if (r.found) {
    badge.textContent = 'vulnérable'; badge.className = 'badge badge--bad';
    body.innerHTML = `
      <p style="font-size:0.82rem;color:var(--red);margin-bottom:10px">⚠ Open redirect détecté sur le paramètre <code style="color:var(--amber)">${r.param}</code></p>
      <p style="font-size:0.82rem;color:var(--text-dim);margin-bottom:10px">Un attaquant peut créer un lien vers votre domaine qui redirige vers un site malveillant, en contournant les filtres anti-phishing.</p>
      <code class="finding-fix">Valider côté serveur que la destination de redirection appartient à votre domaine. Ne jamais rediriger vers une URL fournie directement par l'utilisateur sans validation.</code>`;
  } else {
    badge.textContent = 'ok'; badge.className = 'badge badge--good';
    body.innerHTML = '<p class="dim-note">✓ Aucun open redirect détecté sur les paramètres courants.</p>';
  }
}

function renderDeepHeaders(dh) {
  const badge = document.getElementById('deep-headers-badge');
  const list  = document.getElementById('deep-headers-list');
  list.innerHTML = '';
  const issues = dh.issues || [];
  const debugH = dh.debug_headers || [];
  const total  = issues.filter(i => i.severity !== 'info').length + debugH.length;
  badge.textContent = total === 0 ? 'ok' : `${total} problème(s)`;
  badge.className = `badge ${bc(total===0?'good':debugH.some(d=>d.severity==='critical')||issues.some(i=>i.severity==='high')?'bad':'warn')}`;
  const sevClass = { high: 'risk-high', medium: 'risk-medium', low: 'risk-info', info: 'risk-info', critical: 'risk-critical' };
  debugH.forEach(d => {
    list.innerHTML += `<li>
      <div style="display:flex;justify-content:space-between;align-items:flex-start">
        <strong>${d.header}: <span style="color:var(--cyan);font-family:var(--mono);font-size:0.78rem">${d.value.substring(0,60)}</span></strong>
        <span class="risk-tag ${sevClass[d.severity]||'risk-info'}">${d.severity}</span>
      </div>
      <span class="finding-desc">${d.desc}</span>
      <code class="finding-fix">Supprimer cet en-tête en production via la configuration du framework ou du serveur web.</code>
    </li>`;
  });
  issues.forEach(i => {
    if (i.severity === 'info') return;
    list.innerHTML += `<li>
      <div style="display:flex;justify-content:space-between;align-items:flex-start">
        <strong>${i.title}</strong>
        <span class="risk-tag ${sevClass[i.severity]||'risk-info'}">${i.severity}</span>
      </div>
      <span class="finding-desc">${i.desc}</span>
      <code class="finding-fix">${i.fix}</code>
    </li>`;
  });
  issues.filter(i => i.severity === 'info').forEach(i => {
    list.innerHTML += `<li><span class="finding-desc">${i.title}: ${i.desc}</span></li>`;
  });
  if (!list.innerHTML) list.innerHTML = '<li class="ok">✓ HSTS, CSP et headers avancés correctement configurés</li>';
}

function renderTech(tech) {
  document.getElementById('tech-list').innerHTML = tech.length
    ? tech.map(t=>`<li>${t}</li>`).join('')
    : '<li style="color:var(--text-dim)">Aucune technologie identifiée</li>';
}
