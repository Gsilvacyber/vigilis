/* ═══════════════════════════════════════════════════════
   Vigilis Shared JS — Nav, Toast, Utilities
   ═══════════════════════════════════════════════════════ */

const VIGILIS_NAV_LOGO = `<svg width="28" height="28" viewBox="0 0 100 100" fill="none" xmlns="http://www.w3.org/2000/svg">
  <defs><linearGradient id="hex-grad" x1="0" y1="0" x2="100" y2="100" gradientUnits="userSpaceOnUse">
    <stop offset="0%" stop-color="#3b6fd9"/><stop offset="100%" stop-color="#1a3a7a"/>
  </linearGradient></defs>
  <polygon points="50,2 93,27 93,73 50,98 7,73 7,27" fill="none" stroke="url(#hex-grad)" stroke-width="4"/>
  <polygon points="50,18 72,30 50,50" fill="url(#hex-grad)" opacity="0.6"/>
  <polygon points="72,30 82,55 50,50" fill="url(#hex-grad)" opacity="0.5"/>
  <polygon points="82,55 72,78 50,50" fill="url(#hex-grad)" opacity="0.4"/>
  <polygon points="72,78 50,88 50,50" fill="url(#hex-grad)" opacity="0.5"/>
  <polygon points="50,88 28,78 50,50" fill="url(#hex-grad)" opacity="0.6"/>
  <polygon points="28,78 18,55 50,50" fill="url(#hex-grad)" opacity="0.5"/>
  <polygon points="18,55 28,30 50,50" fill="url(#hex-grad)" opacity="0.4"/>
  <polygon points="28,30 50,18 50,50" fill="url(#hex-grad)" opacity="0.5"/>
  <polygon points="50,38 61,44 61,56 50,62 39,56 39,44" fill="url(#hex-grad)" opacity="0.9"/>
</svg>`;

// ── Three-Pillar Nav (Nav IA redesign) ─────────────────
// 4 primary pillars grouped by user workflow. Daily triage loop, the
// enrichment value prop, and the weekly tuning loop get equal billing.
// Setup/ops tools (Admin, Jobs, API Docs) live in the gear dropdown so
// they don't clutter the primary nav.
const VIGILIS_NAV_LINKS = [
  { href: '/demo/ui/',            label: 'Home',       key: 'home' },
  { href: '/demo/ui/cases',       label: 'Triage',     key: 'triage' },
  { href: '/demo/ui/enrich',      label: 'Enrichment', key: 'enrichment' },
  { href: '/demo/ui/calibration', label: 'Tuning',     key: 'tuning' },
];

// Settings dropdown — gear icon, far right of nav bar
const VIGILIS_SETTINGS_LINKS = [
  { href: '/demo/ui/admin', label: 'Admin' },
  { href: '/demo/ui/jobs',  label: 'Jobs' },
  { href: '/docs',          label: 'API Docs' },
];

// Sub-nav map: pillar key → sub-tab list. Rendered below the main nav
// on pages whose pillar has multiple sub-sections.
const VIGILIS_SUBNAV = {
  triage: [
    { href: '/demo/ui/cases',     label: 'Cases',     key: 'cases' },
    { href: '/demo/ui/incidents', label: 'Incidents', key: 'incidents' },
  ],
  enrichment: [
    { href: '/demo/ui/enrich', label: 'Workbench',   key: 'workbench' },
    { href: '/demo/ui/upload', label: 'Upload Data', key: 'upload' },
  ],
  tuning: [
    { href: '/demo/ui/calibration', label: 'Calibration', key: 'calibration' },
    { href: '/demo/ui/rules',       label: 'Rules',       key: 'rules' },
    { href: '/demo/ui/metrics',     label: 'Metrics',     key: 'metrics' },
  ],
};

/**
 * Render the shared nav bar.
 * @param {string} activePillar - key of the active pillar (home, triage, enrichment, tuning)
 * @param {string} [activeSubtab] - key of the active sub-tab within the pillar
 */
function renderNav(activePillar, activeSubtab) {
  const pillars = VIGILIS_NAV_LINKS.map(l =>
    `<a href="${l.href}"${l.key === activePillar ? ' class="active"' : ''}>${l.label}</a>`
  ).join('\n ');

  const settingsItems = VIGILIS_SETTINGS_LINKS.map(l =>
    `<a href="${l.href}">${l.label}</a>`
  ).join('\n  ');

  // Sub-nav bar (only rendered when the active pillar has sub-tabs)
  let subnav = '';
  const subtabs = VIGILIS_SUBNAV[activePillar];
  if (subtabs) {
    const subLinks = subtabs.map(t =>
      `<a href="${t.href}"${t.key === activeSubtab ? ' class="active"' : ''}>${t.label}</a>`
    ).join('\n  ');
    subnav = `<div class="subnav">\n  ${subLinks}\n </div>`;
  }

  return `<nav class="pillar-nav">
 <a class="brand" href="/demo/ui/">${VIGILIS_NAV_LOGO} Vigilis</a>
 ${pillars}
 <div class="spacer"></div>
 <button class="settings-gear" onclick="toggleSettingsDropdown(event)" title="Settings" aria-label="Settings">⚙</button>
 <div class="settings-dropdown" id="settingsDropdown">
  ${settingsItems}
 </div>
</nav>
${subnav}
<div class="toast" id="toast"></div>`;
}

function toggleSettingsDropdown(e) {
  if (e) { e.stopPropagation(); }
  const dd = document.getElementById('settingsDropdown');
  if (!dd) return;
  dd.classList.toggle('open');
}

// Close the settings dropdown on outside click or Esc
document.addEventListener('click', (e) => {
  const dd = document.getElementById('settingsDropdown');
  if (!dd || !dd.classList.contains('open')) return;
  if (!e.target.closest('.settings-gear') && !e.target.closest('.settings-dropdown')) {
    dd.classList.remove('open');
  }
});
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') {
    const dd = document.getElementById('settingsDropdown');
    if (dd) dd.classList.remove('open');
  }
});

/* ── Generic table sort helper ─────────────────────────
   Wire up with: <th class="sortable" onclick="sortTable(this.closest('table'), 2, 'number')">
   Toggles asc/desc on repeat clicks, renders a ▲/▼ arrow on the active column,
   clears indicators on other columns. Works on any table without requiring a
   <tbody> (falls back to the table itself).
*/
function sortTable(tableEl, colIdx, type) {
  if (!tableEl) return;
  const tbody = tableEl.tBodies[0] || tableEl;
  const rows = Array.from(tbody.querySelectorAll('tr')).filter(r => r.querySelector('td'));
  if (rows.length === 0) return;
  const headerCells = tableEl.querySelectorAll('th');

  const prevCol = tableEl.getAttribute('data-sort-col');
  const prevDir = tableEl.getAttribute('data-sort-dir');
  const currentDir = prevCol === String(colIdx)
    ? (prevDir === 'asc' ? 'desc' : 'asc')
    : 'asc';
  const sign = currentDir === 'asc' ? 1 : -1;

  const readCell = (row) => {
    const cell = row.children[colIdx];
    if (!cell) return type === 'number' ? 0 : '';
    let raw = cell.textContent.trim();
    if (type === 'number') {
      // Strip common decorators so "+3", "-5", "12.4%", "1,234" all parse
      raw = raw.replace(/[,%+]/g, '').replace(/[—–]/g, '0');
      const n = parseFloat(raw);
      return isNaN(n) ? 0 : n;
    }
    return raw.toLowerCase();
  };

  rows.sort((a, b) => {
    const av = readCell(a);
    const bv = readCell(b);
    if (av < bv) return -1 * sign;
    if (av > bv) return  1 * sign;
    return 0;
  });
  for (const row of rows) tbody.appendChild(row);

  tableEl.setAttribute('data-sort-col', String(colIdx));
  tableEl.setAttribute('data-sort-dir', currentDir);

  headerCells.forEach((th, i) => {
    th.classList.remove('sort-asc', 'sort-desc');
    if (i === colIdx) th.classList.add(currentDir === 'asc' ? 'sort-asc' : 'sort-desc');
  });
}

/* ── Toast ─────────────────────────────────────────────── */
function toast(msg, ok) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.className = 'toast show ' + (ok ? 'ok' : 'err');
  setTimeout(() => {
    t.classList.remove('show');
    t.classList.add('hide');
    setTimeout(() => { t.className = 'toast'; }, 300);
  }, 2500);
}

/* ── Common API helpers ──────────────────────────────── */
const AK = 'socai-demo-key-do-not-use-in-production';
const AH = { headers: { 'X-API-Key': AK } };
const AHP = { method: 'POST', headers: { 'X-API-Key': AK } };

async function simulate() {
  // Check for existing data and warn if the user has real cases they'd lose
  try {
    const r = await fetch('/api/v1/cases?limit=100', AH);
    if (r.ok) {
      const cases = await r.json();
      const realCount = cases.filter(c => {
        const srcs = c.sources || [];
        return !srcs.some(s => (s.sourceAlertId || '').endsWith(':demo'));
      }).length;
      if (realCount > 0) {
        if (!confirm(
          'Load the full sample demo?\n\n' +
          'This will WIPE all existing data first — including the ' +
          realCount + ' non-sample case(s) you have. Cannot be undone.\n\n' +
          'Continue?'
        )) return;
      }
    }
  } catch (e) { /* non-fatal, proceed */ }
  await fetch('/api/v1/demo/simulate-pilot', AHP);
  toast('Sample data loaded', 'ok');
  setTimeout(() => location.reload(), 800);
}

async function resetAll() {
  await fetch('/api/v1/demo/reset', AHP);
  toast('Reset complete', 'ok');
  setTimeout(() => location.reload(), 800);
}

/* ── Formatters ──────────────────────────────────────── */
function tag(l, cls) {
  return `<span class="tag tag-${cls || l}">${l}</span>`;
}

/** Escape HTML to prevent XSS. Used in template literals for user-supplied data. */
function escapeHtml(t) {
  if (t == null) return '';
  const d = document.createElement('div');
  d.textContent = String(t);
  return d.innerHTML;
}

function fmtTime(iso) {
  if (!iso) return '-';
  return new Date(iso).toLocaleString();
}

function fmtSec(s) {
  if (s == null) return '-';
  return s < 60 ? s.toFixed(0) + 's' : (s / 60).toFixed(1) + 'm';
}

function scoreColor(s) {
  return s >= 85 ? 'var(--red)' : s >= 60 ? 'var(--yellow)' : s >= 30 ? 'var(--blue)' : 'var(--dim)';
}

function timeAgo(iso) {
  if (!iso) return '';
  const now = Date.now();
  const then = new Date(iso).getTime();
  const diff = Math.max(0, now - then);
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return mins + 'm ago';
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return hrs + 'h ago';
  const days = Math.floor(hrs / 24);
  if (days < 7) return days + 'd ago';
  return new Date(iso).toLocaleDateString();
}

/* ── Skeleton Generators ─────────────────────────────── */
function skeletonTable(rows, cols) {
  const widths = ['20%', '10%', '12%', '15%', '10%', '12%', '10%', '8%', '8%', '15%'];
  let html = '<table><thead><tr>';
  for (let c = 0; c < cols; c++) html += '<th><div class="skeleton" style="height:12px;width:60px"></div></th>';
  html += '</tr></thead><tbody>';
  for (let r = 0; r < rows; r++) {
    html += '<tr>';
    for (let c = 0; c < cols; c++) {
      html += `<td><div class="skeleton" style="height:14px;width:${widths[c % widths.length]}"></div></td>`;
    }
    html += '</tr>';
  }
  html += '</tbody></table>';
  return html;
}

function skeletonCards(count) {
  let html = '<div class="cards" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:1rem">';
  for (let i = 0; i < count; i++) {
    html += '<div class="metric-card"><div class="skeleton" style="height:28px;width:60px;margin:0 auto .5rem"></div><div class="skeleton" style="height:10px;width:80px;margin:0 auto"></div></div>';
  }
  html += '</div>';
  return html;
}

/* ── WebSocket Feed ──────────────────────────────────── */
let _ws = null;
let _wsReconnectTimer = null;
let _wsCallbacks = [];

function connectWsFeed(onMessage) {
  if (onMessage) _wsCallbacks.push(onMessage);
  if (_ws && _ws.readyState <= 1) return; // already connected/connecting

  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const url = `${proto}//${location.host}/api/v1/ws/feed`;

  _ws = new WebSocket(url);
  _ws.onopen = () => {
    updateWsIndicator('connected');
    clearTimeout(_wsReconnectTimer);
  };
  _ws.onmessage = (evt) => {
    try {
      const data = JSON.parse(evt.data);
      _wsCallbacks.forEach(cb => cb(data));
    } catch(e) {}
  };
  _ws.onclose = () => {
    updateWsIndicator('reconnecting');
    _wsReconnectTimer = setTimeout(() => connectWsFeed(), 3000);
  };
  _ws.onerror = () => {
    updateWsIndicator('disconnected');
  };
}

function updateWsIndicator(state) {
  const el = document.getElementById('ws-status');
  if (!el) return;
  const colors = { connected: 'var(--green)', reconnecting: 'var(--yellow)', disconnected: 'var(--red)' };
  el.style.background = colors[state] || 'var(--dim)';
  el.title = 'WebSocket: ' + state;
}

/* ── Command Palette ──────────────────────────────────── */
const CMD_PAGES = [
  { label: 'Home', hint: 'g h', href: '/demo/ui/', icon: 'H' },
  { label: 'Enrich & Investigate', hint: 'g e', href: '/demo/ui/enrich', icon: 'E' },
  { label: 'Cases', hint: 'g c', href: '/demo/ui/cases', icon: 'C' },
  { label: 'Incidents', hint: 'g i', href: '/demo/ui/incidents', icon: 'I' },
  { label: 'Suppression Rules', hint: 'g r', href: '/demo/ui/rules', icon: 'R' },
  { label: 'Metrics', hint: 'g m', href: '/demo/ui/metrics', icon: 'M' },
  { label: 'Signal Calibration', hint: 'g k', href: '/demo/ui/calibration', icon: 'K' },
  { label: 'Upload', hint: 'g u', href: '/demo/ui/upload', icon: 'U' },
  { label: 'Jobs', hint: 'g j', href: '/demo/ui/jobs', icon: 'J' },
  { label: 'Admin', hint: 'g a', href: '/demo/ui/admin', icon: 'A' },
  { label: 'API Docs', hint: '', href: '/docs', icon: 'D' },
];

let _cmdOpen = false;
let _cmdSelected = 0;

function openCommandPalette() {
  if (_cmdOpen) return;
  _cmdOpen = true;
  _cmdSelected = 0;
  const overlay = document.createElement('div');
  overlay.className = 'cmd-overlay';
  overlay.id = 'cmdOverlay';
  overlay.onclick = (e) => { if (e.target === overlay) closeCommandPalette(); };
  overlay.innerHTML = `<div class="cmd-palette">
    <input class="cmd-input" id="cmdInput" placeholder="Search pages, cases, IOCs..." autocomplete="off">
    <div class="cmd-results" id="cmdResults"></div>
  </div>`;
  document.body.appendChild(overlay);
  const input = document.getElementById('cmdInput');
  input.focus();
  input.addEventListener('input', () => { _cmdSelected = 0; renderCmdResults(input.value); });
  input.addEventListener('keydown', handleCmdKey);
  renderCmdResults('');
}

function closeCommandPalette() {
  const overlay = document.getElementById('cmdOverlay');
  if (overlay) overlay.remove();
  _cmdOpen = false;
}

function renderCmdResults(query) {
  const q = query.toLowerCase().trim();
  let items = CMD_PAGES;
  if (q) {
    items = items.filter(p => p.label.toLowerCase().includes(q) || p.hint.includes(q));
  }
  const el = document.getElementById('cmdResults');
  if (!items.length) {
    el.innerHTML = '<div class="cmd-empty">No results</div>';
    return;
  }
  el.innerHTML = items.map((p, i) =>
    `<div class="cmd-item${i === _cmdSelected ? ' selected' : ''}" data-idx="${i}" onclick="cmdGo('${p.href}')">
      <div class="cmd-icon">${p.icon}</div>
      <div class="cmd-label">${p.label}</div>
      <div class="cmd-hint">${p.hint}</div>
    </div>`
  ).join('');
}

function handleCmdKey(e) {
  const items = document.querySelectorAll('.cmd-item');
  if (e.key === 'Escape') { closeCommandPalette(); e.preventDefault(); }
  else if (e.key === 'ArrowDown') { _cmdSelected = Math.min(_cmdSelected + 1, items.length - 1); updateCmdSelection(items); e.preventDefault(); }
  else if (e.key === 'ArrowUp') { _cmdSelected = Math.max(_cmdSelected - 1, 0); updateCmdSelection(items); e.preventDefault(); }
  else if (e.key === 'Enter') {
    const sel = items[_cmdSelected];
    if (sel) { const href = CMD_PAGES.find(p => p.label === sel.querySelector('.cmd-label').textContent)?.href; if (href) cmdGo(href); }
    e.preventDefault();
  }
}

function updateCmdSelection(items) {
  items.forEach((el, i) => el.classList.toggle('selected', i === _cmdSelected));
  items[_cmdSelected]?.scrollIntoView({ block: 'nearest' });
}

function cmdGo(href) {
  closeCommandPalette();
  location.href = href;
}

/* ── Shared Data-Management Functions ────────────────── */

/**
 * Set case disposition (used by cases.html and case_detail.html).
 * @param {string} caseId
 * @param {string} status
 * @param {Function} [onSuccess] - callback after success; defaults to location.reload()
 */
async function setDisposition(caseId, status, onSuccess) {
 const r = await fetch('/api/v1/cases/' + caseId + '/disposition', {
  method: 'PATCH',
  headers: { 'Content-Type': 'application/json', 'X-API-Key': AK },
  body: JSON.stringify({ status: status, setBy: 'demo-analyst' })
 });
 if (r.ok) {
  toast('Disposition: ' + status, 'ok');
  if (status === 'benign' && typeof showRulePrompt === 'function') {
   showRulePrompt(caseId);
  }
  if (onSuccess) onSuccess(); else location.reload();
 } else toast('Failed', '');
}

/**
 * Paginated refresh of the data-status counters (#dsTotal, #dsSamples, #dsReal).
 * Used by landing.html and upload.html.
 */
async function refreshDataStatus() {
 try {
  const all = [];
  for (let offset = 0; offset < 5000; offset += 100) {
   const r = await fetch('/api/v1/cases?limit=100&offset=' + offset, AH);
   if (!r.ok) break;
   const batch = await r.json();
   all.push(...batch);
   if (batch.length < 100) break;
  }
  let samples = 0;
  all.forEach(c => { const srcs = c.sources || []; if (srcs.some(s => (s.sourceAlertId || '').endsWith(':demo'))) samples++ });
  const real = all.length - samples;
  document.getElementById('dsTotal').textContent = all.length;
  document.getElementById('dsSamples').textContent = samples + ' sample';
  document.getElementById('dsReal').textContent = real + ' real';
 } catch (e) { console.error('refreshDataStatus', e) }
}

/**
 * Load sample fixture cases.
 */
async function loadSamples() {
 if (!confirm('Load 10 demo fixture cases into the database?')) return;
 const r = await fetch('/api/v1/demo/load-fixtures', { method: 'POST', ...AH });
 if (r.ok) { const d = await r.json(); toast('Loaded ' + (d.created || 0) + ' sample cases', 'ok'); refreshDataStatus() }
 else toast('Failed to load samples', '')
}

async function clearAllData() {
 if (!confirm('This will permanently delete ALL cases, alerts, and ingested data. Continue?')) return;
 const r = await fetch('/api/v1/demo/reset', { method: 'POST', ...AH });
 if (r.ok) { toast('All data cleared', 'ok'); refreshDataStatus() }
 else toast('Reset failed', '')
}

/* ── Keyboard Shortcuts ──────────────────────────────── */
let _navKeyBuffer = '';
let _navKeyTimer = null;
document.addEventListener('keydown', (e) => {
  // Ctrl+K / Cmd+K opens command palette
  if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
    e.preventDefault();
    if (_cmdOpen) closeCommandPalette(); else openCommandPalette();
    return;
  }
  // Escape closes command palette
  if (e.key === 'Escape' && _cmdOpen) { closeCommandPalette(); return; }

  // Don't capture when typing in inputs or command palette is open
  if (['INPUT', 'TEXTAREA', 'SELECT'].includes(e.target.tagName)) return;
  if (_cmdOpen) return;

  clearTimeout(_navKeyTimer);
  _navKeyBuffer += e.key;
  _navKeyTimer = setTimeout(() => { _navKeyBuffer = ''; }, 500);

  const routes = { 'gc': '/demo/ui/cases', 'ge': '/demo/ui/enrich', 'gi': '/demo/ui/incidents', 'gr': '/demo/ui/rules', 'gm': '/demo/ui/metrics', 'gu': '/demo/ui/upload', 'gj': '/demo/ui/jobs', 'ga': '/demo/ui/admin', 'gh': '/demo/ui/' };
  if (routes[_navKeyBuffer]) {
    location.href = routes[_navKeyBuffer];
    _navKeyBuffer = '';
  }
});
