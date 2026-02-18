/**
 * ============================================================
 *  Termite Recon - Chrome Extension
 *  Result Page Script (Findings Renderer)
 * ============================================================
 *  Copyright (c) 2025 muh-syaipullah
 *  GitHub  : https://github.com/muh-syaipullah
 *  License : MIT
 *
 *  Renders scan results: secrets, endpoints, and file type
 *  badges. Supports search, filter, and JSON export.
 * ============================================================
 */

// ── Global event delegation for item-header toggle ─────────────────────
// Attached once to document, handling all dynamically rendered .item-header
document.addEventListener('click', (e) => {
  const header = e.target.closest('.item-header');
  if (!header) return;
  header.classList.toggle('open');
  const body = header.nextElementSibling;
  if (body && body.classList.contains('item-body')) {
    body.classList.toggle('open');
  }
});

// ── Load data from storage ────────────────────────────────────────────────
chrome.storage.local.get(['scanResult', 'scanMeta'], (data) => {
  const results = data.scanResult || [];
  const meta    = data.scanMeta   || {};

  // ── Header & Meta bar ──────────────────────────────────────────────────
  document.getElementById('headerSub').textContent =
    meta.domain ? `Domain: ${meta.domain}` : 'No domain info';

  const metaBar = document.getElementById('metaBar');
  if (meta.scannedAt) {
    const dt = new Date(meta.scannedAt).toLocaleString();
    metaBar.innerHTML = `
      <span><strong>Scanned:</strong> ${dt}</span>
      <span><strong>Pages crawled:</strong> ${meta.pagesFound ?? '—'}</span>
      <span><strong>Files scanned:</strong> ${meta.jsFound ?? '—'}</span>
      <span><strong>Files with findings:</strong> ${meta.withFindings ?? results.length}</span>
    `;
  }

  // ── Summary cards ──────────────────────────────────────────────────────
  const totalSecrets   = results.reduce((n, r) => n + r.secrets.length, 0);
  const totalEndpoints = results.reduce((n, r) => n + r.endpoints.length, 0);
  const filesWithSec   = results.filter(r => r.secrets.length > 0).length;
  const filesWithEp    = results.filter(r => r.endpoints.length > 0).length;

  document.getElementById('summaryGrid').innerHTML = `
    <div class="summary-card">
      <div class="num">${results.length}</div>
      <div class="label">Files with Findings</div>
    </div>
    <div class="summary-card">
      <div class="num">${filesWithSec}</div>
      <div class="label">Files with Secrets</div>
    </div>
    <div class="summary-card">
      <div class="num">${filesWithEp}</div>
      <div class="label">Files with Endpoints</div>
    </div>
    <div class="summary-card">
      <div class="num">${totalSecrets}</div>
      <div class="label">Total Secret Types Found</div>
    </div>
    <div class="summary-card">
      <div class="num">${totalEndpoints}</div>
      <div class="label">Total Unique Endpoints</div>
    </div>
  `;

  if (results.length === 0) {
    ['secretsList', 'endpointsList', 'allList'].forEach(id => {
      document.getElementById(id).innerHTML =
        '<div class="empty">No findings. Run a scan first.</div>';
    });
    return;
  }

  // ── Render all tabs ───────────────────────────────────────────────────
  renderSecrets(results);
  renderEndpoints(results);
  renderAll(results);

  // ── Search handlers ────────────────────────────────────────────────────
  document.getElementById('secretSearch').addEventListener('input', e => {
    renderSecrets(results, e.target.value);
  });
  document.getElementById('endpointSearch').addEventListener('input', e => {
    renderEndpoints(results, e.target.value);
  });
  document.getElementById('allSearch').addEventListener('input', e => {
    const activeFilter = document.querySelector('#tab-all .filter-btn.active')?.dataset.filter || 'all';
    renderAll(results, e.target.value, activeFilter);
  });

  // ── Filter buttons (All tab) ───────────────────────────────────────────
  document.querySelectorAll('#tab-all .filter-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('#tab-all .filter-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      const q = document.getElementById('allSearch').value;
      renderAll(results, q, btn.dataset.filter);
    });
  });

  // ── Export buttons ─────────────────────────────────────────────────────
  document.getElementById('exportSecretsBtn').addEventListener('click', () => {
    const out = results
      .filter(r => r.secrets.length > 0)
      .map(r => ({ file: r.jsUrl, secrets: r.secrets }));
    downloadJson(out, 'secuscan-secrets.json');
  });
  document.getElementById('exportEndpointsBtn').addEventListener('click', () => {
    const out = results
      .filter(r => r.endpoints.length > 0)
      .map(r => ({ file: r.jsUrl, endpoints: r.endpoints }));
    downloadJson(out, 'secuscan-endpoints.json');
  });
  document.getElementById('exportAllBtn').addEventListener('click', () => {
    downloadJson(results, 'secuscan-full.json');
  });
});

// ── Tab switching ──────────────────────────────────────────────────────────
document.querySelectorAll('.tab-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
    btn.classList.add('active');
    document.getElementById('tab-' + btn.dataset.tab).classList.add('active');
  });
});

// ── Render: Secrets tab ───────────────────────────────────────────────────
function renderSecrets(results, query = '') {
  const container = document.getElementById('secretsList');
  const q = query.toLowerCase();

  const filtered = results.filter(r =>
    r.secrets.length > 0 &&
    (!q ||
      r.jsUrl.toLowerCase().includes(q) ||
      r.secrets.some(s =>
        s.type.toLowerCase().includes(q) ||
        s.values.some(v => v.toLowerCase().includes(q))
      )
    )
  );

  if (filtered.length === 0) {
    container.innerHTML = '<div class="empty">No secrets found.</div>';
    return;
  }

  // No onclick here — using event delegation above
  container.innerHTML = filtered.map(r => `
    <div class="result-item has-secrets">
      <div class="item-header">
        ${fileTypeBadge(r.jsUrl)}
        <span class="item-url">${escHtml(r.jsUrl)}</span>
        <span class="badge badge-secret">${r.secrets.length} secret type(s)</span>
        <span class="chevron">&#9658;</span>
      </div>
      <div class="item-body">
        <div class="section-label">Secrets Found</div>
        ${r.secrets.map(s => `
          <div class="secret-group">
            <div class="secret-type ${s.type.startsWith('JSON Key:') ? 'secret-type-json' : ''}">${escHtml(s.type)}</div>
            ${s.values.map(v => `<code class="secret-value">${escHtml(v)}</code>`).join('')}
          </div>
        `).join('')}
      </div>
    </div>
  `).join('');
}

// ── Render: Endpoints tab ─────────────────────────────────────────────────
function renderEndpoints(results, query = '') {
  const container = document.getElementById('endpointsList');
  const q = query.toLowerCase();

  // Collect all unique endpoints along with their source files
  const epMap = new Map(); // endpoint -> Set of files
  results.forEach(r => {
    r.endpoints.forEach(ep => {
      if (!epMap.has(ep)) epMap.set(ep, new Set());
      epMap.get(ep).add(r.jsUrl);
    });
  });

  const entries = [...epMap.entries()].filter(([ep]) =>
    !q || ep.toLowerCase().includes(q)
  );

  if (entries.length === 0) {
    container.innerHTML = '<div class="empty">No endpoints found.</div>';
    return;
  }

  // Group by type
  const apiEntries  = entries.filter(([ep]) => /\/api\//i.test(ep));
  const httpEntries = entries.filter(([ep]) => /^https?:\/\//i.test(ep) && !/\/api\//i.test(ep));
  const pathEntries = entries.filter(([ep]) => !(/^https?:\/\//i.test(ep)));

  function renderGroup(title, items) {
    if (!items.length) return '';
    return `
      <div class="section-label">${title} (${items.length})</div>
      <ul class="endpoint-list" style="margin-bottom:18px">
        ${items.map(([ep, files]) => `
          <li title="Found in: ${escHtml([...files].join(', '))}">
            ${escHtml(ep)}
            <span style="color:#555;font-size:0.78em;margin-left:6px">[${files.size} file(s)]</span>
          </li>
        `).join('')}
      </ul>
    `;
  }

  container.innerHTML =
    renderGroup('API Endpoints', apiEntries) +
    renderGroup('Full URLs', httpEntries) +
    renderGroup('Path Endpoints', pathEntries);
}

// ── Render: All Files tab ─────────────────────────────────────────────────
function renderAll(results, query = '', filter = 'all') {
  const container = document.getElementById('allList');
  const q = query.toLowerCase();

  const filtered = results.filter(r => {
    const matchQ = !q || r.jsUrl.toLowerCase().includes(q);
    const matchF =
      filter === 'all'       ? true :
      filter === 'secrets'   ? r.secrets.length > 0 :
      filter === 'endpoints' ? r.endpoints.length > 0 : true;
    return matchQ && matchF;
  });

  if (filtered.length === 0) {
    container.innerHTML = '<div class="empty">No files match.</div>';
    return;
  }

  // No onclick here — using event delegation above
  container.innerHTML = filtered.map(r => `
    <div class="result-item ${r.secrets.length > 0 ? 'has-secrets' : ''}">
      <div class="item-header">
        ${fileTypeBadge(r.jsUrl)}
        <span class="item-url">${escHtml(r.jsUrl)}</span>
        ${r.secrets.length   > 0 ? `<span class="badge badge-secret">${r.secrets.length} secrets</span>` : ''}
        ${r.endpoints.length > 0 ? `<span class="badge badge-endpoint">${r.endpoints.length} endpoints</span>` : ''}
        ${r.secrets.length === 0 && r.endpoints.length === 0 ? `<span class="badge badge-none">-</span>` : ''}
        <span class="chevron">&#9658;</span>
      </div>
      <div class="item-body">
        ${r.secrets.length > 0 ? `
          <div class="section-label">Secrets</div>
          ${r.secrets.map(s => `
            <div class="secret-group">
              <div class="secret-type ${s.type.startsWith('JSON Key:') ? 'secret-type-json' : ''}">${escHtml(s.type)}</div>
              ${s.values.map(v => `<code class="secret-value">${escHtml(v)}</code>`).join('')}
            </div>
          `).join('')}
        ` : ''}
        ${r.endpoints.length > 0 ? `
          <div class="section-label">Endpoints</div>
          <ul class="endpoint-list">
            ${r.endpoints.map(ep => `<li>${escHtml(ep)}</li>`).join('')}
          </ul>
        ` : ''}
        ${r.secrets.length === 0 && r.endpoints.length === 0 ? `
          <div style="color:#555;font-style:italic;padding:8px 0">No findings in this file.</div>
        ` : ''}
      </div>
    </div>
  `).join('');
}

// ── Helpers ───────────────────────────────────────────────────────────────
function escHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// File type badge based on URL extension
function fileTypeBadge(url) {
  const path = url.split('?')[0].toLowerCase();
  const ext  = path.match(/\.([a-z0-9]+)$/);
  const e    = ext ? '.' + ext[1] : '';

  const map = {
    '.js': ['badge-type-js',   'JS'],
    '.mjs':['badge-type-js',   'MJS'],
    '.ts': ['badge-type-ts',   'TS'],
    '.tsx':['badge-type-ts',   'TSX'],
    '.jsx':['badge-type-ts',   'JSX'],
    '.json':['badge-type-json','JSON'],
    '.jsonc':['badge-type-json','JSONC'],
    '.env': ['badge-type-env', 'ENV'],
    '.yaml':['badge-type-yaml','YAML'],
    '.yml': ['badge-type-yaml','YML'],
    '.xml': ['badge-type-xml', 'XML'],
    '.bak': ['badge-type-bak', 'BAK'],
    '.backup':['badge-type-bak','BAK'],
    '.old': ['badge-type-bak', 'OLD'],
    '.php': ['badge-type-php', 'PHP'],
    '.py':  ['badge-type-php', 'PY'],
    '.rb':  ['badge-type-php', 'RB'],
    '.toml':['badge-type-yaml','TOML'],
    '.ini': ['badge-type-yaml','INI'],
    '.tf':  ['badge-type-yaml','TF'],
    '.graphql':['badge-type-ts','GQL'],
  };

  const [cls, label] = map[e] || ['badge-type-other', e.replace('.','') || 'FILE'];
  return `<span class="badge ${cls}">${label}</span>`;
}

function downloadJson(data, filename) {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href     = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}
