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
      <div class="num" style="color:#eee">${results.length}</div>
      <div class="label">Files with Findings</div>
    </div>
    <div class="summary-card">
      <div class="num" style="color:#e53935">${filesWithSec}</div>
      <div class="label">Files with Secrets</div>
    </div>
    <div class="summary-card">
      <div class="num" style="color:#1e88e5">${filesWithEp}</div>
      <div class="label">Files with Endpoints</div>
    </div>
    <div class="summary-card">
      <div class="num" style="color:#e53935">${totalSecrets}</div>
      <div class="label">Secret Types Found</div>
    </div>
    <div class="summary-card">
      <div class="num" style="color:#1e88e5">${totalEndpoints}</div>
      <div class="label">Unique Endpoints</div>
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

  // ── Init AI Analysis ───────────────────────────────────────────────────
  initAiAnalysis(results, meta);
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
  
  // High priority: Env match (for /.env.local etc)
  if (path.includes('/.env')) return `<span class="badge badge-type-env">ENV</span>`;
  
  const extMatch = path.match(/\.([a-z0-9]+)$/);
  const ext = extMatch ? '.' + extMatch[1] : '';

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
    '.orig':['badge-type-bak', 'ORIG'],
    '.tmp': ['badge-type-bak', 'TMP'],
    '.php': ['badge-type-php', 'PHP'],
    '.py':  ['badge-type-php', 'PY'],
    '.rb':  ['badge-type-php', 'RB'],
    '.toml':['badge-type-yaml','TOML'],
    '.ini': ['badge-type-yaml','INI'],
    '.tf':  ['badge-type-yaml','TF'],
    '.graphql':['badge-type-ts','GQL'],
    '.gql': ['badge-type-ts','GQL'],
  };

  const [cls, label] = map[ext] || ['badge-type-other', ext.replace('.','') || 'FILE'];
  return `<span class="badge ${cls}">${label.toUpperCase()}</span>`;
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

// ══════════════════════════════════════════════════════════════════════════
//  AI SECURITY ANALYSIS ENGINE
// ══════════════════════════════════════════════════════════════════════════

// ── Provider configurations ──────────────────────────────────────────────
const AI_PROVIDERS = {
  gemini: {
    label: '✦ Gemini',
    model: 'gemini-2.0-flash',
    getUrl: (key) => `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${key}`,
    buildBody: (prompt) => ({
      contents: [{ parts: [{ text: prompt }] }],
      generationConfig: { temperature: 0.3, maxOutputTokens: 8192 }
    }),
    extractText: (json) => {
      if (json.candidates && json.candidates[0]) {
        return json.candidates[0].content?.parts?.[0]?.text || '';
      }
      throw new Error(json.error?.message || 'No response from Gemini');
    }
  },
  chatgpt: {
    label: '◉ ChatGPT',
    model: 'gpt-4o-mini',
    getUrl: () => 'https://api.openai.com/v1/chat/completions',
    buildBody: (prompt) => ({
      model: 'gpt-4o-mini',
      messages: [
        { role: 'system', content: 'You are a cybersecurity expert. Analyze scan results and provide detailed security assessment.' },
        { role: 'user', content: prompt }
      ],
      temperature: 0.3,
      max_tokens: 4096
    }),
    getHeaders: (key) => ({ 'Authorization': `Bearer ${key}`, 'Content-Type': 'application/json' }),
    extractText: (json) => {
      if (json.choices && json.choices[0]) {
        return json.choices[0].message?.content || '';
      }
      throw new Error(json.error?.message || 'No response from ChatGPT');
    }
  },
  claude: {
    label: '◈ Claude',
    model: 'claude-3-5-haiku-latest',
    getUrl: () => 'https://api.anthropic.com/v1/messages',
    buildBody: (prompt) => ({
      model: 'claude-3-5-haiku-latest',
      max_tokens: 4096,
      messages: [{ role: 'user', content: prompt }]
    }),
    getHeaders: (key) => ({
      'x-api-key': key,
      'Content-Type': 'application/json',
      'anthropic-version': '2023-06-01',
      'anthropic-dangerous-direct-browser-access': 'true'
    }),
    extractText: (json) => {
      if (json.content && json.content[0]) {
        return json.content[0].text || '';
      }
      throw new Error(json.error?.message || 'No response from Claude');
    }
  },
  deepseek: {
    label: '◆ DeepSeek',
    model: 'deepseek-chat',
    getUrl: () => 'https://api.deepseek.com/chat/completions',
    buildBody: (prompt) => ({
      model: 'deepseek-chat',
      messages: [
        { role: 'system', content: 'You are a cybersecurity expert. Analyze scan results and provide detailed security assessment.' },
        { role: 'user', content: prompt }
      ],
      temperature: 0.3,
      max_tokens: 4096
    }),
    getHeaders: (key) => ({ 'Authorization': `Bearer ${key}`, 'Content-Type': 'application/json' }),
    extractText: (json) => {
      if (json.choices && json.choices[0]) {
        return json.choices[0].message?.content || '';
      }
      throw new Error(json.error?.message || 'No response from DeepSeek');
    }
  },
  openrouter: {
    label: '◯ OpenRouter',
    model: 'google/gemini-2.5-flash', // You can change the model later or give config
    getUrl: () => 'https://openrouter.ai/api/v1/chat/completions',
    buildBody: (prompt) => ({
      model: 'google/gemini-2.5-flash',
      messages: [
        { role: 'system', content: 'You are a cybersecurity expert. Analyze scan results and provide detailed security assessment.' },
        { role: 'user', content: prompt }
      ],
      max_tokens: 4096
    }),
    getHeaders: (key) => ({ 'Authorization': `Bearer ${key}`, 'Content-Type': 'application/json', 'HTTP-Referer': 'https://github.com/muh-syaipullah/termite-recon', 'X-Title': 'Termite Recon' }),
    extractText: (json) => {
      if (json.choices && json.choices[0]) {
        return json.choices[0].message?.content || '';
      }
      throw new Error(json.error?.message || 'No response from OpenRouter');
    }
  }
};

// ── Build the security analysis prompt ───────────────────────────────────
function buildAnalysisPrompt(results, meta) {
  // Collect summary data
  const totalFiles    = results.length;
  const totalSecrets  = results.reduce((n, r) => n + r.secrets.length, 0);
  const totalEndpts   = results.reduce((n, r) => n + r.endpoints.length, 0);
  const domain        = meta.domain || 'Unknown domain';

  // Build secrets summary (limit to avoid token overflow)
  let secretsSummary = '';
  let secretCount = 0;
  for (const r of results) {
    if (r.secrets.length === 0) continue;
    secretsSummary += `\n📄 File: ${r.jsUrl}\n`;
    for (const s of r.secrets) {
      secretsSummary += `  • ${s.type}: ${s.values.slice(0, 3).join(', ')}${s.values.length > 3 ? ` (+${s.values.length - 3} more)` : ''}\n`;
      secretCount++;
      if (secretCount > 50) break; // Limit
    }
    if (secretCount > 50) {
      secretsSummary += '\n  ... (truncated for analysis)\n';
      break;
    }
  }

  // Build endpoints summary (limit to avoid token overflow)
  let endpointsSummary = '';
  const allEndpoints = new Set();
  for (const r of results) {
    for (const ep of r.endpoints) {
      allEndpoints.add(ep);
      if (allEndpoints.size > 80) break;
    }
    if (allEndpoints.size > 80) break;
  }
  endpointsSummary = [...allEndpoints].map(ep => `  • ${ep}`).join('\n');
  if (allEndpoints.size > 80) endpointsSummary += '\n  ... (truncated)';

  return `You are an expert cybersecurity analyst. Analyze the following web application scan results from the domain "${domain}" and provide a comprehensive security assessment.

## Scan Summary
- **Domain**: ${domain}
- **Files with findings**: ${totalFiles}
- **Pages crawled**: ${meta.pagesFound ?? 'N/A'}
- **Files scanned**: ${meta.jsFound ?? 'N/A'}
- **Total secret types found**: ${totalSecrets}
- **Total unique endpoints**: ${totalEndpts}
- **Scan time**: ${meta.scannedAt ?? 'N/A'}

## Secrets/Credentials Found
${secretsSummary || '  (none)'}

## Endpoints Discovered
${endpointsSummary || '  (none)'}

---

Please provide your analysis in the following format (use markdown):

## 🔴 Critical Findings
List any critical security issues (exposed API keys, database credentials, private keys, etc.)
For each finding, include:
- **Severity**: Critical / High / Medium / Low
- **Type**: What was found
- **Location**: Where it was found
- **Risk**: What an attacker could do with this
- **Recommendation**: How to fix it

## 🟡 Warning Findings
List moderate security concerns (exposed endpoints, information disclosure, etc.)

## 🟢 Informational
List low-risk findings and general observations

## 📊 Risk Score
Give an overall risk score from 0-100 and a brief justification

## 🛡️ Recommendations
Provide actionable recommendations prioritized by severity

Keep the analysis concise but thorough. Focus on real, actionable security risks. Do not be alarmist about common/expected findings (like public CDN URLs or standard API endpoints). Highlight things that could lead to data breaches, unauthorized access, or financial loss.`;
}

// ── Simple Markdown to HTML renderer ─────────────────────────────────────
function markdownToHtml(md) {
  let html = md;
  // Escape HTML first (but preserve markdown)
  html = html.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

  // Code blocks (```)
  html = html.replace(/```([a-z]*)\n([\s\S]*?)```/g, (_, lang, code) =>
    `<pre><code>${code.trim()}</code></pre>`
  );

  // Inline code
  html = html.replace(/`([^`]+)`/g, '<code>$1</code>');

  // Headers
  html = html.replace(/^### (.+)$/gm, '<h3>$1</h3>');
  html = html.replace(/^## (.+)$/gm, '<h2>$1</h2>');
  html = html.replace(/^# (.+)$/gm, '<h1>$1</h1>');

  // Bold
  html = html.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');

  // Italic
  html = html.replace(/\*(.+?)\*/g, '<em>$1</em>');

  // Severity highlighting
  html = html.replace(/\b(Critical)\b/gi, '<span class="severity-critical">$1</span>');
  html = html.replace(/\b(High)\b/gi, '<span class="severity-high">$1</span>');
  html = html.replace(/\b(Medium)\b/gi, '<span class="severity-medium">$1</span>');
  html = html.replace(/\b(Low)\b/gi, '<span class="severity-low">$1</span>');

  // Unordered lists
  html = html.replace(/^- (.+)$/gm, '<li>$1</li>');
  html = html.replace(/(<li>.*<\/li>\n?)+/g, '<ul>$&</ul>');

  // Line breaks (avoid double <br> inside block elements)
  html = html.replace(/\n\n/g, '</p><p>');
  html = html.replace(/\n/g, '<br>');

  // Wrap in paragraphs
  html = '<p>' + html + '</p>';

  // Clean up empty paragraphs
  html = html.replace(/<p>\s*<\/p>/g, '');
  html = html.replace(/<p>(<h[1-3]>)/g, '$1');
  html = html.replace(/(<\/h[1-3]>)<\/p>/g, '$1');
  html = html.replace(/<p>(<pre>)/g, '$1');
  html = html.replace(/(<\/pre>)<\/p>/g, '$1');
  html = html.replace(/<p>(<ul>)/g, '$1');
  html = html.replace(/(<\/ul>)<\/p>/g, '$1');

  return html;
}

// ── Call AI API ──────────────────────────────────────────────────────────
async function callAiApi(provider, apiKey, prompt) {
  const config = AI_PROVIDERS[provider];
  if (!config) throw new Error(`Unknown AI provider: ${provider}`);

  const url     = config.getUrl(apiKey);
  const body    = config.buildBody(prompt);
  const headers = config.getHeaders
    ? config.getHeaders(apiKey)
    : { 'Content-Type': 'application/json' };

  const response = await fetch(url, {
    method: 'POST',
    headers,
    body: JSON.stringify(body)
  });

  if (!response.ok) {
    const errText = await response.text();
    let errMsg = `HTTP ${response.status}`;
    try {
      const errJson = JSON.parse(errText);
      errMsg = errJson.error?.message || errJson.error?.status || errMsg;
    } catch { errMsg += `: ${errText.slice(0, 200)}`; }
    throw new Error(errMsg);
  }

  const json = await response.json();
  return config.extractText(json);
}

// ── Initialize AI Analysis Section ──────────────────────────────────────
function initAiAnalysis(results, meta) {
  const providerTag  = document.getElementById('aiProviderTag');
  const analyzeBtn   = document.getElementById('btnAiAnalyze');
  const noKeyMsg     = document.getElementById('aiNoKey');
  const loadingEl    = document.getElementById('aiLoading');
  const loadingText  = document.getElementById('aiLoadingText');
  const errorEl      = document.getElementById('aiError');
  const resultEl     = document.getElementById('aiResult');

  chrome.storage.local.get(['aiApiKey', 'aiProvider'], (data) => {
    const apiKey   = data.aiApiKey;
    const provider = data.aiProvider;

    if (!apiKey || !provider) {
      noKeyMsg.style.display = 'block';
      return;
    }

    // Show provider badge and analyze button
    const config = AI_PROVIDERS[provider];
    if (config) {
      providerTag.textContent = `${config.label} (${config.model})`;
      providerTag.className = `ai-provider-tag ${provider}`;
      providerTag.style.display = 'inline-flex';
    }

    analyzeBtn.style.display = 'flex';

    // Run analysis handler
    const runAnalysis = async () => {
      analyzeBtn.disabled = true;
      analyzeBtn.innerHTML = '<span>⏳</span> Analyzing...';
      loadingEl.classList.add('active');
      errorEl.classList.remove('active');
      resultEl.classList.remove('active');

      try {
        loadingText.textContent = `Building analysis prompt...`;
        const prompt = buildAnalysisPrompt(results, meta);

        loadingText.textContent = `Sending to ${config?.label || provider}...`;

        const analysisText = await callAiApi(provider, apiKey, prompt);

        loadingText.textContent = 'Rendering analysis...';

        // Render the result
        resultEl.innerHTML = markdownToHtml(analysisText);
        resultEl.classList.add('active');

        // Scroll to result
        resultEl.scrollIntoView({ behavior: 'smooth', block: 'start' });

      } catch (err) {
        errorEl.textContent = `❌ AI Analysis Error: ${err.message}`;
        errorEl.classList.add('active');
      } finally {
        loadingEl.classList.remove('active');
        analyzeBtn.disabled = false;
        analyzeBtn.innerHTML = '<span>▶</span> Run AI Analysis';
      }
    };

    analyzeBtn.addEventListener('click', runAnalysis);

    // Auto-run analysis if there are results
    if (results.length > 0) {
      runAnalysis();
    }
  });
}

