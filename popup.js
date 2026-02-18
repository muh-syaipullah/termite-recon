/**
 * ============================================================
 *  Termite Recon - Chrome Extension
 *  Popup Script (UI Controller)
 * ============================================================
 *  Copyright (c) 2025 muh-syaipullah
 *  GitHub  : https://github.com/muh-syaipullah
 *  License : MIT
 *
 *  Manages proxy list, triggers scan via content script,
 *  and navigates to the result page.
 * ============================================================
 */

// ── List of known proxies along with their paths ────────────────────────────
// If domain is known, path is auto-filled. If unknown, use /proxy?url=
const KNOWN_PROXIES = {
  'api.codetabs.com':       'https://api.codetabs.com/v1/proxy?quest=',
  'corsproxy.io':           'https://corsproxy.io/?',
  'api.allorigins.win':     'https://api.allorigins.win/raw?url=',
  'cors-anywhere.herokuapp.com': 'https://cors-anywhere.herokuapp.com/',
  'thingproxy.freeboard.io':'https://thingproxy.freeboard.io/fetch/',
  'crossorigin.me':         'https://crossorigin.me/',
};

// Build full proxy URL from user input domain
function buildProxyUrl(domain) {
  const clean = domain.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/$/, '');
  if (KNOWN_PROXIES[clean]) return KNOWN_PROXIES[clean];
  // Unknown → try guessing common format
  return `https://${clean}/proxy?url=`;
}

// ── State: proxy list (array of { domain, url, enabled }) ──────────────
let proxyList = [];

// ── Load state from storage ───────────────────────────────────────────────
chrome.storage.local.get(['proxyList'], (data) => {
  if (Array.isArray(data.proxyList) && data.proxyList.length > 0) {
    proxyList = data.proxyList;
  } else {
    // Default: codetabs active
    proxyList = [
      { domain: 'api.codetabs.com', url: KNOWN_PROXIES['api.codetabs.com'], enabled: true }
    ];
  }
  renderProxyList();
});

// ── Render proxy list in UI ─────────────────────────────────────────────
function renderProxyList() {
  const container = document.getElementById('proxyList');
  const empty     = document.getElementById('proxyEmpty');

  if (proxyList.length === 0) {
    container.innerHTML = '';
    container.appendChild(empty);
    empty.style.display = 'block';
    return;
  }
  empty.style.display = 'none';

  // Remove all old items (except empty)
  [...container.querySelectorAll('.proxy-item')].forEach(el => el.remove());

  proxyList.forEach((p, i) => {
    const item = document.createElement('div');
    item.className = 'proxy-item' + (p.enabled ? '' : ' disabled');

    // Checkbox active/inactive
    const chk = document.createElement('input');
    chk.type    = 'checkbox';
    chk.checked = p.enabled;
    chk.title   = 'Enable/disable this proxy';
    chk.addEventListener('change', () => {
      proxyList[i].enabled = chk.checked;
      item.classList.toggle('disabled', !chk.checked);
      saveProxyList();
    });

    // Domain Label
    const domainEl = document.createElement('span');
    domainEl.className   = 'proxy-domain';
    domainEl.textContent = p.domain;
    domainEl.title       = 'Full URL: ' + p.url;

    // Hint path (short)
    const pathHint = document.createElement('span');
    pathHint.className   = 'proxy-path-hint';
    const urlObj = (() => { try { return new URL(p.url); } catch { return null; } })();
    pathHint.textContent = urlObj ? urlObj.pathname.slice(0, 20) + (urlObj.search ? '…' : '') : '';

    // Delete button
    const delBtn = document.createElement('button');
    delBtn.className   = 'btn-del';
    delBtn.textContent = '✕';
    delBtn.title       = 'Remove this proxy';
    delBtn.addEventListener('click', () => {
      proxyList.splice(i, 1);
      saveProxyList();
      renderProxyList();
    });

    item.append(chk, domainEl, pathHint, delBtn);
    container.appendChild(item);
  });
}

// ── Save to storage ─────────────────────────────────────────────────────
function saveProxyList() {
  chrome.storage.local.set({ proxyList });
}

// ── Add new proxy ─────────────────────────────────────────────────────
document.getElementById('addProxyBtn').addEventListener('click', () => {
  const input  = document.getElementById('proxyDomainInput');
  const domain = input.value.trim();
  if (!domain) return;

  const clean = domain.toLowerCase().replace(/^https?:\/\//, '').replace(/\/$/, '');

  // Prevent duplicate
  if (proxyList.some(p => p.domain === clean)) {
    input.style.borderColor = '#ff9800';
    input.placeholder = 'Domain already exists!';
    setTimeout(() => {
      input.style.borderColor = '';
      input.placeholder = 'example: api.codetabs.com';
    }, 1500);
    input.value = '';
    return;
  }

  const proxyUrl = buildProxyUrl(clean);
  proxyList.push({ domain: clean, url: proxyUrl, enabled: true });
  saveProxyList();
  renderProxyList();
  input.value = '';
});

// Enter in input also triggers Add
document.getElementById('proxyDomainInput').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') document.getElementById('addProxyBtn').click();
});

// ── Scan Button ───────────────────────────────────────────────────────────
document.getElementById('scanBtn').addEventListener('click', () => {
  const scanLoading = document.getElementById('scanLoading');
  const scanStatus  = document.getElementById('scanStatus');

  // Get only active proxies
  const activeProxies = proxyList.filter(p => p.enabled).map(p => p.url);

  // Save to storage so content.js can read
  chrome.storage.local.set({ proxyList, activeProxies }, () => {
    scanLoading.style.display = 'flex';
    scanStatus.textContent = 'Starting scan...';

    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      chrome.scripting.executeScript(
        { target: { tabId: tabs[0].id }, files: ['content.js'] },
        () => {
          const listener = (msg) => {
            if (msg && msg.type === 'scan-progress') {
              scanStatus.textContent = msg.text || 'Scanning...';
            }
            if (msg && msg.type === 'scan-finished') {
              scanLoading.style.display = 'none';
              chrome.runtime.onMessage.removeListener(listener);
              alert(`✅ Scan complete!\n📄 ${msg.jsCount} files found\n🔍 ${msg.findings} files with findings`);
            }
          };
          chrome.runtime.onMessage.addListener(listener);
        }
      );
    });
  });
});

// ── Result Button ─────────────────────────────────────────────────────────
document.getElementById('resultBtn').addEventListener('click', () => {
  chrome.tabs.create({ url: chrome.runtime.getURL('result.html') });
});
