/**
 * ============================================================
 *  Termite Recon - Chrome Extension
 *  Content Script (Scanner Engine)
 * ============================================================
 *  Copyright (c) 2025 muh-syaipullah
 *  GitHub  : https://github.com/muh-syaipullah
 *  License : MIT
 *
 *  Crawls public web files and uncovers API keys,
 *  secrets, and endpoints from JS, JSON, YAML, XML,
 *  ENV, BAK, and other exposed file formats.
 * ============================================================
 */

// ====== Sensitive Patterns ======
// Avoid SyntaxError when this content script is injected/executed multiple times
// by reusing a single global `window.sensitivePatterns` array if already present.
if (typeof window.sensitivePatterns === 'undefined') {
  window.sensitivePatterns = [
  // ── AWS: Credentials ─────────────────────────────────────────────────────
  { name: "AWS Session Token",          regex: /ASIA[0-9A-Z]{16,}/g },
  { name: "AWS SES SMTP Credentials",   regex: /AKIA[0-9A-Z]{16}:[A-Za-z0-9/+=]{40}/g },
  { name: "AWS Access Key",             regex: /(?<![A-Za-z0-9])AKIA[0-9A-Z]{16}(?![A-Za-z0-9])/g },
  { name: "AWS Secret Key",             regex: /(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY|secretAccessKey|SecretAccessKey|secret_access_key|aws_secret|AWSSecretKey|awsSecretKey)\s*[:=]\s*['"]?([A-Za-z0-9\/+=]{40})['"]?/gi },

  // ── AWS: Resource URLs & Patterns ────────────────────────────────────────
  { name: "AWS S3 Bucket (virtual-hosted)", regex: /https?:\/\/[a-z0-9][a-z0-9\-\.]{1,61}[a-z0-9]\.s3[.-][a-z0-9-]*\.amazonaws\.com\/?[^\s"']*/gi },
  { name: "AWS S3 Bucket (path-style)",     regex: /https?:\/\/s3[.-][a-z0-9-]*\.amazonaws\.com\/[a-z0-9][a-z0-9\-\.]{1,61}[^\s"']*/gi },
  { name: "AWS S3 Bucket (s3://)",          regex: /s3:\/\/[a-z0-9][a-z0-9\-\.]{1,61}[a-z0-9](?:\/[^\s"']*)?/gi },
  { name: "AWS ARN",                        regex: /arn:aws[a-z-]*:[a-z0-9-]+:[a-z0-9-]*:\d{12}:[\w\-\/:.+@]+/gi },
  { name: "AWS CloudFront Domain",          regex: /https?:\/\/[a-z0-9]+\.cloudfront\.net\/?[^\s"']*/gi },
  { name: "AWS API Gateway URL",            regex: /https?:\/\/[a-z0-9]{10}\.execute-api\.[a-z0-9-]+\.amazonaws\.com\/[^\s"']*/gi },
  { name: "AWS Cognito Identity Pool ID",   regex: /[a-z]{2}-[a-z]+-\d:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi },
  { name: "AWS Cognito User Pool ID",       regex: /[a-z]{2}-[a-z]+-\d_[A-Za-z0-9]{9}/g },
  { name: "AWS Cognito App Client ID",      regex: /(?:userPoolClientId|clientId|AppClientId)\s*[:=]\s*['"]([0-9a-z]{26})['"]\s*/gi },
  { name: "AWS Lambda Function URL",        regex: /https?:\/\/[a-z0-9]+\.lambda-url\.[a-z0-9-]+\.on\.aws\/?[^\s"']*/gi },
  { name: "AWS SQS Queue URL",              regex: /https?:\/\/sqs\.[a-z0-9-]+\.amazonaws\.com\/\d{12}\/[a-zA-Z0-9_-]+/gi },
  { name: "AWS SNS Topic ARN",              regex: /arn:aws:sns:[a-z0-9-]+:\d{12}:[a-zA-Z0-9_-]+/gi },
  { name: "AWS ECR Registry URL",           regex: /\d{12}\.dkr\.ecr\.[a-z0-9-]+\.amazonaws\.com\/[^\s"']*/gi },
  { name: "AWS RDS Endpoint",               regex: /[a-z0-9-]+\.(?:[a-z0-9-]+\.)?[a-z]{2}-[a-z]+-\d\.rds\.amazonaws\.com/gi },
  { name: "AWS ElastiCache Endpoint",       regex: /[a-z0-9-]+\.(?:[a-z0-9-]+\.)?cfg\.[a-z]{2}-[a-z]+-\d\.cache\.amazonaws\.com/gi },
  { name: "AWS Elastic Beanstalk URL",      regex: /https?:\/\/[a-z0-9-]+\.[a-z]{2}-[a-z]+-\d\.elasticbeanstalk\.com\/?[^\s"']*/gi },
  { name: "AWS Region Hardcoded",           regex: /(?:region|AWS_REGION|aws_region)\s*[:=]\s*['"]?(us|eu|ap|sa|ca|me|af)-[a-z]+-\d['"]?/gi },
  { name: "AWS Account ID",                 regex: /(?:account.?id|accountId|AccountId)\s*[:=]\s*['"]?(\d{12})['"]?/gi },

  // ── Cloud & Infra (Others) ────────────────────────────────────────────────
  { name: "Google Service Account JSON",regex: /"type"\s*:\s*"service_account"/g },
  { name: "Azure Storage Account Key",  regex: /(?:AccountKey|account_key)\s*[:=]\s*['"][A-Za-z0-9+/=]{80,100}['"]/g },
  { name: "Azure SAS Token",            regex: /sv=\d{4}-\d{2}-\d{2}&ss=[a-zA-Z]+&srt=[a-zA-Z]+&sp=[a-zA-Z]+&se=\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z&st=\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z&spr=https?&sig=[A-Za-z0-9%]+/g },
  { name: "Firebase Database URL",      regex: /https?:\/\/[\w-]+\.firebaseio\.com\//g },
  { name: "Google OAuth Client Secret", regex: /"client_secret"\s*:\s*"[A-Za-z0-9-_]{24,}"/g },

  // Database & Backend
  { name: "MySQL URI",                  regex: /mysql:\/\/[\w\d%:._-]+:[\w\d%:._-]+@[\w\d%:._-]+(:\d+)?\/[\w\d%:._-]+/gi },
  { name: "SQL Server URI",             regex: /mssql:\/\/[\w\d%:._-]+:[\w\d%:._-]+@[\w\d%:._-]+(:\d+)?\/[\w\d%:._-]+/gi },
  { name: "Elasticsearch Endpoint",     regex: /https?:\/\/[\w\d\.-]+:9200\/?/g },
  { name: "CouchDB URI",                regex: /https?:\/\/[\w\d%:._-]+:[\w\d%:._-]+@[\w\d%:._-]+(:\d+)?\/[\w\d%:._-]+/gi },
  { name: "Neo4j URI",                  regex: /neo4j\+s?:\/\/[\w\d%:._-]+:[\w\d%:._-]+@[\w\d%:._-]+(:\d+)?\/[\w\d%:._-]+/gi },

  // CI/CD & Source Control
  { name: "GitLab Personal Access Token", regex: /glpat-[0-9a-zA-Z\-_]{20,}/g },
  { name: "GitHub App Token",           regex: /ghs_[0-9a-zA-Z]{36,}/g },
  { name: "CircleCI Token",             regex: /circleci-token-[0-9a-zA-Z\-_]{20,}/g },
  { name: "Travis CI Token",            regex: /travis_[0-9a-zA-Z\-_]{20,}/g },

  // Auth / Identity
  { name: "OAuth Client Secret",        regex: /client_secret\s*[:=]\s*['"][A-Za-z0-9-_]{24,}['"]/g },
  { name: "Auth0 Client Secret",        regex: /auth0.+client_secret\s*[:=]\s*['"][A-Za-z0-9-_]{24,}['"]/gi },
  { name: "Okta API Token",             regex: /\b00[a-zA-Z0-9\-_]{40}\b/g },
  { name: "SAML Certificate",           regex: /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g },

  // Payment & SaaS
  { name: "PayPal Access Token",        regex: /access_token\$production\$[0-9a-zA-Z\-_]+/g },
  { name: "Razorpay API Key",           regex: /rzp_live_[0-9a-zA-Z]{14,}/g },
  { name: "Shopify Private App Token",  regex: /shpat_[0-9a-fA-F]{32,}/g },
  { name: "Square Access Token",        regex: /sq0atp-[0-9A-Za-z\-_]{22,}/g },

  // Messaging & Email
  { name: "Telegram Bot Token",         regex: /\d{9,10}:[a-zA-Z0-9_-]{35}/g },
  { name: "Postmark API Token",         regex: /PM[a-zA-Z0-9]{34,}/g },

  // Generic Credentials
  { name: "Hardcoded Password",         regex: /password\s*[:=]\s*['"][^'"]{4,}['"]/gi },
  { name: "API Key (generic)",          regex: /api_key\s*[:=]\s*['"][A-Za-z0-9\-_]{8,}['"]/gi },
  { name: "Secret (generic)",           regex: /secret\s*[:=]\s*['"][A-Za-z0-9\-_]{8,}['"]/gi },
  { name: "Token (generic)",            regex: /token\s*[:=]\s*['"][A-Za-z0-9\-_]{8,}['"]/gi },

  // Cloud Keys
  { name: "Google API Key",             regex: /AIza[0-9A-Za-z\-_]{35}/g },
  { name: "Firebase Key",               regex: /AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}/g },

  { name: "Supabase Project URL",       regex: /https?:\/\/[a-z0-9\-]+\.supabase\.co/gi },
  { name: "Supabase API Key",           regex: /sbp_[A-Za-z0-9\-_]{30,}/g },
  { name: "Supabase JWT",               regex: /eyJ[A-Za-z0-9_\-]+?\.[A-Za-z0-9_\-]+?\.[A-Za-z0-9_\-]+/g },
  { name: "Stripe Secret Key",          regex: /sk_live_[0-9a-zA-Z]{24}/g },
  { name: "Stripe Test Key",            regex: /sk_test_[0-9a-zA-Z]{24}/g },
  { name: "Stripe Publishable Key",     regex: /pk_(test|live)_[0-9a-zA-Z]{24}/g },
  { name: "GitHub PAT",                 regex: /ghp_[0-9a-zA-Z]{36}/g },
  { name: "GitHub OAuth Token",         regex: /gho_[0-9a-zA-Z]{36}/g },
  { name: "Slack Bot Token",            regex: /xoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,}/g },
  { name: "Slack User Token",           regex: /xoxp-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,}/g },
  { name: "Discord Bot Token",          regex: /[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}/g },
  { name: "Twilio SID",                 regex: /(?<![A-Za-z0-9])AC[a-f0-9]{32}(?![A-Za-z0-9])/gi },
  { name: "Twilio Auth Token",          regex: /(?<![A-Za-z0-9])[a-f0-9]{32}(?![A-Za-z0-9])/gi },
  { name: "SendGrid API Key",           regex: /SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/g },
  { name: "Mailgun API Key",            regex: /key-[0-9a-zA-Z]{32}/g },
  { name: "OpenAI API Key",             regex: /sk-[A-Za-z0-9]{48}/g },
  { name: "Bearer Token",               regex: /Bearer\s+[A-Za-z0-9\-\._~\+\/]+=*/g },
  { name: "JWT Token",                  regex: /\beyJ[A-Za-z0-9_\-]+?\.[A-Za-z0-9_\-]+?\.[A-Za-z0-9_\-]+/g },
  { name: "Private Key",                regex: /-----BEGIN (?:RSA|EC|DSA|PGP) PRIVATE KEY-----/g },
  { name: "MongoDB URI",                regex: /mongodb(?:\+srv)?:\/\/[^ "]+/gi },
  { name: "PostgreSQL URI",             regex: /postgres(?:ql)?:\/\/[^ "]+/gi },
  { name: "Redis URI",                  regex: /redis:\/\/[^ "]+/gi },
  ];
}

const sensitivePatterns = window.sensitivePatterns;

// ====== Endpoint Regex ======
const endpointRegex = new RegExp(
  '(?:"|\'|`)((?:[a-zA-Z]{1,10}://|//)[^"\'`]*?|(?:/|\\./|\\.\\./)[^"\'`\\s<>]+|[a-zA-Z0-9_/\\-]+\\.[^"\'`\\s\\?]+(?:\\?.*)?)(?:"|\'|`)',
  'g'
);

// ====== Helper: fetch with proxy array (chained fallback) ======
// Try each active proxy one by one; if all fail, try direct fetch.
async function fetchText(url, proxies = []) {
  const isLocal = /^https?:\/\/localhost/.test(url);
  const attempts = isLocal ? [] : proxies.filter(p => p && p.trim());
  // Add direct fetch as last fallback
  attempts.push(''); // empty string = direct

  for (const proxy of attempts) {
    const fetchUrl = proxy ? proxy.trim() + encodeURIComponent(url) : url;
    try {
      const res = await fetch(fetchUrl, { cache: 'no-store' });
      if (res.ok) return res.text();
    } catch { /* try next */ }
  }
  throw new Error('All proxies and direct fetch failed');
}

// ====== Extract endpoints from text ======
function extractEndpoints(code) {
  const matches = [...code.matchAll(endpointRegex)];
  const raw = matches.map(m => m[1]);
  return [...new Set(raw.filter(ep =>
    ep &&
    ep.length > 2 &&
    !ep.endsWith('.png') &&
    !ep.endsWith('.jpg') &&
    !ep.endsWith('.gif') &&
    !ep.endsWith('.svg') &&
    !ep.endsWith('.woff') &&
    !ep.endsWith('.woff2') &&
    !ep.endsWith('.ttf') &&
    !ep.endsWith('.eot') &&
    !ep.endsWith('.ico') &&
    !ep.endsWith('.css') &&
    !ep.endsWith('.map') &&
    !ep.endsWith('.png') &&
    !ep.endsWith('.jpg') &&
    !ep.endsWith('.gif') &&
    !ep.endsWith('.svg')
  ))];
}

// ====== JSON-aware deep key-value scan ======
// Walks every key in a parsed JSON object and flags suspicious key names
const SENSITIVE_JSON_KEYS = [
  // AWS
  'aws_access_key_id','aws_secret_access_key','aws_session_token',
  'accesskeyid','secretaccesskey','sessiontoken',
  'aws_region','aws_account_id','accountid',
  // Generic secrets
  'password','passwd','pwd','secret','token','api_key','apikey',
  'api_secret','apisecret','auth_token','authtoken',
  'access_token','accesstoken','refresh_token','refreshtoken',
  'client_secret','clientsecret','private_key','privatekey',
  'encryption_key','encryptionkey','signing_key','signingkey',
  'webhook_secret','jwt_secret','bearer',
  // Database
  'db_password','database_password','db_pass','connection_string',
  'mongodb_uri','postgres_uri','mysql_uri','redis_url','database_url',
  // Cloud / Services
  'firebase_token','firebase_key','supabase_key','stripe_secret',
  'twilio_auth_token','sendgrid_api_key','mailgun_api_key',
  'github_token','gitlab_token','slack_token','discord_token',
  'openai_api_key','anthropic_api_key',
  // Endpoints / URLs
  'endpoint','base_url','baseurl','api_url','apiurl','api_endpoint',
  'server_url','backend_url','host','hostname',
];

function deepScanJson(obj, parentKey = '', depth = 0) {
  if (depth > 10) return []; // prevent infinite recursion
  const found = [];

  if (Array.isArray(obj)) {
    obj.forEach((item, i) => {
      found.push(...deepScanJson(item, `${parentKey}[${i}]`, depth + 1));
    });
  } else if (obj !== null && typeof obj === 'object') {
    for (const [key, value] of Object.entries(obj)) {
      const keyLower = key.toLowerCase().replace(/[-_.]/g, '');
      const fullKey  = parentKey ? `${parentKey}.${key}` : key;

      if (typeof value === 'string' && value.length >= 8) {
        // Check if key name looks sensitive
        const isSensitiveKey = SENSITIVE_JSON_KEYS.some(sk =>
          keyLower.includes(sk.replace(/[-_.]/g, ''))
        );
        if (isSensitiveKey) {
          found.push({ type: `JSON Key: ${fullKey}`, values: [value] });
        }
      }
      // Recurse into nested objects/arrays
      if (typeof value === 'object' && value !== null) {
        found.push(...deepScanJson(value, fullKey, depth + 1));
      }
    }
  }
  return found;
}

// ====== Extract sensitive data from text ======
function extractSensitive(code) {
  const findings = [];

  // ── Regex-based scan (works on any text format) ──────────────────────────
  for (const { name, regex } of sensitivePatterns) {
    regex.lastIndex = 0;
    const matches = code.match(regex) || [];
    if (matches.length) {
      findings.push({ type: name, values: [...new Set(matches)] });
    }
  }

  // ── JSON-aware deep scan (extra layer for .json files) ───────────────────
  try {
    const parsed = JSON.parse(code);
    const jsonFindings = deepScanJson(parsed);
    for (const jf of jsonFindings) {
      // Avoid duplicating what regex already found
      const alreadyFound = findings.some(f =>
        f.values.some(v => jf.values.includes(v))
      );
      if (!alreadyFound) {
        findings.push(jf);
      }
    }
  } catch { /* Not valid JSON — skip deep scan, regex already ran */ }

  return findings;
}

// ====== File extensions that are worth scanning ======
const SCANNABLE_EXT = [
  '.js', '.mjs', '.ts', '.tsx', '.jsx',   // Scripts
  '.json', '.jsonc',                        // JSON configs
  '.env', '.env.local', '.env.prod', '.env.staging', '.env.development',
  '.yaml', '.yml',                          // YAML configs
  '.xml',                                   // XML configs
  '.bak', '.backup', '.old', '.orig', '.tmp', // Backup files
  '.php', '.py', '.rb', '.config', '.conf', // Server-side configs
  '.toml', '.ini',                          // Other config formats
  '.graphql', '.gql',                       // GraphQL
  '.tf',                                    // Terraform
];

function isScannableUrl(url) {
  try {
    const path = new URL(url).pathname.toLowerCase().split('?')[0];
    // No extension or scannable extension
    return SCANNABLE_EXT.some(ext => path.endsWith(ext)) ||
           !path.includes('.');
  } catch { return false; }
}

// ====== Common public paths to probe for exposed configs ======
const COMMON_PROBE_PATHS = [
  // Environment files
  '/.env', '/.env.local', '/.env.development', '/.env.production', '/.env.staging',
  // JSON configs
  '/config.json', '/settings.json', '/appsettings.json', '/app.config.json',
  '/firebase.json', '/.firebaserc',
  '/package.json', '/composer.json', '/Pipfile.lock',
  '/webpack.config.js', '/next.config.js', '/nuxt.config.js',
  // API Docs (endpoint discovery)
  '/swagger.json', '/swagger.yaml', '/openapi.json', '/openapi.yaml',
  '/api-docs', '/api-docs.json', '/v1/api-docs', '/v2/api-docs', '/v3/api-docs',
  '/_api/swagger.json',
  // YAML / XML
  '/.travis.yml', '/circle.yml', '/.circleci/config.yml',
  '/docker-compose.yml', '/docker-compose.yaml',
  '/kubernetes.yaml', '/k8s.yaml',
  '/WEB-INF/web.xml', '/config/database.xml',
  // Backup & exposed files
  '/config.bak', '/config.php.bak', '/wp-config.php.bak',
  '/database.yml', '/database.yaml', '/database.json',
  '/credentials.json', '/credentials.yml', '/secrets.json', '/secrets.yaml',
  // Cloud specific
  '/cloudformation.json', '/cloudformation.yaml', '/serverless.yml',
  '/terraform.tfvars', '/variables.tf',
  // Well-known paths
  '/.well-known/openid-configuration',
  '/robots.txt',
  '/graphql',
];

// ====== Collect all scannable URLs from an HTML string ======
function extractScanUrls(html, baseOrigin) {
  const urls = new Set();

  // <script src="..."> → JS files
  const scriptRegex = /<script[^>]+src=["']([^"']+)["']/gi;
  let m;
  while ((m = scriptRegex.exec(html)) !== null) {
    try {
      const abs = new URL(m[1], baseOrigin).href;
      if (abs.startsWith(baseOrigin)) urls.add(abs);
    } catch {}
  }

  // <link href="..."> → could be JSON/XML/etc
  const linkRegex = /<link[^>]+href=["']([^"']+)["']/gi;
  while ((m = linkRegex.exec(html)) !== null) {
    try {
      const abs = new URL(m[1], baseOrigin).href;
      if (abs.startsWith(baseOrigin) && isScannableUrl(abs)) urls.add(abs);
    } catch {}
  }

  // <a href="..."> → links to config/data files
  const aRegex = /<a[^>]+href=["']([^"'#?]+)["']/gi;
  while ((m = aRegex.exec(html)) !== null) {
    try {
      const abs = new URL(m[1], baseOrigin).href;
      if (abs.startsWith(baseOrigin) && isScannableUrl(abs)) urls.add(abs);
    } catch {}
  }

  return urls;
}

// ====== Collect all page links from HTML ======
function extractPageLinks(html, baseOrigin) {
  const urls = new Set();
  const linkRegex = /<a[^>]+href=["']([^"'#?]+)["']/gi;
  let m;
  while ((m = linkRegex.exec(html)) !== null) {
    const href = m[1];
    try {
      const abs = new URL(href, baseOrigin).href;
      // Only get pages on the same domain, not binary files
      if (
        abs.startsWith(baseOrigin) &&
        !abs.match(/\.(png|jpg|jpeg|gif|svg|ico|css|woff|woff2|ttf|eot|pdf|zip|mp4|mp3)$/i)
      ) {
        urls.add(abs);
      }
    } catch {}
  }
  return urls;
}

// ====== Collect URLs from sitemap.xml ======
function extractSitemapUrls(xml, baseOrigin) {
  const urls = new Set();
  const locRegex = /<loc>(.*?)<\/loc>/gi;
  let m;
  while ((m = locRegex.exec(xml)) !== null) {
    const loc = m[1].trim();
    try {
      const abs = new URL(loc).href;
      if (abs.startsWith(baseOrigin)) urls.add(abs);
    } catch {}
  }
  return urls;
}

// ====== MAIN ======
(async function () {
  const baseOrigin = window.location.origin;
  const baseUrl    = window.location.href;

  // Get active proxy list from storage (saved by popup.js)
  let activeProxies = [];
  try {
    const storage = await new Promise(r => chrome.storage.local.get(['activeProxies'], r));
    if (Array.isArray(storage.activeProxies)) activeProxies = storage.activeProxies;
  } catch {}

  // ── Phase 0: Probe common public config/secret file paths ─────────────
  chrome.runtime.sendMessage({ type: 'scan-progress', text: 'Phase 0: Probing common config paths...' });

  const allTargetUrls = new Set();

  // Add JS from current page DOM (already loaded by browser)
  document.querySelectorAll('script[src]').forEach(s => {
    try {
      const abs = new URL(s.src, baseOrigin).href;
      if (abs.startsWith(baseOrigin)) allTargetUrls.add(abs);
    } catch {}
  });
  // Add current page itself (may have inline data)
  allTargetUrls.add(baseUrl);

  // Probe all common public paths
  for (const probePath of COMMON_PROBE_PATHS) {
    const probeUrl = baseOrigin + probePath;
    try {
      // Use redirect: 'follow' but check if the final URL is different
      const res = await fetch(probeUrl, { method: 'GET', cache: 'no-store' });
      
      if (res.ok) {
        const finalUrl = new URL(res.url);
        const contentType = res.headers.get('content-type') || '';

        // VALIDATION LOGIC:
        // 1. If we requested a specific file path but got redirected to a different path (like /login or /), it's a false positive.
        const pathChanged = finalUrl.pathname !== probePath;
        
        // 2. If we expect a config/env file but get HTML, it's a generic error page/redirect.
        const isHtml = contentType.includes('text/html');
        const isConfigFile = /\.(env|json|yaml|yml|bak|config|conf|xml|bak)$/i.test(probePath);

        if (pathChanged && finalUrl.pathname !== probePath) continue;
        if (isConfigFile && isHtml) continue;

        allTargetUrls.add(probeUrl);
      }
    } catch {}
  }

  // ── Phase 1: Crawl pages and collect scannable files ──────────────────
  chrome.runtime.sendMessage({ type: 'scan-progress', text: 'Phase 1: Discovering pages...' });

  const visitedPages = new Set();
  const pageQueue    = new Set([baseUrl]);

  // Try sitemap.xml
  const sitemapUrls = [`${baseOrigin}/sitemap.xml`, `${baseOrigin}/sitemap_index.xml`];
  for (const smUrl of sitemapUrls) {
    try {
      const xml = await fetchText(smUrl, activeProxies);
      extractSitemapUrls(xml, baseOrigin).forEach(u => pageQueue.add(u));
    } catch {}
  }

  // Crawl pages (max 30 pages)
  const MAX_PAGES = 30;

  for (const pageUrl of pageQueue) {
    if (visitedPages.size >= MAX_PAGES) break;
    if (visitedPages.has(pageUrl)) continue;
    visitedPages.add(pageUrl);

    chrome.runtime.sendMessage({
      type: 'scan-progress',
      text: `Phase 1: Crawling page ${visitedPages.size}/${MAX_PAGES}...`
    });

    try {
      const html = await fetchText(pageUrl, activeProxies);
      // Collect JS + config files from this page
      extractScanUrls(html, baseOrigin).forEach(u => allTargetUrls.add(u));
      // Collect other page links to crawl
      if (visitedPages.size < MAX_PAGES) {
        extractPageLinks(html, baseOrigin).forEach(u => {
          if (!visitedPages.has(u)) pageQueue.add(u);
        });
      }
    } catch {}
  }

  // ── Phase 2: Scan all collected files ─────────────────────────────────
  chrome.runtime.sendMessage({
    type: 'scan-progress',
    text: `Phase 2: Scanning ${allTargetUrls.size} file(s)...`
  });

  const allResults = [];
  let scanned = 0;

  for (const url of allTargetUrls) {
    scanned++;
    chrome.runtime.sendMessage({
      type: 'scan-progress',
      text: `Phase 2: Scanning file ${scanned}/${allTargetUrls.size}...`
    });

    try {
      const code      = await fetchText(url, activeProxies);
      const endpoints = extractEndpoints(code);
      const secrets   = extractSensitive(code);

      // Only save if there are findings
      if (endpoints.length > 0 || secrets.length > 0) {
        allResults.push({ jsUrl: url, endpoints, secrets });
      }
    } catch {}
  }

  // ── Sort: own domain files first, google/tag manager at bottom ──
  allResults.sort((a, b) => {
    const isTagA    = /googletagmanager\.com/i.test(a.jsUrl);
    const isTagB    = /googletagmanager\.com/i.test(b.jsUrl);
    const isGoogleA = /google\./i.test(a.jsUrl);
    const isGoogleB = /google\./i.test(b.jsUrl);
    const hasSecA   = a.secrets.length > 0 ? -1 : 0;
    const hasSecB   = b.secrets.length > 0 ? -1 : 0;

    if (isTagA && !isTagB) return 1;
    if (!isTagA && isTagB) return -1;
    if (isGoogleA && !isGoogleB) return 1;
    if (!isGoogleA && isGoogleB) return -1;
    // Files with secrets move up
    return hasSecA - hasSecB;
  });

  // ── Save result & notify popup ──────────────────────────────────────
  chrome.storage.local.set(
    {
      scanResult: allResults,
      scanMeta: {
        scannedAt:    new Date().toISOString(),
        domain:       baseOrigin,
        pagesFound:   visitedPages.size,
        jsFound:      allTargetUrls.size,
        withFindings: allResults.length,
      }
    },
    () => {
      chrome.runtime.sendMessage({
        type: 'scan-finished',
        jsCount:  allTargetUrls.size,
        findings: allResults.length,
      });
    }
  );
})();
