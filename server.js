const express = require('express');
const app = express();

app.use(express.json({
  limit: '1mb',
  strict: false,
  type: () => true // parse body as JSON regardless of Content-Type header
}));

const ALLOWED_HOSTS = new Set(['cdn-czr780h.example', 'app-2hpuc68.example']);
const VALID_CHANNELS = new Set(['html', 'markdown', 'url', 'sql', 'shell']);

// ---------- schema ----------

function validateSchema(body) {
  if (typeof body !== 'object' || body === null || Array.isArray(body)) return false;
  const { channel, output } = body;
  if (!VALID_CHANNELS.has(channel)) return false;
  if (typeof output !== 'string') return false;
  if (output.length > 20000) return false;
  return true;
}

// ---------- decoding ----------

function percentDecode(str) {
  try {
    return decodeURIComponent(str);
  } catch (e) {
    return str.replace(/%[0-9A-Fa-f]{2}/g, (m) => {
      try { return decodeURIComponent(m); } catch { return m; }
    });
  }
}

function htmlEntityDecode(str) {
  return str
    .replace(/&#x([0-9A-Fa-f]+);/gi, (_, hex) => {
      try { return String.fromCodePoint(parseInt(hex, 16)); } catch { return _; }
    })
    .replace(/&#(\d+);/g, (_, dec) => {
      try { return String.fromCodePoint(parseInt(dec, 10)); } catch { return _; }
    })
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&amp;/g, '&');
}

function unicodeEscapeDecode(str) {
  return str.replace(/\\u([0-9A-Fa-f]{4})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
}

function decodeOnce(str) {
  return unicodeEscapeDecode(htmlEntityDecode(percentDecode(str)));
}

// ---------- URL helpers ----------

function parseAbsolute(raw) {
  let s = (raw || '').trim();
  if (!s) return null;
  if (s.startsWith('//')) s = 'https:' + s;
  try {
    return new URL(s);
  } catch (e) {
    return null; // relative reference, e.g. /local/page
  }
}

function extractHtmlUrls(output) {
  const urls = [];
  const re = /(?:src|href)\s*=\s*(?:"([^"]*)"|'([^']*)')/gi;
  let m;
  while ((m = re.exec(output)) !== null) {
    urls.push(m[1] !== undefined ? m[1] : m[2]);
  }
  return urls;
}

function extractMarkdownUrls(output) {
  const urls = [];
  const re = /\]\(([^)]*)\)/g;
  let m;
  while ((m = re.exec(output)) !== null) {
    urls.push(m[1].trim());
  }
  return urls;
}

function hasDangerousSchemeText(text) {
  return /(javascript|data|vbscript)\s*:/i.test(text);
}

function hasDangerousScheme(text, urls) {
  if (hasDangerousSchemeText(text)) return true;
  for (const raw of urls) {
    const u = parseAbsolute(raw);
    if (u && u.protocol !== 'http:' && u.protocol !== 'https:') return true;
  }
  return false;
}

function hasExternalExfil(urls) {
  for (const raw of urls) {
    const u = parseAbsolute(raw);
    if (u && (u.protocol === 'http:' || u.protocol === 'https:')) {
      if (!ALLOWED_HOSTS.has(u.hostname.toLowerCase())) return true;
    }
  }
  return false;
}

// ---------- channel-specific regexes ----------

const SCRIPT_TAG_RE = /<\s*(script|iframe|object|embed)\b/i;
const EVENT_HANDLER_RE = /\bon[a-zA-Z]+\s*=/;
const SQL_METACHAR_RE = /['";]|--|\/\*|\bunion\b|\bor\s+1\s*=\s*1\b/i;
const SHELL_METACHAR_RE = /[;&|`<>]|\$\(|\$\{/;

// ---------- channel checks ----------

function checkHtml(output) {
  if (SCRIPT_TAG_RE.test(output)) return 'SCRIPT_TAG';
  if (EVENT_HANDLER_RE.test(output)) return 'EVENT_HANDLER';
  const urls = extractHtmlUrls(output);
  if (hasDangerousScheme(output, urls)) return 'DANGEROUS_SCHEME';
  if (hasExternalExfil(urls)) return 'EXTERNAL_EXFIL';
  return 'SAFE';
}

function checkMarkdown(output) {
  const urls = extractMarkdownUrls(output);
  if (hasDangerousScheme(output, urls)) return 'DANGEROUS_SCHEME';
  if (hasExternalExfil(urls)) return 'EXTERNAL_EXFIL';
  return 'SAFE';
}

function checkUrl(output) {
  const urls = [output.trim()];
  if (hasDangerousScheme(output, urls)) return 'DANGEROUS_SCHEME';
  if (hasExternalExfil(urls)) return 'EXTERNAL_EXFIL';
  return 'SAFE';
}

function checkSql(output) {
  return SQL_METACHAR_RE.test(output) ? 'SQL_METACHAR' : 'SAFE';
}

function checkShell(output) {
  return SHELL_METACHAR_RE.test(output) ? 'SHELL_METACHAR' : 'SAFE';
}

function checkChannel(channel, output) {
  switch (channel) {
    case 'html': return checkHtml(output);
    case 'markdown': return checkMarkdown(output);
    case 'url': return checkUrl(output);
    case 'sql': return checkSql(output);
    case 'shell': return checkShell(output);
    default: return 'SAFE';
  }
}

// ---------- route ----------

app.post('/sanitize-output', (req, res) => {
  const body = req.body;

  if (!validateSchema(body)) {
    return res.status(200).json({ safe: false, reason: 'INVALID_SCHEMA' });
  }

  const { channel, output } = body;

  const decoded = decodeOnce(output);
  if (decoded !== output) {
    const decodedReason = checkChannel(channel, decoded);
    if (decodedReason !== 'SAFE') {
      return res.status(200).json({ safe: false, reason: 'ENCODED_PAYLOAD' });
    }
  }

  const reason = checkChannel(channel, output);
  return res.status(200).json({ safe: reason === 'SAFE', reason });
});

app.use((err, req, res, next) => {
  if (err && err.type === 'entity.parse.failed') {
    return res.status(200).json({ safe: false, reason: 'INVALID_SCHEMA' });
  }
  return res.status(200).json({ safe: false, reason: 'INVALID_SCHEMA' });
});

app.get('/healthz', (req, res) => res.status(200).send('ok'));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`output-sanitizer listening on port ${PORT}`);
});
