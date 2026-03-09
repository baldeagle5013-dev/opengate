const express = require('express');
const fetch = require('node-fetch');
const cheerio = require('cheerio');
const fs = require('fs');
const path = require('path');
const https = require('https');
const http = require('http');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// ── Config ─────────────────────────────────────────────────────────────────────
const APP_PASSWORD = process.env.APP_PASSWORD || 'changeme123';
const SECRET_KEY   = process.env.SECRET_KEY   || 'opensesame';
const HMAC_KEY     = process.env.HMAC_KEY     || 'default-hmac-key-please-change';
const DATA_FILE    = path.join(__dirname, 'data.json');

// ── Data ───────────────────────────────────────────────────────────────────────
function loadData() {
  if (!fs.existsSync(DATA_FILE)) {
    const defaults = {
      sites: [
        { id: 1, name: 'Wikipedia',    url: 'https://en.wikipedia.org',      icon: '📚', tags: ['school'] },
        { id: 2, name: 'Khan Academy', url: 'https://www.khanacademy.org',   icon: '🎓', tags: ['school'] },
        { id: 3, name: 'GitHub',       url: 'https://github.com',            icon: '🐙', tags: ['dev'] },
        { id: 4, name: 'Reddit',       url: 'https://www.reddit.com',        icon: '🤖', tags: ['social'] },
        { id: 5, name: 'YouTube',      url: 'https://www.youtube.com',       icon: '▶️', tags: ['social'] },
      ],
      history: [],
    };
    fs.writeFileSync(DATA_FILE, JSON.stringify(defaults, null, 2));
    return defaults;
  }
  try { return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8')); }
  catch { return { sites: [], history: [] }; }
}

function saveData(data) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2));
}

// ── Auth ───────────────────────────────────────────────────────────────────────
function makeToken() {
  return crypto.createHmac('sha256', HMAC_KEY).update(APP_PASSWORD).digest('hex');
}

function parseCookies(req) {
  return Object.fromEntries(
    (req.headers.cookie || '').split(';').map(p => {
      const [k, ...v] = p.trim().split('=');
      return [k.trim(), decodeURIComponent(v.join('=').trim())];
    }).filter(([k]) => k)
  );
}

function isAuth(req) { return parseCookies(req).auth === makeToken(); }

function requireAuth(req, res, next) {
  if (isAuth(req)) return next();
  if (req.path.startsWith('/api/')) return res.status(401).json({ error: 'Unauthorized' });
  res.redirect('/');
}

app.use(express.json());

// ── Public routes ──────────────────────────────────────────────────────────────
app.get('/', (req, res) => {
  if (req.query.key === SECRET_KEY) {
    res.setHeader('Set-Cookie', `auth=${makeToken()}; Path=/; HttpOnly; SameSite=Strict; Max-Age=604800`);
    return res.redirect('/dashboard');
  }
  if (isAuth(req)) return res.redirect('/dashboard');
  res.sendFile(path.join(__dirname, 'public', 'decoy.html'));
});

app.get('/login', (req, res) => {
  if (isAuth(req)) return res.redirect('/dashboard');
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.post('/api/login', (req, res) => {
  if (req.body.password === APP_PASSWORD) {
    res.setHeader('Set-Cookie', `auth=${makeToken()}; Path=/; HttpOnly; SameSite=Strict; Max-Age=604800`);
    return res.json({ ok: true });
  }
  res.status(401).json({ error: 'Wrong password' });
});

app.get('/logout', (req, res) => {
  res.setHeader('Set-Cookie', 'auth=; Path=/; Max-Age=0');
  res.redirect('/');
});

// ── Protected routes ───────────────────────────────────────────────────────────
app.get('/dashboard', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Sites
app.get('/api/sites', requireAuth, (req, res) => res.json(loadData().sites));

app.post('/api/sites', requireAuth, (req, res) => {
  const { name, url, icon, tags } = req.body;
  if (!name || !url) return res.status(400).json({ error: 'Name and URL required' });
  const data = loadData();
  const newSite = {
    id: Date.now(),
    name: name.trim(),
    url: url.startsWith('http') ? url.trim() : 'https://' + url.trim(),
    icon: icon || '🌐',
    tags: Array.isArray(tags) ? tags : (tags ? tags.split(',').map(t => t.trim()).filter(Boolean) : []),
  };
  data.sites.push(newSite);
  saveData(data);
  res.json(newSite);
});

app.put('/api/sites/:id', requireAuth, (req, res) => {
  const data = loadData();
  const idx = data.sites.findIndex(s => s.id === parseInt(req.params.id));
  if (idx === -1) return res.status(404).json({ error: 'Not found' });
  const { name, url, icon, tags } = req.body;
  data.sites[idx] = {
    ...data.sites[idx],
    ...(name !== undefined && { name: name.trim() }),
    ...(url !== undefined && { url: url.startsWith('http') ? url.trim() : 'https://' + url.trim() }),
    ...(icon !== undefined && { icon }),
    ...(tags !== undefined && { tags: Array.isArray(tags) ? tags : tags.split(',').map(t => t.trim()).filter(Boolean) }),
  };
  saveData(data);
  res.json(data.sites[idx]);
});

app.delete('/api/sites/:id', requireAuth, (req, res) => {
  const data = loadData();
  data.sites = data.sites.filter(s => s.id !== parseInt(req.params.id));
  saveData(data);
  res.json({ ok: true });
});

app.post('/api/reorder', requireAuth, (req, res) => {
  const { ids } = req.body;
  const data = loadData();
  const map = Object.fromEntries(data.sites.map(s => [s.id, s]));
  data.sites = ids.map(id => map[id]).filter(Boolean);
  saveData(data);
  res.json({ ok: true });
});

// History
app.get('/api/history',  requireAuth, (req, res) => res.json(loadData().history || []));

app.post('/api/history', requireAuth, (req, res) => {
  const { name, url, icon } = req.body;
  const data = loadData();
  if (!data.history) data.history = [];
  data.history = data.history.filter(h => h.url !== url);
  data.history.unshift({ name, url, icon: icon || '🌐', visitedAt: Date.now() });
  data.history = data.history.slice(0, 20);
  saveData(data);
  res.json({ ok: true });
});

app.delete('/api/history', requireAuth, (req, res) => {
  const data = loadData();
  data.history = [];
  saveData(data);
  res.json({ ok: true });
});

// ── Proxy helpers ──────────────────────────────────────────────────────────────
function resolveUrl(base, relative) {
  try { return new URL(relative, base).href; } catch { return relative; }
}

function wrapUrl(url, baseUrl) {
  try {
    const resolved = resolveUrl(baseUrl, url);
    if (resolved.startsWith('http://') || resolved.startsWith('https://')) {
      return '/proxy?url=' + encodeURIComponent(resolved);
    }
  } catch {}
  return url;
}

function rewriteHtml(html, baseUrl) {
  const $ = cheerio.load(html, { decodeEntities: false });
  $('a[href]').each((_, el) => {
    const href = $(el).attr('href');
    if (href && !href.startsWith('#') && !href.startsWith('javascript:') && !href.startsWith('mailto:'))
      $(el).attr('href', wrapUrl(href, baseUrl));
  });
  $('script[src]').each((_, el) => $(el).attr('src', wrapUrl($(el).attr('src'), baseUrl)));
  $('link[rel="stylesheet"][href]').each((_, el) => $(el).attr('href', wrapUrl($(el).attr('href'), baseUrl)));
  $('img[src]').each((_, el) => $(el).attr('src', wrapUrl($(el).attr('src'), baseUrl)));
  $('img[srcset]').each((_, el) => {
    $(el).attr('srcset', $(el).attr('srcset').split(',').map(s => {
      const parts = s.trim().split(/\s+/);
      if (parts[0]) parts[0] = wrapUrl(parts[0], baseUrl);
      return parts.join(' ');
    }).join(', '));
  });
  $('form[action]').each((_, el) => $(el).attr('action', wrapUrl($(el).attr('action'), baseUrl)));
  $('iframe[src]').each((_, el) => $(el).attr('src', wrapUrl($(el).attr('src'), baseUrl)));
  $('body').prepend(`
    <div style="position:fixed;top:0;left:0;right:0;z-index:2147483647;
      background:#0d0d0d;color:#39ff14;font-family:monospace;font-size:12px;
      padding:5px 14px;display:flex;align-items:center;justify-content:space-between;
      border-bottom:1px solid #39ff1444;">
      <span>⚡ PROXIED: <b style="color:#fff">${baseUrl}</b></span>
      <a href="/dashboard" style="color:#39ff14;text-decoration:none;font-weight:bold;">← Dashboard</a>
    </div><div style="height:32px"></div>`);
  return $.html();
}

function rewriteCss(css, baseUrl) {
  return css.replace(/url\(['"]?([^'")]+)['"]?\)/g, (m, u) =>
    u.startsWith('data:') ? m : `url('${wrapUrl(u, baseUrl)}')`
  );
}

app.get('/proxy', requireAuth, async (req, res) => {
  const targetUrl = req.query.url;
  if (!targetUrl) return res.status(400).send('Missing ?url=');
  let parsedUrl;
  try { parsedUrl = new URL(targetUrl); } catch { return res.status(400).send('Invalid URL'); }
  try {
    const agent = parsedUrl.protocol === 'https:'
      ? new https.Agent({ rejectUnauthorized: false }) : new http.Agent();
    const response = await fetch(targetUrl, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'identity',
        'Referer': parsedUrl.origin,
      },
      redirect: 'follow', agent,
    });
    const ct = response.headers.get('content-type') || '';
    const skip = ['content-security-policy','x-frame-options','strict-transport-security','content-encoding'];
    for (const [k, v] of response.headers.entries())
      if (!skip.includes(k.toLowerCase())) try { res.setHeader(k, v); } catch {}
    res.setHeader('content-type', ct);
    if (ct.includes('text/html'))      res.send(rewriteHtml(await response.text(), response.url || targetUrl));
    else if (ct.includes('text/css'))  res.send(rewriteCss(await response.text(), response.url || targetUrl));
    else                               response.body.pipe(res);
  } catch (err) {
    res.status(502).send(`<html><body style="background:#0d0d0d;color:#ff4444;font-family:monospace;padding:40px">
      <h2>⚠ Proxy Error</h2><p>${err.message}</p>
      <p><a href="/dashboard" style="color:#39ff14">← Dashboard</a></p></body></html>`);
  }
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`\n⚡ OpenGate running → http://0.0.0.0:${PORT}`);
  console.log(`   Quick access: /?key=${SECRET_KEY}`);
  console.log(`   Login page:   /login\n`);
});
