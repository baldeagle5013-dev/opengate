const express  = require('express');
const fetch    = require('node-fetch');
const cheerio  = require('cheerio');
const fs       = require('fs');
const path     = require('path');
const https    = require('https');
const http     = require('http');
const crypto   = require('crypto');

const app  = express();
const PORT = process.env.PORT || 3000;

// ── Config ────────────────────────────────────────────────────────────────────
const APP_PASSWORD  = process.env.APP_PASSWORD  || 'changeme123';
const EDIT_PASSWORD = process.env.EDIT_PASSWORD || 'editpass123';
const SECRET_KEY    = process.env.SECRET_KEY    || 'opensesame';
const HMAC_KEY      = process.env.HMAC_KEY      || 'default-hmac-key-change-me';
const DATA_FILE     = path.join(__dirname, 'data.json');

// ── Data helpers ──────────────────────────────────────────────────────────────
function loadData() {
  if (!fs.existsSync(DATA_FILE)) {
    const d = {
      sites: [
        { id:1, name:'Wikipedia',    url:'https://en.wikipedia.org',    icon:'📚', tags:['school'], compat:false },
        { id:2, name:'Khan Academy', url:'https://www.khanacademy.org', icon:'🎓', tags:['school'], compat:false },
        { id:3, name:'GitHub',       url:'https://github.com',          icon:'🐙', tags:['dev'],    compat:false },
        { id:4, name:'Reddit',       url:'https://www.reddit.com',      icon:'🤖', tags:['social'], compat:false },
      ],
      history:   {},   // keyed by userId
      cookieJar: {},   // keyed by userId -> domain -> cookieString
      guestTokens: {}, // token -> { expiresAt }
    };
    fs.writeFileSync(DATA_FILE, JSON.stringify(d, null, 2));
    return d;
  }
  try { return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8')); }
  catch { return { sites:[], history:{}, cookieJar:{}, guestTokens:{} }; }
}

function saveData(d) { fs.writeFileSync(DATA_FILE, JSON.stringify(d, null, 2)); }

// ── Auth helpers ──────────────────────────────────────────────────────────────
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

function isAuth(req) {
  const cookies = parseCookies(req);
  // Full auth
  if (cookies.auth === makeToken()) return 'full';
  // Guest token (from cookie or query param)
  const gt = cookies.guestToken || req.query.guestToken;
  if (gt) {
    const data = loadData();
    const token = data.guestTokens?.[gt];
    if (token && token.expiresAt > Date.now()) return 'guest';
  }
  return false;
}

function requireAuth(req, res, next) {
  const auth = isAuth(req);
  if (auth) { req.authLevel = auth; return next(); }
  if (req.path.startsWith('/api/')) return res.status(401).json({ error: 'Unauthorized' });
  res.redirect('/login');
}

function requireEditAuth(req, res, next) {
  if (req.authLevel === 'guest') return res.status(403).json({ error: 'Guests cannot edit sites' });
  const pw = req.headers['x-edit-password'];
  if (pw === EDIT_PASSWORD) return next();
  res.status(403).json({ error: 'Edit password required' });
}

// ── User ID ───────────────────────────────────────────────────────────────────
function getUserId(req, res) {
  const cookies = parseCookies(req);
  if (cookies.uid) return cookies.uid;
  const uid = crypto.randomBytes(12).toString('hex');
  res.setHeader('Set-Cookie', `uid=${uid}; Path=/; HttpOnly; SameSite=Strict; Max-Age=31536000`);
  return uid;
}

app.use(express.json());

// ── Public routes ─────────────────────────────────────────────────────────────
app.get('/', (req, res) => {
  // Secret key URL → set auth cookie, go to dashboard
  if (req.query.key === SECRET_KEY) {
    res.setHeader('Set-Cookie', `auth=${makeToken()}; Path=/; HttpOnly; SameSite=Strict; Max-Age=604800`);
    return res.redirect('/dashboard');
  }
  // Guest token URL → set guest cookie, go to dashboard
  if (req.query.guestToken) {
    const data = loadData();
    const token = data.guestTokens?.[req.query.guestToken];
    if (token && token.expiresAt > Date.now()) {
      res.setHeader('Set-Cookie', `guestToken=${req.query.guestToken}; Path=/; HttpOnly; SameSite=Strict; Max-Age=3600`);
      return res.redirect('/dashboard');
    }
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
  res.setHeader('Set-Cookie', [
    'auth=; Path=/; Max-Age=0',
    'guestToken=; Path=/; Max-Age=0',
  ]);
  res.redirect('/');
});

// ── Protected: dashboard ──────────────────────────────────────────────────────
app.get('/dashboard', requireAuth, (req, res) => {
  getUserId(req, res); // ensure uid cookie is set
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ── Sites API (read: all authed users; write: edit password required) ─────────
app.get('/api/sites', requireAuth, (req, res) => {
  res.json(loadData().sites);
});

app.post('/api/sites', requireAuth, requireEditAuth, (req, res) => {
  const { name, url, icon, tags, compat } = req.body;
  if (!name || !url) return res.status(400).json({ error: 'Name and URL required' });
  const data = loadData();
  const s = {
    id: Date.now(),
    name: name.trim(),
    url: url.startsWith('http') ? url.trim() : 'https://' + url.trim(),
    icon: icon || '🌐',
    tags: Array.isArray(tags) ? tags : (tags || '').split(',').map(t => t.trim()).filter(Boolean),
    compat: !!compat,
  };
  data.sites.push(s);
  saveData(data);
  res.json(s);
});

app.put('/api/sites/:id', requireAuth, requireEditAuth, (req, res) => {
  const data = loadData();
  const idx = data.sites.findIndex(s => s.id === parseInt(req.params.id));
  if (idx === -1) return res.status(404).json({ error: 'Not found' });
  const { name, url, icon, tags, compat } = req.body;
  data.sites[idx] = {
    ...data.sites[idx],
    ...(name  !== undefined && { name: name.trim() }),
    ...(url   !== undefined && { url: url.startsWith('http') ? url.trim() : 'https://' + url.trim() }),
    ...(icon  !== undefined && { icon }),
    ...(tags  !== undefined && { tags: Array.isArray(tags) ? tags : tags.split(',').map(t => t.trim()).filter(Boolean) }),
    ...(compat !== undefined && { compat: !!compat }),
  };
  saveData(data);
  res.json(data.sites[idx]);
});

app.delete('/api/sites/:id', requireAuth, requireEditAuth, (req, res) => {
  const data = loadData();
  data.sites = data.sites.filter(s => s.id !== parseInt(req.params.id));
  saveData(data);
  res.json({ ok: true });
});

app.post('/api/reorder', requireAuth, requireEditAuth, (req, res) => {
  const { ids } = req.body;
  const data = loadData();
  const map  = Object.fromEntries(data.sites.map(s => [s.id, s]));
  data.sites  = ids.map(id => map[id]).filter(Boolean);
  saveData(data);
  res.json({ ok: true });
});

// ── History API (per user) ────────────────────────────────────────────────────
app.get('/api/history', requireAuth, (req, res) => {
  const uid  = parseCookies(req).uid || 'default';
  const data = loadData();
  res.json((data.history || {})[uid] || []);
});

app.post('/api/history', requireAuth, (req, res) => {
  const uid  = parseCookies(req).uid || 'default';
  const { name, url, icon } = req.body;
  const data = loadData();
  if (!data.history) data.history = {};
  if (!data.history[uid]) data.history[uid] = [];
  data.history[uid] = data.history[uid].filter(h => h.url !== url);
  data.history[uid].unshift({ name, url, icon: icon || '🌐', visitedAt: Date.now() });
  data.history[uid] = data.history[uid].slice(0, 20);
  saveData(data);
  res.json({ ok: true });
});

app.delete('/api/history', requireAuth, (req, res) => {
  const uid  = parseCookies(req).uid || 'default';
  const data = loadData();
  if (data.history) data.history[uid] = [];
  saveData(data);
  res.json({ ok: true });
});

// ── Guest links ───────────────────────────────────────────────────────────────
app.post('/api/guest-link', requireAuth, (req, res) => {
  if (req.authLevel !== 'full') return res.status(403).json({ error: 'Full auth required' });
  const minutes = parseInt(req.body.minutes) || 15;
  const token   = crypto.randomBytes(20).toString('hex');
  const data    = loadData();
  if (!data.guestTokens) data.guestTokens = {};
  // Clean expired tokens
  for (const [k, v] of Object.entries(data.guestTokens)) {
    if (v.expiresAt <= Date.now()) delete data.guestTokens[k];
  }
  data.guestTokens[token] = { expiresAt: Date.now() + minutes * 60 * 1000, minutes };
  saveData(data);
  const url = `${req.protocol}://${req.get('host')}/?guestToken=${token}`;
  res.json({ token, url, expiresIn: minutes });
});

// ── Auth info (for frontend to know guest vs full) ────────────────────────────
app.get('/api/me', requireAuth, (req, res) => {
  res.json({ level: req.authLevel });
});

// ── Proxy helpers ─────────────────────────────────────────────────────────────
function resolveUrl(base, relative) {
  try { return new URL(relative, base).href; } catch { return relative; }
}

function wrapUrl(url, baseUrl) {
  try {
    const resolved = resolveUrl(baseUrl, url);
    if (resolved.startsWith('http')) return '/proxy?url=' + encodeURIComponent(resolved);
  } catch {}
  return url;
}

// Script injected into every proxied HTML page
function buildInjectedScript() {
  return `
<script>
(function(){
  // ── BroadcastChannel: receive PANIC from any tab ──
  try {
    var bc = new BroadcastChannel('opengate');
    bc.onmessage = function(e){
      if(e.data==='PANIC') window.top.location.href='/';
    };
  } catch(e){}

  // ── Panic key on proxied page ──
  document.addEventListener('keydown', function(e){
    if(e.key==='p'||e.key==='P'){
      try{ new BroadcastChannel('opengate').postMessage('PANIC'); }catch(e){}
      window.top.location.href='/';
    }
  });

  // ── Idle redirect ──
  var idleMs = parseInt(
    (function(){ try{ return window.top.localStorage.getItem('idleTimeout'); }catch(e){return localStorage.getItem('idleTimeout');} })()
  );
  if(idleMs && idleMs > 0){
    var idleTimer;
    function resetIdle(){
      clearTimeout(idleTimer);
      idleTimer = setTimeout(function(){
        try{ new BroadcastChannel('opengate').postMessage('PANIC'); }catch(e){}
        window.top.location.href='/';
      }, idleMs);
    }
    ['mousemove','keydown','mousedown','touchstart','scroll'].forEach(function(ev){
      document.addEventListener(ev, resetIdle, {passive:true});
    });
    resetIdle();
  }
})();
</script>`;
}

function rewriteHtml(html, baseUrl, noJs) {
  const $ = cheerio.load(html, { decodeEntities: false });

  if (noJs) {
    $('script').remove();
    $('[onload],[onclick],[onerror],[onmouseover]').each((_, el) => {
      ['onload','onclick','onerror','onmouseover','onmouseout','onfocus','onblur'].forEach(attr => $(el).removeAttr(attr));
    });
  }

  $('a[href]').each((_, el) => {
    const h = $(el).attr('href');
    if (h && !h.startsWith('#') && !h.startsWith('javascript:') && !h.startsWith('mailto:'))
      $(el).attr('href', wrapUrl(h, baseUrl));
  });
  $('script[src]').each((_, el)   => $(el).attr('src',  wrapUrl($(el).attr('src'),  baseUrl)));
  $('link[rel="stylesheet"][href]').each((_, el) => $(el).attr('href', wrapUrl($(el).attr('href'), baseUrl)));
  $('img[src]').each((_, el)  => $(el).attr('src',  wrapUrl($(el).attr('src'),  baseUrl)));
  $('img[srcset]').each((_, el) => {
    $(el).attr('srcset', $(el).attr('srcset').split(',').map(s => {
      const p = s.trim().split(/\s+/);
      if (p[0]) p[0] = wrapUrl(p[0], baseUrl);
      return p.join(' ');
    }).join(', '));
  });
  $('form[action]').each((_, el) => $(el).attr('action', wrapUrl($(el).attr('action'), baseUrl)));
  $('iframe[src]').each((_, el)  => $(el).attr('src',  wrapUrl($(el).attr('src'),  baseUrl)));

  // Proxy bar — note target="_top" on back link so it works inside iframes
  const compatIcon = noJs ? ' <span style="color:#ffa500;font-size:10px">⚡ COMPAT</span>' : '';
  $('body').prepend(`
    <div id="__og_bar__" style="position:fixed;top:0;left:0;right:0;z-index:2147483647;
      background:#0d0d0d;color:#39ff14;font-family:monospace;font-size:12px;
      padding:5px 14px;display:flex;align-items:center;justify-content:space-between;
      border-bottom:1px solid #39ff1444;gap:12px;">
      <a href="/dashboard" target="_top" style="color:#39ff14;text-decoration:none;font-weight:bold;flex-shrink:0">← Dashboard</a>
      <span style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:#fff;font-size:11px">${baseUrl}${compatIcon}</span>
      <button onclick="document.getElementById('__og_bar__').style.display='none'"
        style="background:none;border:none;color:#4a6070;cursor:pointer;font-size:14px;flex-shrink:0">✕</button>
    </div>
    <div style="height:34px"></div>
    ${buildInjectedScript()}
  `);

  return $.html();
}

function rewriteCss(css, baseUrl) {
  return css.replace(/url\(['"]?([^'")]+)['"]?\)/g, (m, u) =>
    u.startsWith('data:') ? m : `url('${wrapUrl(u, baseUrl)}')`
  );
}

// ── Cookie jar helpers ────────────────────────────────────────────────────────
function getCookiesForDomain(data, uid, domain) {
  return (data.cookieJar?.[uid]?.[domain]) || '';
}

function storeCookies(data, uid, domain, setCookieHeaders) {
  if (!setCookieHeaders || !setCookieHeaders.length) return;
  if (!data.cookieJar)       data.cookieJar = {};
  if (!data.cookieJar[uid])  data.cookieJar[uid] = {};
  const existing = {};
  (data.cookieJar[uid][domain] || '').split(';').forEach(p => {
    const [k, ...v] = p.trim().split('=');
    if (k) existing[k.trim()] = v.join('=').trim();
  });
  setCookieHeaders.forEach(header => {
    const part = header.split(';')[0].trim();
    const [k, ...v] = part.split('=');
    if (k) existing[k.trim()] = v.join('=').trim();
  });
  data.cookieJar[uid][domain] = Object.entries(existing).map(([k,v]) => `${k}=${v}`).join('; ');
}

// ── Proxy route ───────────────────────────────────────────────────────────────
app.get('/proxy', requireAuth, async (req, res) => {
  const targetUrl = req.query.url;
  const noJs      = req.query.nojs === '1';

  if (!targetUrl) return res.status(400).send('Missing ?url=');
  let parsed;
  try { parsed = new URL(targetUrl); } catch { return res.status(400).send('Invalid URL'); }

  const uid    = parseCookies(req).uid || 'default';
  const data   = loadData();
  const domain = parsed.hostname;
  const stored = getCookiesForDomain(data, uid, domain);

  try {
    const agent = parsed.protocol === 'https:'
      ? new https.Agent({ rejectUnauthorized: false }) : new http.Agent();

    const response = await fetch(targetUrl, {
      headers: {
        'User-Agent':       'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120 Safari/537.36',
        'Accept':           'text/html,application/xhtml+xml,*/*;q=0.8',
        'Accept-Language':  'en-US,en;q=0.9',
        'Accept-Encoding':  'identity',
        'Referer':          parsed.origin,
        ...(stored && { 'Cookie': stored }),
      },
      redirect: 'follow',
      agent,
    });

    // Store returned cookies
    const rawHeaders = response.headers.raw ? response.headers.raw() : {};
    const setCookies = rawHeaders['set-cookie'] || [];
    if (setCookies.length) { storeCookies(data, uid, domain, setCookies); saveData(data); }

    const ct   = response.headers.get('content-type') || '';
    const skip = ['content-security-policy','x-frame-options','strict-transport-security','content-encoding','set-cookie'];
    for (const [k, v] of response.headers.entries())
      if (!skip.includes(k.toLowerCase())) try { res.setHeader(k, v); } catch {}
    res.setHeader('content-type', ct);

    const finalUrl = response.url || targetUrl;

    if (ct.includes('text/html')) {
      res.send(rewriteHtml(await response.text(), finalUrl, noJs));
    } else if (ct.includes('text/css')) {
      res.send(rewriteCss(await response.text(), finalUrl));
    } else {
      response.body.pipe(res);
    }
  } catch (err) {
    const isBlock = err.message.includes('ECONNREFUSED') || err.message.includes('certificate') || err.message.includes('getaddrinfo');
    const reason  = isBlock
      ? 'The site refused the connection. It may actively block proxies, or the URL is wrong.'
      : err.message;
    const suggestions = [
      'Try enabling <b>Compat Mode</b> on the site card (strips JavaScript)',
      'Some sites (Google, Cloudflare-protected) actively detect proxies',
      'Check the URL is correct and the site is actually reachable',
      'Try opening in a new tab instead of the frame panel',
    ];
    res.status(502).send(`
      <!DOCTYPE html><html><head>
        <title>Proxy Error — OpenGate</title>
        <style>
          body{background:#080c10;color:#c8d8e8;font-family:monospace;padding:48px 32px;max-width:600px;margin:0 auto}
          h2{color:#ff3b5c;font-size:22px;margin-bottom:8px}
          .url{color:#39ff14;font-size:13px;margin-bottom:24px;word-break:break-all}
          .reason{background:#0e1419;border:1px solid #2a1f1f;border-left:3px solid #ff3b5c;padding:16px;border-radius:6px;margin-bottom:24px;font-size:13px;color:#e8c0c0;line-height:1.6}
          h4{color:#00d4ff;margin-bottom:12px;font-size:13px;letter-spacing:.1em;text-transform:uppercase}
          ul{padding-left:20px;line-height:2;font-size:13px;color:#8aa0b0}
          a{color:#39ff14;text-decoration:none;display:inline-block;margin-top:24px;border:1px solid #39ff1444;padding:8px 20px;border-radius:6px}
          a:hover{background:#39ff1415}
        </style>
      </head><body>
        <h2>⚠ Proxy Error</h2>
        <div class="url">${targetUrl}</div>
        <div class="reason">${reason}</div>
        <h4>Suggestions</h4>
        <ul>${suggestions.map(s => `<li>${s}</li>`).join('')}</ul>
        <a href="/dashboard" target="_top">← Back to Dashboard</a>
      </body></html>
    `);
  }
});

// ── Start ─────────────────────────────────────────────────────────────────────
app.listen(PORT, '0.0.0.0', () => {
  console.log(`\n⚡ OpenGate → http://0.0.0.0:${PORT}`);
  console.log(`   Direct access:  /?key=${SECRET_KEY}`);
  console.log(`   Login page:     /login\n`);
});
