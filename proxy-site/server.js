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
        { id:1, name:'Wikipedia',    url:'https://en.wikipedia.org',    icon:'📚', tags:['school'], compat:false, desc:'' },
        { id:2, name:'Khan Academy', url:'https://www.khanacademy.org', icon:'🎓', tags:['school'], compat:false, desc:'' },
        { id:3, name:'GitHub',       url:'https://github.com',          icon:'🐙', tags:['dev'],    compat:false, desc:'' },
        { id:4, name:'Reddit',       url:'https://www.reddit.com',      icon:'🤖', tags:['social'], compat:false, desc:'' },
      ],
      history:     {},
      cookieJar:   {},
      guestTokens: {},
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
      const [k,...v] = p.trim().split('=');
      return [k.trim(), decodeURIComponent(v.join('=').trim())];
    }).filter(([k]) => k)
  );
}
function isAuth(req) {
  const c = parseCookies(req);
  if (c.auth === makeToken()) return 'full';
  const gt = c.guestToken || req.query.guestToken;
  if (gt) {
    const token = loadData().guestTokens?.[gt];
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
  if (req.authLevel === 'guest') return res.status(403).json({ error: 'Guests cannot edit' });
  if (req.headers['x-edit-password'] === EDIT_PASSWORD) return next();
  res.status(403).json({ error: 'Edit password required' });
}
function getUserId(req, res) {
  const c = parseCookies(req);
  if (c.uid) return c.uid;
  const uid = crypto.randomBytes(12).toString('hex');
  res.setHeader('Set-Cookie', `uid=${uid}; Path=/; HttpOnly; SameSite=Strict; Max-Age=31536000`);
  return uid;
}

app.use(express.json());

// ── Public routes ─────────────────────────────────────────────────────────────
app.get('/', (req, res) => {
  if (req.query.key === SECRET_KEY) {
    res.setHeader('Set-Cookie', `auth=${makeToken()}; Path=/; HttpOnly; SameSite=Strict; Max-Age=604800`);
    return res.redirect('/dashboard');
  }
  if (req.query.guestToken) {
    const token = loadData().guestTokens?.[req.query.guestToken];
    if (token && token.expiresAt > Date.now()) {
      res.setHeader('Set-Cookie', `guestToken=${req.query.guestToken}; Path=/; HttpOnly; SameSite=Strict; Max-Age=3600`);
      return res.redirect('/dashboard');
    }
  }
  if (isAuth(req)) return res.redirect('/dashboard');
  res.sendFile(path.join(__dirname, 'public', 'decoy.html'));
});
app.get('/decoy', (req, res) => res.sendFile(path.join(__dirname, 'public', 'decoy.html')));
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
  res.setHeader('Set-Cookie', ['auth=; Path=/; Max-Age=0', 'guestToken=; Path=/; Max-Age=0']);
  res.redirect('/');
});

// ── Dashboard ─────────────────────────────────────────────────────────────────
app.get('/dashboard', requireAuth, (req, res) => {
  getUserId(req, res);
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ── Meta fetch (for auto description) ────────────────────────────────────────
app.get('/api/fetch-meta', requireAuth, async (req, res) => {
  const targetUrl = req.query.url;
  if (!targetUrl) return res.json({ desc: '', title: '' });
  try {
    const agent = targetUrl.startsWith('https')
      ? new https.Agent({ rejectUnauthorized: false }) : new http.Agent();
    const r = await fetch(targetUrl, {
      headers: { 'User-Agent': 'Mozilla/5.0', 'Accept': 'text/html' },
      redirect: 'follow', agent,
      timeout: 5000,
    });
    const html = await r.text();
    const $ = cheerio.load(html);
    const desc =
      $('meta[name="description"]').attr('content') ||
      $('meta[property="og:description"]').attr('content') ||
      $('meta[name="twitter:description"]').attr('content') || '';
    const title =
      $('meta[property="og:title"]').attr('content') ||
      $('title').text() || '';
    res.json({ desc: desc.trim().slice(0, 200), title: title.trim().slice(0, 80) });
  } catch { res.json({ desc: '', title: '' }); }
});

// ── Sites API ─────────────────────────────────────────────────────────────────
app.get('/api/sites', requireAuth, (req, res) => res.json(loadData().sites));

app.post('/api/sites', requireAuth, requireEditAuth, (req, res) => {
  const { name, url, icon, tags, compat, desc } = req.body;
  if (!name || !url) return res.status(400).json({ error: 'Name and URL required' });
  const data = loadData();
  const s = {
    id: Date.now(),
    name: name.trim(),
    url: url.startsWith('http') ? url.trim() : 'https://' + url.trim(),
    icon: icon || '🌐',
    tags: Array.isArray(tags) ? tags : (tags||'').split(',').map(t=>t.trim()).filter(Boolean),
    compat: !!compat,
    desc: (desc||'').trim().slice(0,200),
  };
  data.sites.push(s);
  saveData(data);
  res.json(s);
});

app.put('/api/sites/:id', requireAuth, requireEditAuth, (req, res) => {
  const data = loadData();
  const idx  = data.sites.findIndex(s => s.id === parseInt(req.params.id));
  if (idx === -1) return res.status(404).json({ error: 'Not found' });
  const { name, url, icon, tags, compat, desc } = req.body;
  data.sites[idx] = {
    ...data.sites[idx],
    ...(name  !== undefined && { name: name.trim() }),
    ...(url   !== undefined && { url: url.startsWith('http') ? url.trim() : 'https://'+url.trim() }),
    ...(icon  !== undefined && { icon }),
    ...(tags  !== undefined && { tags: Array.isArray(tags) ? tags : tags.split(',').map(t=>t.trim()).filter(Boolean) }),
    ...(compat !== undefined && { compat: !!compat }),
    ...(desc  !== undefined && { desc: desc.trim().slice(0,200) }),
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
  const data = loadData();
  const map  = Object.fromEntries(data.sites.map(s=>[s.id,s]));
  data.sites  = req.body.ids.map(id=>map[id]).filter(Boolean);
  saveData(data);
  res.json({ ok: true });
});

// ── History API ───────────────────────────────────────────────────────────────
app.get('/api/history', requireAuth, (req, res) => {
  const uid = parseCookies(req).uid || 'default';
  res.json((loadData().history||{})[uid]||[]);
});
app.post('/api/history', requireAuth, (req, res) => {
  const uid = parseCookies(req).uid || 'default';
  const { name, url, icon } = req.body;
  const data = loadData();
  if (!data.history) data.history = {};
  if (!data.history[uid]) data.history[uid] = [];
  data.history[uid] = data.history[uid].filter(h=>h.url!==url);
  data.history[uid].unshift({ name, url, icon:icon||'🌐', visitedAt:Date.now() });
  data.history[uid] = data.history[uid].slice(0,20);
  saveData(data);
  res.json({ ok: true });
});
app.delete('/api/history', requireAuth, (req, res) => {
  const uid = parseCookies(req).uid || 'default';
  const data = loadData();
  if (data.history) data.history[uid] = [];
  saveData(data);
  res.json({ ok: true });
});

// ── Guest links ───────────────────────────────────────────────────────────────
app.post('/api/guest-link', requireAuth, requireEditAuth, (req, res) => {
  if (req.authLevel !== 'full') return res.status(403).json({ error: 'Full auth required' });
  const minutes = parseInt(req.body.minutes) || 15;
  const token   = crypto.randomBytes(20).toString('hex');
  const data    = loadData();
  if (!data.guestTokens) data.guestTokens = {};
  for (const [k,v] of Object.entries(data.guestTokens))
    if (v.expiresAt <= Date.now()) delete data.guestTokens[k];
  data.guestTokens[token] = { expiresAt: Date.now() + minutes*60*1000, minutes };
  saveData(data);
  res.json({ token, url:`${req.protocol}://${req.get('host')}/?guestToken=${token}`, expiresIn:minutes });
});

app.get('/api/me', requireAuth, (req, res) => res.json({ level: req.authLevel }));

// ── Ad-block selector list ────────────────────────────────────────────────────
const AD_SELECTORS = [
  'iframe[src*="doubleclick"]','iframe[src*="googlesyndication"]',
  'iframe[src*="adnxs"]','iframe[src*="adsrvr"]',
  'script[src*="googlesyndication"]','script[src*="doubleclick"]',
  'script[src*="adsbygoogle"]','script[src*="amazon-adsystem"]',
  '[id*="google_ads"]','[id*="carbonads"]',
  '[class*="adsbygoogle"]','[class*="banner-ad"]',
  '[class*="ad-banner"]','[class*="advertisement"]',
  '[class*="sponsored-content"]','[class*="sponsor-"]',
  '[data-ad]','[data-ad-unit]',
  'ins.adsbygoogle',
];

// ── Decoy school CSS (injected into proxied pages when school mode on) ────────
const SCHOOL_CSS = `
<style id="__og_school__">
  :root {
    --s-bg: #f0f4fa !important;
    --s-text: #1a2a4a !important;
    --s-accent: #2c5fa8 !important;
    --s-border: #c0d0e8 !important;
  }
  body { background: #f0f4fa !important; color: #1a2a4a !important; font-family: 'Segoe UI', Arial, sans-serif !important; }
  a { color: #2c5fa8 !important; }
  h1,h2,h3,h4 { color: #1a2a4a !important; }
  header, nav, .header, .nav, .navbar, .site-header, .top-bar {
    background: #2c5fa8 !important; color: #fff !important;
    border-bottom: 3px solid #1a3a78 !important;
  }
  header a, nav a, .header a, .nav a { color: #fff !important; }
  footer, .footer { background: #dce8f5 !important; color: #4a6a9a !important; }
  button, .btn, [role="button"] {
    background: #2c5fa8 !important; color: #fff !important;
    border: none !important; border-radius: 4px !important;
  }
  input, textarea, select {
    border: 1px solid #c0d0e8 !important;
    background: #fff !important; color: #1a2a4a !important;
  }
</style>
<div id="__og_school_bar__" style="position:fixed;top:34px;left:0;right:0;z-index:2147483646;
  background:#2c5fa8;color:#fff;font-family:Arial,sans-serif;font-size:12px;
  padding:4px 14px;display:flex;align-items:center;gap:10px;border-bottom:2px solid #1a3a78;
  box-shadow:0 1px 4px #0002">
  <span style="font-weight:bold;font-size:13px">🏫 Schulportal</span>
  <span style="opacity:.7">Lernmaterialien &amp; Ressourcen</span>
  <span style="margin-left:auto;opacity:.5;font-size:10px">Klasse 10 · Gymnasium</span>
</div>
<div style="height:28px"></div>`;

// ── Proxy helpers ─────────────────────────────────────────────────────────────
function resolveUrl(base, rel) {
  try { return new URL(rel, base).href; } catch { return rel; }
}
function wrapUrl(url, baseUrl) {
  try {
    const r = resolveUrl(baseUrl, url);
    if (r.startsWith('http')) return '/proxy?url='+encodeURIComponent(r);
  } catch {}
  return url;
}

function buildInjectedScript() {
  return `<script>
(function(){
  try {
    var bc=new BroadcastChannel('opengate');
    bc.onmessage=function(e){ if(e.data==='PANIC') window.top.location.href='/decoy'; };
  } catch(e){}
  document.addEventListener('keydown',function(e){
    if(e.key==='p'||e.key==='P'){
      try{ new BroadcastChannel('opengate').postMessage('PANIC'); }catch(e){}
      window.top.location.href='/decoy';
    }
  });
  var idleMs=parseInt((function(){ try{ return window.top.localStorage.getItem('idleTimeout'); }catch(e){ return localStorage.getItem('idleTimeout'); } })());
  if(idleMs&&idleMs>0){
    var t;
    function ri(){ clearTimeout(t); t=setTimeout(function(){ try{new BroadcastChannel('opengate').postMessage('PANIC');}catch(e){} window.top.location.href='/decoy'; },idleMs); }
    ['mousemove','keydown','mousedown','touchstart','scroll'].forEach(function(ev){ document.addEventListener(ev,ri,{passive:true}); });
    ri();
  }
})();
</script>`;
}

function rewriteHtml(html, baseUrl, opts) {
  const noJs   = opts.noJs   || false;
  const noAd   = opts.noAd   || false;
  const school  = opts.school || false;

  const $ = cheerio.load(html, { decodeEntities: false });

  // Strip scripts in compat mode
  if (noJs) {
    $('script').remove();
    $('[onload],[onclick],[onerror],[onmouseover],[onmouseout],[onfocus],[onblur]').each((_,el)=>{
      ['onload','onclick','onerror','onmouseover','onmouseout','onfocus','onblur'].forEach(a=>$(el).removeAttr(a));
    });
  }

  // Ad blocker
  if (noAd) {
    AD_SELECTORS.forEach(sel => { try { $(sel).remove(); } catch {} });
    // Also remove scripts whose src contains ad network keywords
    $('script[src]').each((_,el)=>{
      const src=$(el).attr('src')||'';
      if(/googlesyndication|doubleclick|adnxs|adsrvr|adservice|amazon-adsystem/i.test(src))
        $(el).remove();
    });
  }

  // Rewrite links
  $('a[href]').each((_,el)=>{ const h=$(el).attr('href'); if(h&&!h.startsWith('#')&&!h.startsWith('javascript:')&&!h.startsWith('mailto:')) $(el).attr('href',wrapUrl(h,baseUrl)); });
  $('script[src]').each((_,el)=>$(el).attr('src',wrapUrl($(el).attr('src'),baseUrl)));
  $('link[rel="stylesheet"][href]').each((_,el)=>$(el).attr('href',wrapUrl($(el).attr('href'),baseUrl)));
  $('img[src]').each((_,el)=>$(el).attr('src',wrapUrl($(el).attr('src'),baseUrl)));
  $('img[srcset]').each((_,el)=>{
    $(el).attr('srcset',$(el).attr('srcset').split(',').map(s=>{
      const p=s.trim().split(/\s+/); if(p[0])p[0]=wrapUrl(p[0],baseUrl); return p.join(' ');
    }).join(', '));
  });
  $('form[action]').each((_,el)=>$(el).attr('action',wrapUrl($(el).attr('action'),baseUrl)));
  $('iframe[src]').each((_,el)=>$(el).attr('src',wrapUrl($(el).attr('src'),baseUrl)));

  const badges = [
    noJs  ? '<span style="color:#ffa500;font-size:10px">⚡COMPAT</span>' : '',
    noAd  ? '<span style="color:#39ff14;font-size:10px">🛡AD-FREE</span>' : '',
    school? '<span style="color:#7bc8ff;font-size:10px">🏫SCHULM.</span>' : '',
  ].filter(Boolean).join(' ');

  $('body').prepend(`
    ${school ? SCHOOL_CSS : ''}
    <div id="__og_bar__" style="position:fixed;top:0;left:0;right:0;z-index:2147483647;
      background:#0d0d0d;color:#39ff14;font-family:monospace;font-size:12px;
      padding:5px 14px;display:flex;align-items:center;gap:10px;border-bottom:1px solid #39ff1444">
      <a href="/dashboard" target="_top" style="color:#39ff14;text-decoration:none;font-weight:bold;flex-shrink:0">← Dashboard</a>
      <span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:#aaa;font-size:10px">${baseUrl}</span>
      ${badges}
      <button onclick="document.getElementById('__og_bar__').style.display='none'" style="background:none;border:none;color:#4a6070;cursor:pointer;font-size:14px;flex-shrink:0">✕</button>
    </div>
    <div style="height:34px"></div>
    ${buildInjectedScript()}
  `);

  return $.html();
}

function rewriteCss(css, baseUrl) {
  return css.replace(/url\(['"]?([^'")]+)['"]?\)/g,(m,u)=>u.startsWith('data:')?m:`url('${wrapUrl(u,baseUrl)}')`);
}

// ── Cookie jar ────────────────────────────────────────────────────────────────
function getCookiesForDomain(data, uid, domain) {
  return (data.cookieJar?.[uid]?.[domain])||'';
}
function storeCookies(data, uid, domain, setCookieHeaders) {
  if (!setCookieHeaders?.length) return;
  if (!data.cookieJar) data.cookieJar={};
  if (!data.cookieJar[uid]) data.cookieJar[uid]={};
  const ex={};
  (data.cookieJar[uid][domain]||'').split(';').forEach(p=>{
    const[k,...v]=p.trim().split('='); if(k)ex[k.trim()]=v.join('=').trim();
  });
  setCookieHeaders.forEach(h=>{
    const part=h.split(';')[0].trim();
    const[k,...v]=part.split('='); if(k)ex[k.trim()]=v.join('=').trim();
  });
  data.cookieJar[uid][domain]=Object.entries(ex).map(([k,v])=>`${k}=${v}`).join('; ');
}

// ── Proxy route ───────────────────────────────────────────────────────────────
app.get('/proxy', requireAuth, async (req, res) => {
  const targetUrl = req.query.url;
  const noJs   = req.query.nojs   === '1';
  const noAd   = req.query.noad   !== '0'; // on by default; pass noad=0 to disable
  const school  = req.query.school === '1';

  if (!targetUrl) return res.status(400).send('Missing ?url=');
  let parsed;
  try { parsed = new URL(targetUrl); } catch { return res.status(400).send('Invalid URL'); }

  const uid    = parseCookies(req).uid || 'default';
  const data   = loadData();
  const domain = parsed.hostname;
  const stored = getCookiesForDomain(data, uid, domain);

  try {
    const agent = parsed.protocol==='https:'
      ? new https.Agent({rejectUnauthorized:false}) : new http.Agent();
    const response = await fetch(targetUrl, {
      headers: {
        'User-Agent':      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120 Safari/537.36',
        'Accept':          'text/html,application/xhtml+xml,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'identity',
        'Referer':         parsed.origin,
        ...(stored && {'Cookie': stored}),
      },
      redirect: 'follow', agent,
    });

    const rawHeaders = response.headers.raw ? response.headers.raw() : {};
    const setCookies = rawHeaders['set-cookie'] || [];
    if (setCookies.length) { storeCookies(data, uid, domain, setCookies); saveData(data); }

    const ct   = response.headers.get('content-type')||'';
    const skip = ['content-security-policy','x-frame-options','strict-transport-security','content-encoding','set-cookie'];
    for (const [k,v] of response.headers.entries())
      if (!skip.includes(k.toLowerCase())) try { res.setHeader(k,v); } catch {}
    res.setHeader('content-type', ct);

    const finalUrl = response.url || targetUrl;

    if (ct.includes('text/html'))
      res.send(rewriteHtml(await response.text(), finalUrl, { noJs, noAd, school }));
    else if (ct.includes('text/css'))
      res.send(rewriteCss(await response.text(), finalUrl));
    else
      response.body.pipe(res);

  } catch(err) {
    const isBlock = /ECONNREFUSED|certificate|getaddrinfo/i.test(err.message);
    res.status(502).send(`<!DOCTYPE html><html><head><title>Proxy Error</title>
      <style>body{background:#080c10;color:#c8d8e8;font-family:monospace;padding:48px 32px;max-width:600px;margin:0 auto}
      h2{color:#ff3b5c}a{color:#39ff14;border:1px solid #39ff1444;padding:8px 20px;border-radius:6px;text-decoration:none;display:inline-block;margin-top:24px}</style>
      </head><body>
      <h2>⚠ Proxy Error</h2>
      <p style="color:#aaa;margin:8px 0 24px;font-size:12px">${targetUrl}</p>
      <p style="background:#0e1419;border-left:3px solid #ff3b5c;padding:14px;border-radius:6px;font-size:13px;line-height:1.6;color:#e8c0c0">
        ${isBlock ? 'The site refused the connection — it may actively block proxies.' : err.message}
      </p>
      <ul style="margin-top:20px;line-height:2;font-size:13px;color:#8aa0b0;padding-left:20px">
        <li>Enable <b>Compat Mode</b> on the card (strips JavaScript)</li>
        <li>Some sites (Google, Cloudflare) actively block proxies</li>
        <li>Try opening in a new tab instead of the frame panel</li>
      </ul>
      <a href="/dashboard" target="_top">← Back to Dashboard</a>
      </body></html>`);
  }
});

// ── Start ─────────────────────────────────────────────────────────────────────
app.listen(PORT, '0.0.0.0', () => {
  console.log(`\n⚡ OpenGate → http://0.0.0.0:${PORT}`);
  console.log(`   Direct: /?key=${SECRET_KEY}  Login: /login\n`);
});
