const express = require('express');
const fetch   = require('node-fetch');
const cheerio = require('cheerio');
const fs      = require('fs');
const path    = require('path');
const https   = require('https');
const http    = require('http');
const crypto  = require('crypto');

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
  try   { return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8')); }
  catch { return { sites:[], history:{}, cookieJar:{}, guestTokens:{} }; }
}
function saveData(d) { fs.writeFileSync(DATA_FILE, JSON.stringify(d, null, 2)); }

// ── Auth ──────────────────────────────────────────────────────────────────────
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
  res.setHeader('Set-Cookie', `uid=${uid}; Path=/; HttpOnly; SameSite=Lax; Max-Age=31536000`);
  return uid;
}

app.use(express.json());

// ── Public routes ─────────────────────────────────────────────────────────────
app.get('/', (req, res) => {
  if (req.query.key === SECRET_KEY) {
    res.setHeader('Set-Cookie', `auth=${makeToken()}; Path=/; HttpOnly; SameSite=Lax; Max-Age=604800`);
    return res.redirect('/dashboard');
  }
  if (req.query.guestToken) {
    const token = loadData().guestTokens?.[req.query.guestToken];
    if (token && token.expiresAt > Date.now()) {
      res.setHeader('Set-Cookie', `guestToken=${req.query.guestToken}; Path=/; HttpOnly; SameSite=Lax; Max-Age=3600`);
      return res.redirect('/dashboard');
    }
  }
  if (isAuth(req)) return res.redirect('/dashboard');
  res.sendFile(path.join(__dirname, 'public', 'decoy.html'));
});
app.get('/decoy', (_req, res) => res.sendFile(path.join(__dirname, 'public', 'decoy.html')));
app.get('/login', (req, res) => {
  if (isAuth(req)) return res.redirect('/dashboard');
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});
app.post('/api/login', (req, res) => {
  if (req.body.password === APP_PASSWORD) {
    res.setHeader('Set-Cookie', `auth=${makeToken()}; Path=/; HttpOnly; SameSite=Lax; Max-Age=604800`);
    return res.json({ ok: true });
  }
  res.status(401).json({ error: 'Wrong password' });
});
app.get('/logout', (_req, res) => {
  res.setHeader('Set-Cookie', ['auth=; Path=/; Max-Age=0', 'guestToken=; Path=/; Max-Age=0']);
  res.redirect('/');
});
app.get('/dashboard', requireAuth, (req, res) => {
  getUserId(req, res);
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ── Meta fetch ────────────────────────────────────────────────────────────────
app.get('/api/fetch-meta', requireAuth, async (req, res) => {
  const url = req.query.url;
  if (!url) return res.json({ desc: '', title: '' });
  try {
    const r = await fetch(url, { headers: { 'User-Agent': 'Mozilla/5.0' }, redirect: 'follow',
      agent: url.startsWith('https') ? new https.Agent({ rejectUnauthorized: false }) : new http.Agent() });
    const $ = cheerio.load(await r.text());
    const desc  = ($('meta[name="description"]').attr('content') || $('meta[property="og:description"]').attr('content') || '').trim().slice(0, 200);
    const title = ($('meta[property="og:title"]').attr('content') || $('title').text() || '').trim().slice(0, 80);
    res.json({ desc, title });
  } catch { res.json({ desc: '', title: '' }); }
});

// ── Sites API ─────────────────────────────────────────────────────────────────
app.get('/api/sites', requireAuth, (req, res) => res.json(loadData().sites));

app.post('/api/sites', requireAuth, requireEditAuth, (req, res) => {
  const { name, url, icon, tags, compat, desc } = req.body;
  if (!name || !url) return res.status(400).json({ error: 'Name and URL required' });
  const data = loadData();
  const s = {
    id: Date.now(), name: name.trim(),
    url: url.startsWith('http') ? url.trim() : 'https://' + url.trim(),
    icon: icon || '🌐',
    tags: Array.isArray(tags) ? tags : (tags || '').split(',').map(t => t.trim()).filter(Boolean),
    compat: !!compat, desc: (desc || '').trim().slice(0, 200),
  };
  data.sites.push(s); saveData(data); res.json(s);
});

app.put('/api/sites/:id', requireAuth, requireEditAuth, (req, res) => {
  const data = loadData();
  const idx  = data.sites.findIndex(s => s.id === parseInt(req.params.id));
  if (idx === -1) return res.status(404).json({ error: 'Not found' });
  const { name, url, icon, tags, compat, desc } = req.body;
  data.sites[idx] = {
    ...data.sites[idx],
    ...(name  !== undefined && { name:  name.trim() }),
    ...(url   !== undefined && { url:   url.startsWith('http') ? url.trim() : 'https://'+url.trim() }),
    ...(icon  !== undefined && { icon }),
    ...(tags  !== undefined && { tags:  Array.isArray(tags) ? tags : tags.split(',').map(t => t.trim()).filter(Boolean) }),
    ...(compat !== undefined && { compat: !!compat }),
    ...(desc  !== undefined && { desc:  desc.trim().slice(0, 200) }),
  };
  saveData(data); res.json(data.sites[idx]);
});

app.delete('/api/sites/:id', requireAuth, requireEditAuth, (req, res) => {
  const data = loadData();
  data.sites = data.sites.filter(s => s.id !== parseInt(req.params.id));
  saveData(data); res.json({ ok: true });
});

app.post('/api/reorder', requireAuth, requireEditAuth, (req, res) => {
  const data = loadData();
  const map  = Object.fromEntries(data.sites.map(s => [s.id, s]));
  data.sites  = req.body.ids.map(id => map[id]).filter(Boolean);
  saveData(data); res.json({ ok: true });
});

// ── History ───────────────────────────────────────────────────────────────────
app.get('/api/history', requireAuth, (req, res) => {
  const uid = parseCookies(req).uid || 'default';
  res.json((loadData().history || {})[uid] || []);
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
  saveData(data); res.json({ ok: true });
});
app.delete('/api/history', requireAuth, (req, res) => {
  const uid  = parseCookies(req).uid || 'default';
  const data = loadData();
  if (data.history) data.history[uid] = [];
  saveData(data); res.json({ ok: true });
});

// ── Guest links ───────────────────────────────────────────────────────────────
app.post('/api/guest-link', requireAuth, requireEditAuth, (req, res) => {
  if (req.authLevel !== 'full') return res.status(403).json({ error: 'Full auth required' });
  const minutes = parseInt(req.body.minutes) || 15;
  const token   = crypto.randomBytes(20).toString('hex');
  const data    = loadData();
  if (!data.guestTokens) data.guestTokens = {};
  for (const [k, v] of Object.entries(data.guestTokens))
    if (v.expiresAt <= Date.now()) delete data.guestTokens[k];
  data.guestTokens[token] = { expiresAt: Date.now() + minutes * 60 * 1000, minutes };
  saveData(data);
  res.json({ token, url: `${req.protocol}://${req.get('host')}/?guestToken=${token}`, expiresIn: minutes });
});

app.get('/api/me', requireAuth, (req, res) => res.json({ level: req.authLevel }));

app.post('/api/check-edit-pw', requireAuth, (req, res) => {
  if (req.authLevel === 'guest') return res.status(403).json({ error: 'Guests cannot edit' });
  if (req.headers['x-edit-password'] === EDIT_PASSWORD) return res.json({ ok: true });
  res.status(403).json({ error: 'Wrong edit password' });
});

// ── Ad-block selectors ────────────────────────────────────────────────────────
const AD_SELECTORS = [
  'ins.adsbygoogle', '[id*="google_ads"]', '[id*="carbonads"]',
  '[class*="adsbygoogle"]', '[class*="banner-ad"]', '[class*="ad-banner"]',
  '[class*="advertisement"]', '[class*="sponsored-content"]',
  '[data-ad]', '[data-ad-unit]',
  'iframe[src*="doubleclick"]', 'iframe[src*="googlesyndication"]',
  'iframe[src*="adnxs"]',      'iframe[src*="adsrvr"]',
  'div[id^="div-gpt-ad"]',     'div[id^="advert"]',
  'div[class^="advert"]',      '[aria-label="Advertisement"]',
];
const AD_SCRIPT_RE = /googlesyndication|doubleclick|adnxs|adsrvr|adservice|amazon-adsystem|pagead2|moatads|outbrain|taboola/i;

// ── School CSS for decoy overlay on proxied pages ─────────────────────────────
const SCHOOL_CSS = `<style>
body{background:#f0f4fa!important;color:#1a2a4a!important;font-family:'Segoe UI',Arial,sans-serif!important}
a{color:#2c5fa8!important} h1,h2,h3,h4{color:#1a2a4a!important}
header,nav,.header,.nav,.navbar,.site-header,#header,#nav,#navbar
  {background:#2c5fa8!important;color:#fff!important;border-bottom:3px solid #1a3a78!important}
header a,nav a,#header a{color:#fff!important}
footer,.footer,#footer{background:#dce8f5!important;color:#4a6a9a!important}
button,.btn,[role="button"]{background:#2c5fa8!important;color:#fff!important;border-radius:4px!important}
input,textarea,select{border:1px solid #c0d0e8!important;background:#fff!important;color:#1a2a4a!important}
</style>
<div style="position:fixed;top:34px;left:0;right:0;z-index:2147483646;background:#2c5fa8;color:#fff;
  font-family:Arial,sans-serif;font-size:12px;padding:4px 14px;display:flex;align-items:center;
  gap:10px;border-bottom:2px solid #1a3a78;box-shadow:0 1px 4px #0002">
  <b style="font-size:13px">🏫 Schulportal</b>
  <span style="opacity:.7">Lernmaterialien &amp; Ressourcen</span>
  <span style="margin-left:auto;opacity:.5;font-size:10px">Klasse 10 · Gymnasium</span>
</div><div style="height:28px"></div>`;

// ── URL helpers ───────────────────────────────────────────────────────────────
function resolveUrl(base, rel) {
  try { return new URL(rel, base).href; } catch { return rel; }
}
function wrapUrl(url, base) {
  if (!url || url.startsWith('data:') || url.startsWith('blob:') ||
      url.startsWith('javascript:') || url.startsWith('mailto:') || url.startsWith('#'))
    return url;
  try {
    const r = resolveUrl(base, url.trim());
    if (r.startsWith('http')) return '/proxy?url=' + encodeURIComponent(r);
  } catch {}
  return url;
}

function rewriteSrcset(srcset, base) {
  if (!srcset) return srcset;
  return srcset.split(',').map(part => {
    const p = part.trim().split(/\s+/);
    if (p[0]) p[0] = wrapUrl(p[0], base);
    return p.join(' ');
  }).join(', ');
}

function rewriteCss(css, base) {
  if (!css) return css;
  // url() references
  css = css.replace(/url\(\s*(['"]?)([^'")]+)\1\s*\)/gi, (m, q, u) => {
    const trimmed = u.trim();
    if (trimmed.startsWith('data:') || trimmed.startsWith('blob:')) return m;
    return `url('${wrapUrl(trimmed, base)}')`;
  });
  // @import "..." and @import url(...)  — already caught above for url(), handle quoted form
  css = css.replace(/@import\s+(['"])([^'"]+)\1/gi, (_m, _q, u) => `@import '${wrapUrl(u, base)}'`);
  return css;
}

// ── Client-side navigation interceptor (injected into every proxied page) ─────
function buildInjectedScript(baseUrl) {
  const escaped = baseUrl.replace(/'/g, "\\'");
  return `<script>
(function(){
  var BASE='${escaped}', PR='/proxy?url=';

  function toProxy(url){
    if(!url)return url;
    var s=url.toString();
    if(s.startsWith('#')||s.startsWith('javascript:')||s.startsWith('mailto:')||s.startsWith('data:')||s.startsWith('blob:'))return s;
    if(s.indexOf('/proxy?url=')!==-1)return s;
    try{ var abs=new URL(s,BASE).href; if(abs.startsWith('http'))return PR+encodeURIComponent(abs); }catch(e){}
    return s;
  }

  /* ── Intercept all <a> clicks (catches dynamically-added links) ── */
  document.addEventListener('click',function(e){
    var el=e.target;
    while(el&&el.tagName!=='A')el=el.parentElement;
    if(!el)return;
    var href=el.getAttribute('href');
    if(!href||href.startsWith('#')||href.startsWith('javascript:')||href.startsWith('mailto:'))return;
    if(el.href&&el.href.indexOf('/proxy?url=')!==-1)return;
    e.preventDefault();
    window.top.location.href=toProxy(el.href||href);
  },true);

  /* ── Intercept form submissions ── */
  document.addEventListener('submit',function(e){
    var f=e.target;
    var action=f.getAttribute('action');
    if(action===null)action=BASE; // no action attr = current page
    if(!action||action==='')action=BASE;
    if(action.indexOf('/proxy?url=')!==-1)return;
    if(action.startsWith('javascript:'))return;
    f.action=toProxy(action);
  },true);

  /* ── Intercept history navigation (SPAs: React, Vue, etc.) ── */
  function wrap(orig){
    return function(state,title,url){
      if(url&&typeof url==='string'&&url.indexOf('/proxy?url=')===-1&&!url.startsWith('#'))
        url=toProxy(url);
      return orig.call(history,state,title,url);
    };
  }
  try{ history.pushState=wrap(history.pushState); }catch(e){}
  try{ history.replaceState=wrap(history.replaceState); }catch(e){}

  /* ── Panic & BroadcastChannel ── */
  try{
    var bc=new BroadcastChannel('opengate');
    bc.onmessage=function(e){if(e.data==='PANIC')window.top.location.href='/decoy';};
  }catch(e){}
  document.addEventListener('keydown',function(e){
    if(e.key==='p'||e.key==='P'){
      try{new BroadcastChannel('opengate').postMessage('PANIC');}catch(e){}
      window.top.location.href='/decoy';
    }
  });

  /* ── Idle redirect ── */
  var ms=parseInt((function(){try{return window.top.localStorage.getItem('idleTimeout');}catch(e){return localStorage.getItem('idleTimeout');}})());
  if(ms&&ms>0){
    var t;
    function ri(){clearTimeout(t);t=setTimeout(function(){
      try{new BroadcastChannel('opengate').postMessage('PANIC');}catch(e){}
      window.top.location.href='/decoy';
    },ms);}
    ['mousemove','keydown','mousedown','touchstart','scroll'].forEach(function(ev){
      document.addEventListener(ev,ri,{passive:true});
    });
    ri();
  }
})();
</script>`;
}

// ── HTML rewriter ─────────────────────────────────────────────────────────────
function rewriteHtml(html, baseUrl, { noJs, noAd, school }) {
  const $ = cheerio.load(html, { decodeEntities: false });

  // ── 1. Set <base> tag — safety net for anything we miss ──
  // This makes missed relative URLs resolve to the real site
  // rather than to /proxy with no ?url= parameter
  $('base').remove();
  if ($('head').length) {
    $('head').prepend(`<base href="${baseUrl}">`);
  } else {
    $('html').prepend(`<head><base href="${baseUrl}"></head>`);
  }

  // ── 2. Strip SRI (integrity attributes break proxied resources) ──
  $('[integrity]').removeAttr('integrity').removeAttr('crossorigin');

  // ── 3. Compat mode: strip scripts ──
  if (noJs) {
    $('script').remove();
    ['onload','onclick','onerror','onmouseover','onmouseout','onfocus','onblur','onsubmit','onchange']
      .forEach(ev => $(`[${ev}]`).removeAttr(ev));
  }

  // ── 4. Ad blocker ──
  if (noAd) {
    AD_SELECTORS.forEach(sel => { try { $(sel).remove(); } catch {} });
    $('script[src]').each((_, el) => {
      if (AD_SCRIPT_RE.test($(el).attr('src') || '')) $(el).remove();
    });
  }

  // ── 5. Rewrite <a href> ──
  $('a[href]').each((_, el) => {
    const h = $(el).attr('href');
    if (h && !h.startsWith('#') && !h.startsWith('javascript:') && !h.startsWith('mailto:'))
      $(el).attr('href', wrapUrl(h, baseUrl));
  });

  // ── 6. Rewrite <script src> ──
  $('script[src]').each((_, el) => $(el).attr('src', wrapUrl($(el).attr('src'), baseUrl)));

  // ── 7. Rewrite <link href> — ALL types (stylesheet, icon, preload, etc.) ──
  $('link[href]').each((_, el) => {
    const rel = ($(el).attr('rel') || '').toLowerCase();
    if (rel === 'dns-prefetch' || rel === 'preconnect') return; // skip these
    $(el).attr('href', wrapUrl($(el).attr('href'), baseUrl));
  });

  // ── 8. Rewrite <img src> and srcset ──
  $('img[src]').each((_, el) => $(el).attr('src', wrapUrl($(el).attr('src'), baseUrl)));
  $('img[srcset]').each((_, el) => $(el).attr('srcset', rewriteSrcset($(el).attr('srcset'), baseUrl)));

  // ── 9. Lazy-load data attributes (every common pattern) ──
  const lazyAttrs = ['data-src','data-lazy','data-lazy-src','data-original',
                     'data-url','data-bg','data-background','data-image',
                     'data-img','data-thumb','data-hi-res','data-echo'];
  lazyAttrs.forEach(attr => {
    $(`[${attr}]`).each((_, el) => {
      const v = $(el).attr(attr);
      if (v && !v.startsWith('data:')) $(el).attr(attr, wrapUrl(v, baseUrl));
    });
  });
  // data-srcset
  $('[data-srcset]').each((_, el) => $(el).attr('data-srcset', rewriteSrcset($(el).attr('data-srcset'), baseUrl)));

  // ── 10. <picture><source> ──
  $('source[src]').each((_,el) => $(el).attr('src', wrapUrl($(el).attr('src'), baseUrl)));
  $('source[srcset]').each((_,el) => $(el).attr('srcset', rewriteSrcset($(el).attr('srcset'), baseUrl)));

  // ── 11. <video>, <audio>, <track> ──
  $('video[src], audio[src]').each((_,el) => $(el).attr('src', wrapUrl($(el).attr('src'), baseUrl)));
  $('video[poster]').each((_,el) => $(el).attr('poster', wrapUrl($(el).attr('poster'), baseUrl)));
  $('track[src]').each((_,el) => $(el).attr('src', wrapUrl($(el).attr('src'), baseUrl)));

  // ── 12. SVG <image> and <use> ──
  $('image[href], use[href]').each((_,el) => $(el).attr('href', wrapUrl($(el).attr('href'), baseUrl)));
  // xlink:href — cheerio needs special handling
  $('image, use').each((_, el) => {
    const xl = $(el).attr('xlink:href');
    if (xl) $(el).attr('xlink:href', wrapUrl(xl, baseUrl));
  });

  // ── 13. <input type="image"> ──
  $('input[type="image"][src]').each((_,el) => $(el).attr('src', wrapUrl($(el).attr('src'), baseUrl)));

  // ── 14. <meta> refresh redirect ──
  $('meta[http-equiv="refresh"]').each((_, el) => {
    const c = $(el).attr('content') || '';
    const m = c.match(/^(\d+;\s*url=)(.+)$/i);
    if (m) $(el).attr('content', m[1] + wrapUrl(m[2].trim(), baseUrl));
  });

  // ── 15. <form> actions — including those with NO action attr ──
  $('form').each((_, el) => {
    const action = $(el).attr('action');
    if (action === undefined || action === '') {
      // No action or empty = submit to current proxied URL
      $(el).attr('action', '/proxy?url=' + encodeURIComponent(baseUrl));
    } else {
      $(el).attr('action', wrapUrl(action, baseUrl));
    }
  });

  // ── 16. <iframe src> ──
  $('iframe[src]').each((_, el) => {
    const src = $(el).attr('src');
    if (src && !src.startsWith('javascript:') && !src.startsWith('about:'))
      $(el).attr('src', wrapUrl(src, baseUrl));
  });

  // ── 17. Inline <style> blocks ──
  $('style').each((_, el) => {
    const css = $(el).html();
    if (css) $(el).html(rewriteCss(css, baseUrl));
  });

  // ── 18. Inline style="" attributes ──
  $('[style]').each((_, el) => {
    const s = $(el).attr('style');
    if (s && s.includes('url(')) $(el).attr('style', rewriteCss(s, baseUrl));
  });

  // ── 19. Proxy bar ──
  const badges = [
    noJs  ? '<span style="color:#ffa500;font-size:10px">⚡COMPAT</span>'   : '',
    noAd  ? '<span style="color:#39ff14;font-size:10px">🛡AD-FREE</span>'  : '',
    school? '<span style="color:#7bc8ff;font-size:10px">🏫SCHULM.</span>'  : '',
  ].filter(Boolean).join(' ');

  const bar = `
    ${school ? SCHOOL_CSS : ''}
    <div id="__og_bar__" style="position:fixed;top:0;left:0;right:0;z-index:2147483647;
      background:#0d0d0d;color:#39ff14;font-family:monospace;font-size:12px;
      padding:5px 14px;display:flex;align-items:center;gap:10px;
      border-bottom:1px solid #39ff1444;box-sizing:border-box">
      <a href="/dashboard" target="_top" style="color:#39ff14;text-decoration:none;font-weight:bold;flex-shrink:0">← Back</a>
      <span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:#aaa;font-size:10px">${baseUrl}</span>
      ${badges}
      <button onclick="document.getElementById('__og_bar__').style.display='none'"
        style="background:none;border:none;color:#4a6070;cursor:pointer;font-size:14px;flex-shrink:0">✕</button>
    </div>
    <div style="height:34px"></div>
    ${buildInjectedScript(baseUrl)}`;

  // Prefer prepending to <body>, fall back to <html>
  if ($('body').length) $('body').prepend(bar);
  else $('html').prepend(bar);

  return $.html();
}

function rewriteCssFile(css, base) {
  return rewriteCss(css, base);
}

// ── Cookie jar ────────────────────────────────────────────────────────────────
function getDomainCookies(data, uid, domain) {
  return data.cookieJar?.[uid]?.[domain] || '';
}
function storeDomainCookies(data, uid, domain, headers) {
  if (!headers?.length) return;
  if (!data.cookieJar)        data.cookieJar = {};
  if (!data.cookieJar[uid])   data.cookieJar[uid] = {};
  const ex = {};
  (data.cookieJar[uid][domain] || '').split(';').forEach(p => {
    const [k, ...v] = p.trim().split('='); if (k) ex[k.trim()] = v.join('=').trim();
  });
  headers.forEach(h => {
    const [k, ...v] = h.split(';')[0].trim().split('='); if (k) ex[k.trim()] = v.join('=').trim();
  });
  data.cookieJar[uid][domain] = Object.entries(ex).map(([k, v]) => `${k}=${v}`).join('; ');
}

// ── Proxy route ───────────────────────────────────────────────────────────────
app.get('/proxy', requireAuth, async (req, res) => {
  const targetUrl = req.query.url;

  // ── Missing URL: show a helpful recovery page instead of a blank error ──
  if (!targetUrl) {
    return res.status(400).send(`<!DOCTYPE html><html><head><title>OpenGate</title>
      <style>body{background:#080c10;color:#c8d8e8;font-family:monospace;padding:48px 32px;max-width:600px;margin:0 auto}
      h2{color:#ffa500}a{color:#39ff14;border:1px solid #39ff1444;padding:8px 20px;border-radius:6px;text-decoration:none;display:inline-block;margin-top:20px}
      p{margin:10px 0;color:#aaa;font-size:13px;line-height:1.7}</style></head><body>
      <h2>⚠ No URL specified</h2>
      <p>This happens when a site uses JavaScript to navigate and the proxy didn't catch it in time.</p>
      <p>Tips: use the <b>Back</b> button in your browser, or try enabling <b>Compat Mode</b> on the site card (which strips JS and forces link-based navigation).</p>
      <a href="/dashboard" target="_top">← Back to Dashboard</a>
      </body></html>`);
  }

  let parsed;
  try   { parsed = new URL(targetUrl); }
  catch { return res.status(400).send('Invalid URL: ' + targetUrl); }

  const cookies = parseCookies(req);
  const noJs    = req.query.nojs === '1';
  const noAd    = cookies.og_adblock !== '0';
  const school  = cookies.og_school  === '1';
  const uid     = cookies.uid || 'default';
  const data    = loadData();
  const stored  = getDomainCookies(data, uid, parsed.hostname);

  try {
    const agent = parsed.protocol === 'https:'
      ? new https.Agent({ rejectUnauthorized: false }) : new http.Agent();

    const upstream = await fetch(targetUrl, {
      headers: {
        'User-Agent':      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36',
        'Accept':          'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'identity',
        'Referer':         parsed.origin + '/',
        'Sec-Fetch-Dest':  'document',
        'Sec-Fetch-Mode':  'navigate',
        'Sec-Fetch-Site':  'same-origin',
        ...(stored && { Cookie: stored }),
      },
      redirect: 'follow',
      agent,
    });

    // Store returned cookies for this user+domain
    const rawHeaders = upstream.headers.raw ? upstream.headers.raw() : {};
    const setCookies = rawHeaders['set-cookie'] || [];
    if (setCookies.length) { storeDomainCookies(data, uid, parsed.hostname, setCookies); saveData(data); }

    const finalUrl = upstream.url || targetUrl;
    const ct = upstream.headers.get('content-type') || '';

    // Strip headers that break proxy functionality
    const STRIP_HEADERS = new Set([
      'content-security-policy', 'content-security-policy-report-only',
      'x-frame-options', 'strict-transport-security',
      'content-encoding', 'set-cookie',
      'x-content-type-options', // lets us serve rewritten content
    ]);
    for (const [k, v] of upstream.headers.entries()) {
      if (!STRIP_HEADERS.has(k.toLowerCase())) {
        try { res.setHeader(k, v); } catch {}
      }
    }
    res.setHeader('content-type', ct);

    if (ct.includes('text/html')) {
      const body = await upstream.text();
      res.send(rewriteHtml(body, finalUrl, { noJs, noAd, school }));

    } else if (ct.includes('text/css')) {
      res.send(rewriteCssFile(await upstream.text(), finalUrl));

    } else if (ct.includes('javascript') || ct.includes('application/json')) {
      // Pass JS/JSON through untouched (JS rewriting is too risky/complex)
      res.send(await upstream.text());

    } else {
      // Binary: images, fonts, etc.
      upstream.body.pipe(res);
    }

  } catch (err) {
    const isNetErr = /ECONNREFUSED|ENOTFOUND|ETIMEDOUT|certificate|getaddrinfo/i.test(err.message);
    res.status(502).send(`<!DOCTYPE html><html><head><title>Proxy Error — OpenGate</title>
      <style>body{background:#080c10;color:#c8d8e8;font-family:monospace;padding:48px 32px;max-width:600px;margin:0 auto}
      h2{color:#ff3b5c} .url{color:#39ff14;font-size:12px;margin:6px 0 22px;word-break:break-all}
      .reason{background:#0e1419;border-left:3px solid #ff3b5c;padding:14px;border-radius:6px;font-size:13px;line-height:1.7;color:#e8c0c0}
      ul{margin:16px 0;padding-left:20px;line-height:2;font-size:13px;color:#8aa0b0}
      a{color:#39ff14;border:1px solid #39ff1444;padding:8px 20px;border-radius:6px;text-decoration:none;display:inline-block;margin-top:20px}
      </style></head><body>
      <h2>⚠ Proxy Error</h2>
      <div class="url">${targetUrl}</div>
      <div class="reason">${isNetErr ? 'Could not connect to the site. It may be down, blocking proxies, or the URL is wrong.' : err.message}</div>
      <ul>
        <li>Enable <b>Compat Mode</b> on the site card — strips JavaScript, often fixes broken sites</li>
        <li>Sites protected by Cloudflare or Google actively block proxies</li>
        <li>Try pasting the URL into the quick-navigate bar and opening in a new tab</li>
      </ul>
      <a href="/dashboard" target="_top">← Back to Dashboard</a>
      </body></html>`);
  }
});

// ── Start ─────────────────────────────────────────────────────────────────────
app.listen(PORT, '0.0.0.0', () => {
  console.log(`\n⚡ OpenGate running on http://0.0.0.0:${PORT}`);
  console.log(`   Dashboard:    /dashboard`);
  console.log(`   Secret link:  /?key=${SECRET_KEY}\n`);
});
