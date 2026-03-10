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

// ── Data ──────────────────────────────────────────────────────────────────────
function loadData() {
  if (!fs.existsSync(DATA_FILE)) {
    const d = {
      sites: [
        { id:1, name:'Wikipedia',    url:'https://en.wikipedia.org',    icon:'📚', tags:['school'], compat:false, desc:'' },
        { id:2, name:'Khan Academy', url:'https://www.khanacademy.org', icon:'🎓', tags:['school'], compat:false, desc:'' },
        { id:3, name:'GitHub',       url:'https://github.com',          icon:'🐙', tags:['dev'],    compat:false, desc:'' },
        { id:4, name:'Reddit',       url:'https://www.reddit.com',      icon:'🤖', tags:['social'], compat:false, desc:'' },
      ],
      history:{}, cookieJar:{}, guestTokens:{},
    };
    fs.writeFileSync(DATA_FILE, JSON.stringify(d, null, 2));
    return d;
  }
  try { return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8')); }
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
app.use(express.urlencoded({ extended: true }));

// ── OUR KNOWN APP PATHS (so catch-all doesn't touch them) ─────────────────────
const APP_PATHS = new Set(['/','//']);
const APP_PREFIXES = ['/dashboard','/login','/logout','/decoy','/sw.js','/api/','/proxy'];

function isAppPath(p) {
  return APP_PATHS.has(p) || APP_PREFIXES.some(pre => p === pre || p.startsWith(pre + '/') || p.startsWith(pre + '?'));
}

// ── Service Worker ─────────────────────────────────────────────────────────────
// Served at root scope. Pre-registered from dashboard so it's active BEFORE
// any proxy page opens, meaning 100% of requests are intercepted from page 1.
app.get('/sw.js', (req, res) => {
  res.setHeader('Content-Type',              'application/javascript');
  res.setHeader('Service-Worker-Allowed',    '/');
  res.setHeader('Cache-Control',             'no-cache, no-store, must-revalidate');
  res.send(`
/* OpenGate Service Worker v5 */
'use strict';
var OG  = self.location.origin;  // e.g. https://opengatex.onrender.com
var GIF = 'R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7';

// Paths that belong to our app — never proxy these
function isOwnPath(pathname) {
  return pathname === '/' ||
    ['/dashboard','/login','/logout','/decoy','/sw.js','/api/','/proxy']
      .some(function(p){ return pathname === p || pathname.startsWith(p+'/') || pathname.startsWith(p+'?'); });
}

self.addEventListener('install', function(){ self.skipWaiting(); });
self.addEventListener('activate', function(e){ e.waitUntil(self.clients.claim()); });
self.addEventListener('message', function(e){
  if (e.data && e.data.type === 'SKIP_WAITING') self.skipWaiting();
});

self.addEventListener('fetch', function(event) {
  var req = event.request;
  var url = req.url;

  // Only intercept http(s)
  if (!url.startsWith('http')) return;

  var pu;
  try { pu = new URL(url); } catch(e) { return; }

  // ── Same-origin requests ──────────────────────────────────────────────────
  if (pu.origin === OG) {
    // Normal app path → pass through
    if (isOwnPath(pu.pathname)) return;

    // Unknown path on our origin (e.g. site did window.location = '/about')
    // Reconstruct as a path on the last-visited site using the Referer
    if (req.mode === 'navigate') {
      var ref = req.referrer || '';
      var base = '';
      // Try to get base from Referer header
      try {
        var ru = new URL(ref);
        if (ru.pathname.startsWith('/proxy')) {
          base = decodeURIComponent(ru.searchParams.get('url') || '');
        }
      } catch(e) {}

      event.respondWith((function(){
        var buildTarget = function(b) {
          try {
            var t = new URL(pu.pathname + pu.search + pu.hash, new URL(b).origin).href;
            return fetch(OG + '/proxy?url=' + encodeURIComponent(t), { credentials: 'include', redirect: 'follow' });
          } catch(e) {
            return Promise.reject(e);
          }
        };

        if (base) return buildTarget(base).catch(function(){ return Response.redirect(OG+'/dashboard', 302); });

        // No referrer — ask server for last known base
        return fetch(OG + '/api/last-base', { credentials: 'include' })
          .then(function(r){ return r.json(); })
          .then(function(d){
            if (d && d.url) return buildTarget(d.url);
            return Response.redirect(OG + '/dashboard', 302);
          })
          .catch(function(){ return Response.redirect(OG + '/dashboard', 302); });
      })());
      return;
    }

    // Same-origin non-navigate (XHR/fetch to our API etc.) → pass through
    return;
  }

  // ── External origin — route through proxy ─────────────────────────────────
  var accept  = req.headers.get('Accept') || '';
  var isImage = /image\/|\.(?:png|jpg|jpeg|gif|webp|svg|ico|avif|bmp)(\?|$)/i.test(url) || accept.startsWith('image/');

  // Preserve original request body for POST/PUT/PATCH
  var proxyUrl = OG + '/proxy?url=' + encodeURIComponent(url);

  var fetchPromise;
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    fetchPromise = req.clone().text().then(function(body) {
      return fetch(proxyUrl + '&_method=' + req.method, {
        method: 'POST',
        credentials: 'include',
        redirect: 'follow',
        headers: {
          'Content-Type':  req.headers.get('Content-Type') || 'application/x-www-form-urlencoded',
          'x-og-accept':   accept,
          'x-og-body':     body.slice(0, 8000),
        },
      });
    });
  } else {
    fetchPromise = fetch(proxyUrl, {
      credentials: 'include',
      redirect: 'follow',
      headers: { 'x-og-accept': accept },
    });
  }

  event.respondWith(
    fetchPromise.catch(function() {
      if (isImage) {
        return new Response(self.atob(GIF), { headers: { 'Content-Type': 'image/gif' } });
      }
      if (req.mode === 'navigate') {
        return Response.redirect(OG + '/dashboard', 302);
      }
      return new Response('', { status: 204 });
    })
  );
});
`);
});

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
app.get('/decoy',  (_req, res) => res.sendFile(path.join(__dirname, 'public', 'decoy.html')));
app.get('/login',  (req, res) => { if (isAuth(req)) return res.redirect('/dashboard'); res.sendFile(path.join(__dirname, 'public', 'login.html')); });
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

// ── API: last proxied URL (for SW URL reconstruction) ─────────────────────────
app.get('/api/last-base', requireAuth, (req, res) => {
  const c = parseCookies(req);
  res.json({ url: c.og_last ? decodeURIComponent(c.og_last) : null });
});

// ── Meta fetch ────────────────────────────────────────────────────────────────
app.get('/api/fetch-meta', requireAuth, async (req, res) => {
  const url = req.query.url;
  if (!url) return res.json({ desc: '', title: '' });
  try {
    const r = await fetch(url, {
      headers: { 'User-Agent': 'Mozilla/5.0', 'Accept': 'text/html' }, redirect: 'follow',
      agent: url.startsWith('https') ? new https.Agent({ rejectUnauthorized: false }) : new http.Agent(),
    });
    const $ = cheerio.load(await r.text());
    const desc  = ($('meta[name="description"]').attr('content') || $('meta[property="og:description"]').attr('content') || '').trim().slice(0,200);
    const title = ($('meta[property="og:title"]').attr('content') || $('title').text() || '').trim().slice(0,80);
    res.json({ desc, title });
  } catch { res.json({ desc:'', title:'' }); }
});

// ── Sites API ─────────────────────────────────────────────────────────────────
app.get('/api/sites', requireAuth, (req, res) => res.json(loadData().sites));
app.post('/api/sites', requireAuth, requireEditAuth, (req, res) => {
  const { name, url, icon, tags, compat, desc } = req.body;
  if (!name || !url) return res.status(400).json({ error: 'Name and URL required' });
  const data = loadData();
  const s = { id: Date.now(), name: name.trim(),
    url: url.startsWith('http') ? url.trim() : 'https://' + url.trim(),
    icon: icon || '🌐',
    tags: Array.isArray(tags) ? tags : (tags||'').split(',').map(t=>t.trim()).filter(Boolean),
    compat: !!compat, desc: (desc||'').trim().slice(0,200) };
  data.sites.push(s); saveData(data); res.json(s);
});
app.put('/api/sites/:id', requireAuth, requireEditAuth, (req, res) => {
  const data = loadData();
  const idx  = data.sites.findIndex(s => s.id === parseInt(req.params.id));
  if (idx === -1) return res.status(404).json({ error: 'Not found' });
  const { name, url, icon, tags, compat, desc } = req.body;
  data.sites[idx] = { ...data.sites[idx],
    ...(name  !== undefined && { name:  name.trim() }),
    ...(url   !== undefined && { url:   url.startsWith('http') ? url.trim() : 'https://'+url.trim() }),
    ...(icon  !== undefined && { icon }),
    ...(tags  !== undefined && { tags:  Array.isArray(tags) ? tags : tags.split(',').map(t=>t.trim()).filter(Boolean) }),
    ...(compat !== undefined && { compat: !!compat }),
    ...(desc  !== undefined && { desc:  desc.trim().slice(0,200) }),
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
  const map  = Object.fromEntries(data.sites.map(s=>[s.id,s]));
  data.sites  = req.body.ids.map(id=>map[id]).filter(Boolean);
  saveData(data); res.json({ ok: true });
});

// ── History ───────────────────────────────────────────────────────────────────
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
  saveData(data); res.json({ ok:true });
});
app.delete('/api/history', requireAuth, (req, res) => {
  const uid = parseCookies(req).uid || 'default';
  const data = loadData();
  if (data.history) data.history[uid] = [];
  saveData(data); res.json({ ok:true });
});

// ── Guest links ───────────────────────────────────────────────────────────────
app.post('/api/guest-link', requireAuth, requireEditAuth, (req, res) => {
  if (req.authLevel !== 'full') return res.status(403).json({ error: 'Full auth required' });
  const minutes = parseInt(req.body.minutes)||15;
  const token   = crypto.randomBytes(20).toString('hex');
  const data    = loadData();
  if (!data.guestTokens) data.guestTokens = {};
  for (const [k,v] of Object.entries(data.guestTokens)) if (v.expiresAt<=Date.now()) delete data.guestTokens[k];
  data.guestTokens[token] = { expiresAt: Date.now()+minutes*60*1000, minutes };
  saveData(data);
  res.json({ token, url:`${req.protocol}://${req.get('host')}/?guestToken=${token}`, expiresIn:minutes });
});
app.get('/api/me', requireAuth, (req, res) => res.json({ level: req.authLevel }));
app.post('/api/check-edit-pw', requireAuth, (req, res) => {
  if (req.authLevel === 'guest') return res.status(403).json({ error: 'Guests cannot edit' });
  if (req.headers['x-edit-password'] === EDIT_PASSWORD) return res.json({ ok:true });
  res.status(403).json({ error: 'Wrong edit password' });
});

// ── Ad-block selectors ────────────────────────────────────────────────────────
const AD_SELECTORS = [
  'ins.adsbygoogle','[id*="google_ads"]','[id*="carbonads"]',
  '[class*="adsbygoogle"]','[class*="banner-ad"]','[class*="ad-banner"]',
  '[class*="advertisement"]','[class*="sponsored-content"]',
  '[data-ad]','[data-ad-unit]','iframe[src*="doubleclick"]',
  'iframe[src*="googlesyndication"]','iframe[src*="adnxs"]',
  'div[id^="div-gpt-ad"]','div[id^="advert"]','[aria-label="Advertisement"]',
];
const AD_SCRIPT_RE = /googlesyndication|doubleclick|adnxs|adsrvr|adservice|amazon-adsystem|pagead2|moatads|outbrain|taboola/i;

// ── School CSS (decoy overlay on proxied pages) ───────────────────────────────
const SCHOOL_CSS = `<style>
body{background:#f0f4fa!important;color:#1a2a4a!important;font-family:'Segoe UI',Arial,sans-serif!important}
a{color:#2c5fa8!important}h1,h2,h3,h4{color:#1a2a4a!important}
header,nav,.header,.nav,.navbar,.site-header,#header,#nav
  {background:#2c5fa8!important;color:#fff!important;border-bottom:3px solid #1a3a78!important}
header a,nav a{color:#fff!important}
footer,.footer{background:#dce8f5!important;color:#4a6a9a!important}
button,.btn{background:#2c5fa8!important;color:#fff!important;border-radius:4px!important}
input,textarea,select{border:1px solid #c0d0e8!important;background:#fff!important;color:#1a2a4a!important}
</style>
<div style="position:fixed;top:34px;left:0;right:0;z-index:2147483646;background:#2c5fa8;color:#fff;
  font-family:Arial,sans-serif;font-size:12px;padding:4px 14px;display:flex;align-items:center;
  gap:10px;border-bottom:2px solid #1a3a78">
  <b>🏫 Schulportal</b><span style="opacity:.7">Lernmaterialien &amp; Ressourcen</span>
  <span style="margin-left:auto;opacity:.5;font-size:10px">Klasse 10 · Gymnasium</span>
</div><div style="height:28px"></div>`;

// ── URL helpers ───────────────────────────────────────────────────────────────
function resolveUrl(base, rel) {
  try { return new URL(rel, base).href; } catch { return rel; }
}
function wrapUrl(url, base) {
  if (!url) return url;
  const s = url.trim();
  if (s.startsWith('data:') || s.startsWith('blob:') || s.startsWith('javascript:') ||
      s.startsWith('mailto:') || s.startsWith('tel:') || s.startsWith('#')) return s;
  try {
    const r = resolveUrl(base, s);
    if (r.startsWith('http')) return '/proxy?url=' + encodeURIComponent(r);
  } catch {}
  return url;
}
function rewriteSrcset(srcset, base) {
  if (!srcset) return srcset;
  return srcset.split(',').map(p => {
    const parts = p.trim().split(/\s+/);
    if (parts[0]) parts[0] = wrapUrl(parts[0], base);
    return parts.join(' ');
  }).join(', ');
}
function rewriteCss(css, base) {
  if (!css) return css;
  css = css.replace(/url\(\s*(['"]?)([^'")]+)\1\s*\)/gi, (m, q, u) => {
    const t = u.trim();
    if (t.startsWith('data:') || t.startsWith('blob:')) return m;
    return `url('${wrapUrl(t, base)}')`;
  });
  css = css.replace(/@import\s+(['"])([^'"]+)\1/gi, (_m, _q, u) => `@import '${wrapUrl(u, base)}'`);
  return css;
}

// ── Injected script (top of <head>) ──────────────────────────────────────────
// Injected as the FIRST thing in <head> so window.open, fetch, XHR are all
// patched before any page scripts run. Also registers the SW immediately.
function buildHeadScript(baseUrl) {
  const safe = JSON.stringify(baseUrl); // proper JS string escaping
  return `<script>
(function(){
'use strict';
var BASE=${safe};
var OWN=location.origin;

/* toProxy: convert any URL to a proxied URL */
function toProxy(u){
  if(!u)return u;
  var s=String(u).trim();
  if(!s||s.startsWith('#')||s.startsWith('javascript:')||s.startsWith('mailto:')||s.startsWith('data:')||s.startsWith('blob:'))return s;
  if(s.indexOf(OWN+'/proxy?url=')!==-1||s.startsWith('/proxy?url='))return s;
  try{
    var abs=new URL(s,BASE).href;
    if(!abs.startsWith('http'))return s;
    var absO=new URL(abs).origin;
    if(absO===OWN){
      /* same-origin path — map to BASE origin */
      var pu=new URL(abs);
      var target=new URL(pu.pathname+pu.search+pu.hash,new URL(BASE).origin).href;
      return OWN+'/proxy?url='+encodeURIComponent(target);
    }
    return OWN+'/proxy?url='+encodeURIComponent(abs);
  }catch(e){return s;}
}

/* ── 1. Patch window.open FIRST (before any page JS runs) ── */
var _wopen=window.open;
window.open=function(url,tgt,feat){
  return _wopen.call(window,url?toProxy(url):url,tgt,feat);
};

/* ── 2. Patch fetch ── */
var _fetch=window.fetch;
window.fetch=function(input,init){
  try{
    var u=typeof input==='string'?input:(input instanceof Request?input.url:String(input));
    var abs=new URL(u,BASE).href;
    if(abs.startsWith('http')&&new URL(abs).origin!==OWN){
      var pu=OWN+'/proxy?url='+encodeURIComponent(abs);
      input=typeof input==='string'?pu:new Request(pu,{method:input.method,headers:input.headers,body:input.body,mode:'cors',credentials:'include'});
    }
  }catch(e){}
  return _fetch.call(window,input,init);
};

/* ── 3. Patch XMLHttpRequest ── */
var _XHRopen=XMLHttpRequest.prototype.open;
XMLHttpRequest.prototype.open=function(method,url,async,user,pw){
  try{
    var abs=new URL(String(url),BASE).href;
    if(abs.startsWith('http')&&new URL(abs).origin!==OWN)
      url=OWN+'/proxy?url='+encodeURIComponent(abs);
  }catch(e){}
  return _XHRopen.call(this,method,url,async!==false,user,pw);
};

/* ── 4. Patch location.assign / replace ── */
try{
  var _assign =location.assign.bind(location);
  var _replace=location.replace.bind(location);
  Object.defineProperty(location,'assign', {configurable:true,value:function(u){_assign(toProxy(u));}});
  Object.defineProperty(location,'replace',{configurable:true,value:function(u){_replace(toProxy(u));}});
}catch(e){}

/* ── 5. Patch history ── */
function wH(orig){return function(st,ti,url){
  if(url&&typeof url==='string'){var p=toProxy(url);if(p!==url)url=p;}
  return orig.call(history,st,ti,url);
};}
try{history.pushState   =wH(history.pushState);}catch(e){}
try{history.replaceState=wH(history.replaceState);}catch(e){}

/* ── 6. Click interceptor (catches dynamic links) ── */
document.addEventListener('click',function(e){
  var el=e.target;
  while(el&&el.tagName!=='A')el=el.parentElement;
  if(!el||!el.href)return;
  if(el.href.startsWith('#')||el.href.startsWith('javascript:')||el.href.startsWith('mailto:'))return;
  var dest=toProxy(el.href);
  if(dest===el.href)return;
  e.preventDefault();e.stopPropagation();
  if(el.target==='_blank'||el.target==='_new')window.open(dest,'_blank');
  else window.top.location.href=dest;
},true);

/* ── 7. Form submit interceptor ── */
document.addEventListener('submit',function(e){
  var f=e.target;
  var action=f.action||BASE;
  if(action.indexOf(OWN+'/proxy?url=')!==-1||action.startsWith('javascript:'))return;
  var pa=toProxy(action);
  if(pa!==action)f.action=pa;
},true);

/* ── 8. SW registration (no-op if already registered from dashboard) ── */
if('serviceWorker' in navigator){
  navigator.serviceWorker.register('/sw.js',{scope:'/'})
    .then(function(reg){
      if(reg.waiting) reg.waiting.postMessage({type:'SKIP_WAITING'});
      reg.addEventListener('updatefound',function(){
        var nw=reg.installing;
        if(nw) nw.addEventListener('statechange',function(){
          if(nw.state==='installed') nw.postMessage({type:'SKIP_WAITING'});
        });
      });
    }).catch(function(){});

  /* First visit: SW not yet controlling — reload once after SW activates */
  if(!navigator.serviceWorker.controller){
    navigator.serviceWorker.addEventListener('controllerchange',function(){
      window.location.reload();
    });
  }
}

/* ── 9. Panic ── */
try{
  var bc=new BroadcastChannel('opengate');
  bc.onmessage=function(e){if(e.data==='PANIC')window.top.location.href='/decoy';};
}catch(e){}
document.addEventListener('keydown',function(e){
  var tag=document.activeElement&&document.activeElement.tagName;
  if((e.key==='p'||e.key==='P')&&tag!=='INPUT'&&tag!=='TEXTAREA'&&tag!=='SELECT'){
    try{new BroadcastChannel('opengate').postMessage('PANIC');}catch(e){}
    window.top.location.href='/decoy';
  }
});

/* ── 10. Idle redirect ── */
var _ims=parseInt((function(){try{return window.top.localStorage.getItem('idleTimeout');}catch(e){return localStorage.getItem('idleTimeout');}})());
if(_ims&&_ims>0){
  var _it;
  function _ri(){clearTimeout(_it);_it=setTimeout(function(){
    try{new BroadcastChannel('opengate').postMessage('PANIC');}catch(e){}
    window.top.location.href='/decoy';
  },_ims);}
  ['mousemove','keydown','mousedown','touchstart','scroll'].forEach(function(ev){
    document.addEventListener(ev,_ri,{passive:true});
  });
  _ri();
}
})();
</script>`;
}

// ── HTML rewriter ─────────────────────────────────────────────────────────────
function rewriteHtml(html, baseUrl, { noJs, noAd, school }) {
  const $ = cheerio.load(html, { decodeEntities: false });

  // Ensure a <head> exists
  if (!$('head').length) $('html').prepend('<head></head>');

  // 1. Remove existing <base> tags (they break relative URL resolution)
  $('base').remove();

  // 2. Strip SRI — integrity checks always fail on proxied resources
  $('[integrity]').removeAttr('integrity').removeAttr('crossorigin');

  // 3. Inject our script as the very FIRST element in <head>
  //    This ensures window.open/fetch/XHR are patched before any page script runs
  $('head').prepend(buildHeadScript(baseUrl));

  // 4. Compat mode
  if (noJs) {
    $('script').not('#__og_inject__').remove();
    ['onload','onclick','onerror','onmouseover','onmouseout','onfocus','onblur','onsubmit','onchange']
      .forEach(ev => $('['+ev+']').removeAttr(ev));
  }

  // 5. Ad blocker
  if (noAd) {
    AD_SELECTORS.forEach(sel => { try { $(sel).remove(); } catch {} });
    $('script[src]').each((_,el) => { if (AD_SCRIPT_RE.test($(el).attr('src')||'')) $(el).remove(); });
  }

  // 6. Rewrite static attributes
  $('a[href]').each((_,el) => {
    const h=$(el).attr('href');
    if (h&&!h.startsWith('#')&&!h.startsWith('javascript:')&&!h.startsWith('mailto:'))
      $(el).attr('href', wrapUrl(h, baseUrl));
  });
  $('script[src]').each((_,el) => $(el).attr('src', wrapUrl($(el).attr('src'), baseUrl)));
  $('link[href]').each((_,el) => {
    const rel=($(el).attr('rel')||'').toLowerCase();
    if (rel!=='dns-prefetch'&&rel!=='preconnect') $(el).attr('href', wrapUrl($(el).attr('href'), baseUrl));
  });
  $('img[src]').each((_,el) => $(el).attr('src', wrapUrl($(el).attr('src'), baseUrl)));
  $('img[srcset]').each((_,el) => $(el).attr('srcset', rewriteSrcset($(el).attr('srcset'), baseUrl)));
  ['data-src','data-lazy','data-lazy-src','data-original','data-url','data-bg','data-image','data-img','data-echo']
    .forEach(attr => $('['+attr+']').each((_,el) => {
      const v=$(el).attr(attr); if(v&&!v.startsWith('data:')) $(el).attr(attr, wrapUrl(v, baseUrl));
    }));
  $('[data-srcset]').each((_,el) => $(el).attr('data-srcset', rewriteSrcset($(el).attr('data-srcset'), baseUrl)));
  $('source[src]').each((_,el) => $(el).attr('src', wrapUrl($(el).attr('src'), baseUrl)));
  $('source[srcset]').each((_,el) => $(el).attr('srcset', rewriteSrcset($(el).attr('srcset'), baseUrl)));
  $('video[src],audio[src]').each((_,el) => $(el).attr('src', wrapUrl($(el).attr('src'), baseUrl)));
  $('video[poster]').each((_,el) => $(el).attr('poster', wrapUrl($(el).attr('poster'), baseUrl)));
  $('track[src]').each((_,el) => $(el).attr('src', wrapUrl($(el).attr('src'), baseUrl)));
  $('image[href],use[href]').each((_,el) => $(el).attr('href', wrapUrl($(el).attr('href'), baseUrl)));
  $('image,use').each((_,el) => { const xl=$(el).attr('xlink:href'); if(xl) $(el).attr('xlink:href', wrapUrl(xl, baseUrl)); });
  $('input[type="image"][src]').each((_,el) => $(el).attr('src', wrapUrl($(el).attr('src'), baseUrl)));
  $('meta[http-equiv="refresh"]').each((_,el) => {
    const c=$(el).attr('content')||'', m=c.match(/^(\d+;\s*url=)(.+)$/i);
    if (m) $(el).attr('content', m[1]+wrapUrl(m[2].trim(), baseUrl));
  });
  $('form').each((_,el) => {
    const action=$(el).attr('action');
    if (action===undefined||action==='') $(el).attr('action', '/proxy?url='+encodeURIComponent(baseUrl));
    else $(el).attr('action', wrapUrl(action, baseUrl));
  });
  $('iframe[src]').each((_,el) => {
    const src=$(el).attr('src');
    if (src&&!src.startsWith('javascript:')&&!src.startsWith('about:')) $(el).attr('src', wrapUrl(src, baseUrl));
  });
  $('style').each((_,el) => { const css=$(el).html(); if(css) $(el).html(rewriteCss(css, baseUrl)); });
  $('[style]').each((_,el) => { const s=$(el).attr('style'); if(s&&s.includes('url(')) $(el).attr('style', rewriteCss(s, baseUrl)); });

  // 7. Proxy bar (injected at top of <body>)
  const badges = [
    noJs  ? '<span style="color:#ffa500;font-size:10px">⚡COMPAT</span>'  : '',
    noAd  ? '<span style="color:#39ff14;font-size:10px">🛡AD-FREE</span>' : '',
    school? '<span style="color:#7bc8ff;font-size:10px">🏫SCHULM.</span>' : '',
  ].filter(Boolean).join(' ');

  const bar = `${school ? SCHOOL_CSS : ''}
<div id="__og_bar__" style="position:fixed;top:0;left:0;right:0;z-index:2147483647;
  background:#0d0d0d;color:#39ff14;font-family:monospace;font-size:12px;
  padding:5px 14px;display:flex;align-items:center;gap:10px;
  border-bottom:1px solid #39ff1444;box-sizing:border-box">
  <a href="/dashboard" target="_top" style="color:#39ff14;text-decoration:none;font-weight:bold;flex-shrink:0">← Back</a>
  <span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:#aaa;font-size:10px">${baseUrl}</span>
  ${badges}
  <button onclick="document.getElementById('__og_bar__').style.display='none'"
    style="background:none;border:none;color:#4a6070;cursor:pointer;font-size:14px;flex-shrink:0">✕</button>
</div><div style="height:34px"></div>`;

  if ($('body').length) $('body').prepend(bar);
  else $('html').append('<body>'+bar+'</body>');

  return $.html();
}

function rewriteCssFile(css, base) { return rewriteCss(css, base); }

// ── Cookie jar ────────────────────────────────────────────────────────────────
function getDomainCookies(data, uid, domain) { return data.cookieJar?.[uid]?.[domain]||''; }
function storeDomainCookies(data, uid, domain, headers) {
  if (!headers?.length) return;
  if (!data.cookieJar)       data.cookieJar={};
  if (!data.cookieJar[uid])  data.cookieJar[uid]={};
  const ex={};
  (data.cookieJar[uid][domain]||'').split(';').forEach(p=>{ const[k,...v]=p.trim().split('='); if(k)ex[k.trim()]=v.join('=').trim(); });
  headers.forEach(h=>{ const[k,...v]=h.split(';')[0].trim().split('='); if(k)ex[k.trim()]=v.join('=').trim(); });
  data.cookieJar[uid][domain]=Object.entries(ex).map(([k,v])=>`${k}=${v}`).join('; ');
}

// ── Headers to bypass proxy detection ────────────────────────────────────────
// Mimics a real Chrome 124 browser as closely as possible at the HTTP level
function buildUpstreamHeaders(targetUrl, storedCookies, acceptOverride) {
  const parsed = new URL(targetUrl);
  return {
    'User-Agent':         'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
    'Accept':             acceptOverride || 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
    'Accept-Language':    'en-US,en;q=0.9',
    'Accept-Encoding':    'identity',
    'Cache-Control':      'no-cache',
    'Pragma':             'no-cache',
    'Sec-Ch-Ua':          '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
    'Sec-Ch-Ua-Mobile':   '?0',
    'Sec-Ch-Ua-Platform': '"Windows"',
    'Sec-Fetch-Dest':     'document',
    'Sec-Fetch-Mode':     'navigate',
    'Sec-Fetch-Site':     'none',
    'Sec-Fetch-User':     '?1',
    'Upgrade-Insecure-Requests': '1',
    'Referer':            parsed.origin + '/',
    'Origin':             parsed.origin,
    ...(storedCookies && { Cookie: storedCookies }),
  };
}

// Response headers to always strip
const STRIP_HEADERS = new Set([
  'content-security-policy','content-security-policy-report-only',
  'x-frame-options','strict-transport-security','content-encoding',
  'set-cookie','x-content-type-options','cross-origin-opener-policy',
  'cross-origin-embedder-policy','cross-origin-resource-policy',
  'permissions-policy','feature-policy',
]);

// ── Core fetch helper (shared by GET and POST proxy routes) ──────────────────
async function proxyFetch(targetUrl, method, body, contentType, reqHeaders, uid, noJs, noAd, school, res) {
  const parsed = new URL(targetUrl);
  const data   = loadData();
  const stored = getDomainCookies(data, uid, parsed.hostname);
  const agent  = parsed.protocol==='https:' ? new https.Agent({ rejectUnauthorized:false }) : new http.Agent();
  const accept = reqHeaders['x-og-accept'] || undefined;

  const upstreamHeaders = buildUpstreamHeaders(targetUrl, stored, accept);

  const fetchOpts = { method, headers: upstreamHeaders, redirect: 'follow', agent };
  if (body && method !== 'GET' && method !== 'HEAD') {
    fetchOpts.body = body;
    upstreamHeaders['Content-Type'] = contentType || 'application/x-www-form-urlencoded';
    delete upstreamHeaders['Sec-Fetch-Mode'];
    upstreamHeaders['Sec-Fetch-Mode'] = 'cors';
    upstreamHeaders['Sec-Fetch-Site'] = 'same-origin';
    upstreamHeaders['Sec-Fetch-Dest'] = 'empty';
  }

  const upstream = await fetch(targetUrl, fetchOpts);

  // Store cookies
  const rawH    = upstream.headers.raw ? upstream.headers.raw() : {};
  const setCook = rawH['set-cookie']||[];
  if (setCook.length) { storeDomainCookies(data, uid, parsed.hostname, setCook); saveData(data); }

  const finalUrl = upstream.url || targetUrl;
  const ct       = upstream.headers.get('content-type')||'';

  // Set safe response headers
  for (const [k,v] of upstream.headers.entries()) {
    if (!STRIP_HEADERS.has(k.toLowerCase())) try { res.setHeader(k, v); } catch {}
  }
  res.setHeader('content-type', ct);
  // Allow embedding in iframes (dashboard uses these)
  res.setHeader('x-frame-options', 'ALLOWALL');
  // Set og_last cookie so SW can reconstruct relative navigations
  res.setHeader('set-cookie', `og_last=${encodeURIComponent(finalUrl)}; Path=/; SameSite=Lax; Max-Age=3600`);

  if (ct.includes('text/html')) {
    return res.send(rewriteHtml(await upstream.text(), finalUrl, { noJs, noAd, school }));
  }
  if (ct.includes('text/css')) {
    return res.send(rewriteCssFile(await upstream.text(), finalUrl));
  }
  // JS, JSON, binary — pass through
  upstream.body.pipe(res);
}

// ── Proxy OPTIONS (preflight) ─────────────────────────────────────────────────
app.options('/proxy', requireAuth, (req, res) => {
  res.setHeader('Access-Control-Allow-Origin',  req.headers.origin||'*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,x-og-accept,x-og-body');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.sendStatus(204);
});

// ── GET Proxy ─────────────────────────────────────────────────────────────────
app.get('/proxy', requireAuth, async (req, res) => {
  const targetUrl = req.query.url;

  if (!targetUrl) {
    // The SW should have caught this, but if it didn't, try to recover from cookie
    const c = parseCookies(req);
    const last = c.og_last ? decodeURIComponent(c.og_last) : null;
    if (last) return res.redirect('/proxy?url=' + encodeURIComponent(last));
    return res.redirect('/dashboard');
  }

  let parsed;
  try { parsed = new URL(targetUrl); }
  catch { return res.redirect('/dashboard'); }

  const cookies = parseCookies(req);
  const noJs    = req.query.nojs==='1';
  const noAd    = cookies.og_adblock!=='0';
  const school  = cookies.og_school==='1';
  const uid     = cookies.uid||'default';

  try {
    await proxyFetch(targetUrl, 'GET', null, null, req.headers, uid, noJs, noAd, school, res);
  } catch (err) {
    sendProxyError(res, targetUrl, err);
  }
});

// ── POST Proxy (forms + SW-forwarded POST/PUT/PATCH) ──────────────────────────
app.post('/proxy', requireAuth, async (req, res) => {
  // The SW sends the original method in _method query param
  const targetUrl = req.query.url;
  const method    = (req.query._method||'POST').toUpperCase();
  if (!targetUrl) return res.redirect('/dashboard');

  let parsed;
  try { parsed = new URL(targetUrl); }
  catch { return res.redirect('/dashboard'); }

  const cookies = parseCookies(req);
  const noJs    = req.query.nojs==='1';
  const noAd    = cookies.og_adblock!=='0';
  const school  = cookies.og_school==='1';
  const uid     = cookies.uid||'default';

  // Body: prefer x-og-body header (from SW), fall back to urlencoded/json body
  const ct  = req.headers['content-type']||'';
  let body  = req.headers['x-og-body'];
  if (!body) {
    if (ct.includes('application/json')) body = JSON.stringify(req.body);
    else body = Object.entries(req.body||{}).map(([k,v])=>encodeURIComponent(k)+'='+encodeURIComponent(v)).join('&');
  }

  try {
    await proxyFetch(targetUrl, method, body||undefined, ct, req.headers, uid, noJs, noAd, school, res);
  } catch (err) {
    sendProxyError(res, targetUrl, err);
  }
});

// ── Error page ────────────────────────────────────────────────────────────────
function sendProxyError(res, targetUrl, err) {
  const isNet = /ECONNREFUSED|ENOTFOUND|ETIMEDOUT|certificate|getaddrinfo/i.test(err.message);
  res.status(502).send(`<!DOCTYPE html><html><head><title>Proxy Error</title>
    <style>body{background:#080c10;color:#c8d8e8;font-family:monospace;padding:48px 32px;max-width:600px;margin:0 auto}
    h2{color:#ff3b5c}.u{color:#39ff14;font-size:12px;margin:6px 0 22px;word-break:break-all}
    .r{background:#0e1419;border-left:3px solid #ff3b5c;padding:14px;border-radius:6px;font-size:13px;line-height:1.7;color:#e8c0c0}
    ul{margin:16px 0;padding-left:20px;line-height:2;font-size:13px;color:#8aa0b0}
    a{color:#39ff14;border:1px solid #39ff1444;padding:8px 20px;border-radius:6px;text-decoration:none;display:inline-block;margin-top:20px}
    </style></head><body>
    <h2>⚠ Proxy Error</h2><div class="u">${targetUrl||'(no url)'}</div>
    <div class="r">${isNet?'Could not connect — the site may be down, blocking proxies, or behind Cloudflare.':String(err.message).slice(0,300)}</div>
    <ul>
      <li>Enable <b>Compat Mode</b> on the card — strips JS, often fixes issues</li>
      <li>Sites behind Cloudflare or Google actively block proxies</li>
      <li>Try opening in a new tab instead</li>
    </ul>
    <a href="/dashboard" target="_top">← Back to Dashboard</a>
    </body></html>`);
}

// ── Catch-all: bare paths that JS navigation caused ───────────────────────────
// e.g. window.location = '/about' → hits /about on our server
// The SW handles this in navigate mode, but if it somehow gets here, recover.
app.use((req, res, next) => {
  if (isAppPath(req.path)) return next();
  // Try to recover using og_last cookie
  const c = parseCookies(req);
  const last = c.og_last ? decodeURIComponent(c.og_last) : null;
  if (last) {
    try {
      const target = new URL(req.path + (req.url.includes('?') ? '?' + req.url.split('?')[1] : ''), new URL(last).origin).href;
      return res.redirect('/proxy?url=' + encodeURIComponent(target));
    } catch {}
  }
  // No context → dashboard
  res.redirect('/dashboard');
});

// ── Start ─────────────────────────────────────────────────────────────────────
app.listen(PORT, '0.0.0.0', () => {
  console.log(`\n⚡ OpenGate → http://0.0.0.0:${PORT}`);
  console.log(`   Dashboard: /dashboard`);
  console.log(`   Quick key: /?key=${SECRET_KEY}\n`);
});
