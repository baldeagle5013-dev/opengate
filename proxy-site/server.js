const express = require('express');
const fetch = require('node-fetch');
const cheerio = require('cheerio');
const fs = require('fs');
const path = require('path');
const https = require('https');
const http = require('http');

const app = express();
const PORT = process.env.PORT || 3000;
const SITES_FILE = path.join(__dirname, 'sites.json');

// ── Middleware ────────────────────────────────────────────────────────────────
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ── Sites storage helpers ─────────────────────────────────────────────────────
function loadSites() {
  if (!fs.existsSync(SITES_FILE)) {
    const defaults = [
      { id: 1, name: 'Wikipedia', url: 'https://en.wikipedia.org', icon: '📚' },
      { id: 2, name: 'Khan Academy', url: 'https://www.khanacademy.org', icon: '🎓' },
      { id: 3, name: 'GitHub', url: 'https://github.com', icon: '🐙' },
    ];
    fs.writeFileSync(SITES_FILE, JSON.stringify(defaults, null, 2));
    return defaults;
  }
  return JSON.parse(fs.readFileSync(SITES_FILE, 'utf8'));
}

function saveSites(sites) {
  fs.writeFileSync(SITES_FILE, JSON.stringify(sites, null, 2));
}

// ── Sites API ─────────────────────────────────────────────────────────────────
app.get('/api/sites', (req, res) => {
  res.json(loadSites());
});

app.post('/api/sites', (req, res) => {
  const { name, url, icon } = req.body;
  if (!name || !url) return res.status(400).json({ error: 'Name and URL required' });

  const sites = loadSites();
  const newSite = {
    id: Date.now(),
    name: name.trim(),
    url: url.startsWith('http') ? url.trim() : 'https://' + url.trim(),
    icon: icon || '🌐',
  };
  sites.push(newSite);
  saveSites(sites);
  res.json(newSite);
});

app.delete('/api/sites/:id', (req, res) => {
  const sites = loadSites().filter(s => s.id !== parseInt(req.params.id));
  saveSites(sites);
  res.json({ ok: true });
});

// ── Proxy engine ──────────────────────────────────────────────────────────────

// Resolve a potentially-relative URL against a base
function resolveUrl(base, relative) {
  try {
    return new URL(relative, base).href;
  } catch {
    return relative;
  }
}

// Rewrite a URL so it routes through our /proxy endpoint
function wrapUrl(targetUrl, baseUrl) {
  try {
    const resolved = resolveUrl(baseUrl, targetUrl);
    if (resolved.startsWith('http://') || resolved.startsWith('https://')) {
      return '/proxy?url=' + encodeURIComponent(resolved);
    }
  } catch {}
  return targetUrl;
}

// Rewrite HTML so all links/resources go through the proxy
function rewriteHtml(html, baseUrl) {
  const $ = cheerio.load(html, { decodeEntities: false });

  // Links & redirects
  $('a[href]').each((_, el) => {
    const href = $(el).attr('href');
    if (href && !href.startsWith('#') && !href.startsWith('javascript:') && !href.startsWith('mailto:')) {
      $(el).attr('href', wrapUrl(href, baseUrl));
    }
  });

  // Scripts
  $('script[src]').each((_, el) => {
    $(el).attr('src', wrapUrl($(el).attr('src'), baseUrl));
  });

  // Stylesheets
  $('link[rel="stylesheet"][href]').each((_, el) => {
    $(el).attr('href', wrapUrl($(el).attr('href'), baseUrl));
  });

  // Images
  $('img[src]').each((_, el) => {
    $(el).attr('src', wrapUrl($(el).attr('src'), baseUrl));
  });
  $('img[srcset]').each((_, el) => {
    const srcset = $(el).attr('srcset').split(',').map(s => {
      const parts = s.trim().split(/\s+/);
      if (parts[0]) parts[0] = wrapUrl(parts[0], baseUrl);
      return parts.join(' ');
    }).join(', ');
    $(el).attr('srcset', srcset);
  });

  // Forms
  $('form[action]').each((_, el) => {
    $(el).attr('action', wrapUrl($(el).attr('action'), baseUrl));
  });

  // iframes
  $('iframe[src]').each((_, el) => {
    $(el).attr('src', wrapUrl($(el).attr('src'), baseUrl));
  });

  // Meta refresh
  $('meta[http-equiv="refresh"]').each((_, el) => {
    const content = $(el).attr('content') || '';
    const match = content.match(/^(\d+;\s*url=)(.+)$/i);
    if (match) {
      $(el).attr('content', match[1] + wrapUrl(match[2], baseUrl));
    }
  });

  // Inject a small banner so you know you're proxied
  $('body').prepend(`
    <div id="__proxy_bar__" style="
      position:fixed;top:0;left:0;right:0;z-index:2147483647;
      background:#0d0d0d;color:#39ff14;font-family:monospace;font-size:12px;
      padding:5px 14px;display:flex;align-items:center;justify-content:space-between;
      border-bottom:1px solid #39ff1444;box-shadow:0 2px 12px #39ff1422;
    ">
      <span>⚡ PROXIED: <b style="color:#fff">${baseUrl}</b></span>
      <a href="/" style="color:#39ff14;text-decoration:none;font-weight:bold;">← Dashboard</a>
    </div>
    <div style="height:32px"></div>
  `);

  return $.html();
}

// Rewrite CSS urls() to go through proxy
function rewriteCss(css, baseUrl) {
  return css.replace(/url\(['"]?([^'")]+)['"]?\)/g, (match, url) => {
    if (url.startsWith('data:')) return match;
    return `url('${wrapUrl(url, baseUrl)}')`;
  });
}

// Main proxy route
app.get('/proxy', async (req, res) => {
  const targetUrl = req.query.url;
  if (!targetUrl) return res.status(400).send('Missing ?url= parameter');

  let parsedUrl;
  try {
    parsedUrl = new URL(targetUrl);
  } catch {
    return res.status(400).send('Invalid URL');
  }

  try {
    const agent = parsedUrl.protocol === 'https:'
      ? new https.Agent({ rejectUnauthorized: false })
      : new http.Agent();

    const response = await fetch(targetUrl, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'identity',
        'Referer': parsedUrl.origin,
      },
      redirect: 'follow',
      agent,
    });

    const contentType = response.headers.get('content-type') || '';

    // Strip security headers that break framing/proxying
    const skipHeaders = ['content-security-policy', 'x-frame-options', 'strict-transport-security', 'content-encoding'];
    for (const [key, value] of response.headers.entries()) {
      if (!skipHeaders.includes(key.toLowerCase())) {
        try { res.setHeader(key, value); } catch {}
      }
    }
    res.setHeader('content-type', contentType);

    if (contentType.includes('text/html')) {
      const html = await response.text();
      res.send(rewriteHtml(html, response.url || targetUrl));
    } else if (contentType.includes('text/css')) {
      const css = await response.text();
      res.send(rewriteCss(css, response.url || targetUrl));
    } else {
      // Binary / other — pipe straight through
      response.body.pipe(res);
    }
  } catch (err) {
    console.error('Proxy error:', err.message);
    res.status(502).send(`
      <html><body style="background:#0d0d0d;color:#ff4444;font-family:monospace;padding:40px">
        <h2>⚠ Proxy Error</h2>
        <p>${err.message}</p>
        <p><a href="/" style="color:#39ff14">← Back to Dashboard</a></p>
      </body></html>
    `);
  }
});

// ── Start ─────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n⚡ Proxy Dashboard running → http://localhost:${PORT}\n`);
});
