'use strict';

const express = require('express');
const sqlSanitizer = require('./index.js');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(sqlSanitizer.securityHeaders());

const detections = [];
const protectedMw = sqlSanitizer({
  mode: 'block',
  allowRoutes: ['/webhooks'],
  allowFields: ['bio'],
  rateLimit: { windowMs: 60_000, max: 5 },
  logger: {
    warn(payload) {
      detections.unshift(payload);
      if (detections.length > 20) detections.pop();
    },
  },
  onDetection(event) {
    // hook available for SIEM/webhooks in real apps
  },
});

app.use((req, res, next) => {
  // only protect API-ish routes via middleware below where mounted
  next();
});

const USERS = {
  alice: { password: 'secret', role: 'user' },
  admin: { password: 'adminpass', role: 'admin' },
};

function unsafeLookup(username, password) {
  const fakeSql =
    "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
  const bypass = /'\s*or\s+'/i.test(username) || /'\s*or\s+'/i.test(password);
  if (bypass) {
    return { fakeSql, hacked: true, user: { username: 'admin', role: 'admin' } };
  }
  const user = USERS[username];
  if (user && user.password === password) {
    return { fakeSql, hacked: false, user: { username, role: user.role } };
  }
  return { fakeSql, hacked: false, user: null };
}

app.get('/', (_req, res) => {
  res.type('html').send(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>sql-sanitizer feature demo</title>
  <style>
    :root { font-family: "IBM Plex Sans", "Segoe UI", sans-serif; color: #14231c; }
    body { margin: 0; min-height: 100vh; background: linear-gradient(160deg,#e8f1ec,#f7f3ea 55%,#e7eef7); }
    main { max-width: 960px; margin: 0 auto; padding: 36px 16px 64px; }
    h1 { margin: 0 0 8px; letter-spacing: -0.03em; }
    .lead { color: #4d6358; margin: 0 0 20px; line-height: 1.5; }
    .grid { display: grid; gap: 12px; grid-template-columns: repeat(auto-fit,minmax(200px,1fr)); margin-bottom: 14px; }
    button { border: 0; border-radius: 8px; padding: 12px; font: inherit; cursor: pointer; color: #fff; background: #1f6f54; text-align: left; }
    button.bad { background: #8b2e2e; }
    button.alt { background: #2d3d35; }
    pre { background: #122018; color: #d8f4e4; border-radius: 12px; padding: 14px; min-height: 220px; white-space: pre-wrap; }
    .badge { display: inline-block; margin-bottom: 10px; padding: 4px 10px; border-radius: 999px; background: #e4ebe6; font-size: 0.85rem; font-weight: 600; }
  </style>
</head>
<body>
  <main>
    <h1>sql-sanitizer live features</h1>
    <p class="lead">Proof of protection + new options: modes, allowlists, GraphQL body scan, rate limit, security headers.</p>
    <div class="grid">
      <button id="clean">1. Normal login (200)</button>
      <button id="attack" class="bad">2. SQLi login → blocked (403)</button>
      <button id="unsafe" class="bad">3. Same attack unprotected (bypass)</button>
      <button id="allowField" class="alt">4. allowFields bio (200)</button>
      <button id="graphql" class="bad">5. GraphQL SQLi (403)</button>
      <button id="headers" class="alt">6. Security headers</button>
      <button id="detect" class="alt">7. detect mode (allow + log)</button>
      <button id="stats" class="alt">8. Show detection log / stats</button>
    </div>
    <div id="badge" class="badge">Ready</div>
    <pre id="out">Click a button to run a live check.</pre>
  </main>
  <script>
    const out = document.getElementById('out');
    const badge = document.getElementById('badge');
    function show(title, data) {
      badge.textContent = title;
      out.textContent = typeof data === 'string' ? data : JSON.stringify(data, null, 2);
    }
    async function call(path, options) {
      const res = await fetch(path, options);
      const text = await res.text();
      let json; try { json = JSON.parse(text); } catch { json = text; }
      return { status: res.status, json, headers: Object.fromEntries(res.headers.entries()) };
    }
    document.getElementById('clean').onclick = async () => {
      const r = await call('/login', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ username:'alice', password:'secret' }) });
      show('Normal login → HTTP ' + r.status, r);
    };
    document.getElementById('attack').onclick = async () => {
      const r = await call('/login', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ username:"admin' OR '1'='1", password:'x' }) });
      show('Protected SQLi → HTTP ' + r.status, r);
    };
    document.getElementById('unsafe').onclick = async () => {
      const r = await call('/unsafe-login', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ username:"admin' OR '1'='1", password:'x' }) });
      show('Unprotected SQLi → HTTP ' + r.status, r);
    };
    document.getElementById('allowField').onclick = async () => {
      const r = await call('/profile', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ bio:"O'Brien loves databases", name:'Ann' }) });
      show('allowFields bio → HTTP ' + r.status, r);
    };
    document.getElementById('graphql').onclick = async () => {
      const r = await call('/graphql', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ query: "{ user(id: \\"1' OR '1'='1\\") { id } }" }) });
      show('GraphQL SQLi → HTTP ' + r.status, r);
    };
    document.getElementById('headers').onclick = async () => {
      const r = await call('/headers-check');
      show('Security headers → HTTP ' + r.status, { status: r.status, headers: {
        'x-frame-options': r.headers['x-frame-options'],
        'x-content-type-options': r.headers['x-content-type-options'],
        'referrer-policy': r.headers['referrer-policy']
      }});
    };
    document.getElementById('detect').onclick = async () => {
      const r = await call('/detect-demo?q=' + encodeURIComponent("1' OR '1'='1"));
      show('detect mode → HTTP ' + r.status + ' (not blocked)', r);
    };
    document.getElementById('stats').onclick = async () => {
      const r = await call('/stats');
      show('Stats / recent detections', r.json);
    };
  </script>
</body>
</html>`);
});

app.post('/login', protectedMw, (req, res) => {
  const result = unsafeLookup(req.body.username || '', req.body.password || '');
  if (!result.user) return res.status(401).json({ ok: false, protected: true });
  return res.json({ ok: true, protected: true, user: result.user });
});

app.post('/unsafe-login', (req, res) => {
  const result = unsafeLookup(req.body.username || '', req.body.password || '');
  if (result.hacked) {
    return res.json({ ok: true, protected: false, hacked: true, user: result.user, sqlExecuted: result.fakeSql });
  }
  if (!result.user) return res.status(401).json({ ok: false, protected: false });
  return res.json({ ok: true, protected: false, hacked: false, user: result.user });
});

app.post('/profile', protectedMw, (req, res) => {
  res.json({ ok: true, saved: req.body });
});

app.post('/graphql', protectedMw, (req, res) => {
  res.json({ data: { ok: true } });
});

app.get('/headers-check', (_req, res) => {
  res.json({ ok: true });
});

app.get(
  '/detect-demo',
  sqlSanitizer({
    mode: 'detect',
    onDetection(event) {
      detections.unshift({ ...event, via: 'detect-demo' });
    },
  }),
  (req, res) => {
    res.json({ ok: true, mode: 'detect', message: 'Request allowed; detection logged' });
  }
);

app.get('/stats', (_req, res) => {
  res.json({
    middlewareStats: protectedMw.stats,
    recentDetections: detections.slice(0, 5),
  });
});

app.post('/webhooks/stripe', protectedMw, (req, res) => {
  res.json({ ok: true, allowRoute: true, body: req.body });
});

const port = Number(process.env.PORT) || 4000;
app.listen(port, '0.0.0.0', () => {
  console.log(`Feature demo at http://127.0.0.1:${port}`);
});
