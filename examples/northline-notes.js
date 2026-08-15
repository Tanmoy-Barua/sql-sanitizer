'use strict';

const express = require('express');
const sqlSanitizer = require('../index.js');
const { sql } = sqlSanitizer;

const app = express();
app.set('trust proxy', 1);
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(sqlSanitizer.securityHeaders());

const protect = sqlSanitizer({
  preset: 'form',
  trustProxy: 1,
  mode: 'block',
  statsRoute: '/__sql-sanitizer/stats',
  onDetection(event) {
    detections.unshift({
      at: event.ts,
      path: event.path,
      field: event.field,
      pattern: event.pattern,
      ip: event.ip,
      sample: event.sample,
    });
    if (detections.length > 30) detections.pop();
  },
});

const detections = [];
const USERS = {
  alice: { password: 'secret', name: 'Alice Nguyen' },
  bob: { password: 'hunter2', name: "Bob O'Brien" },
};
/** @type {Array<{id:number, author:string, text:string, at:string}>} */
const notes = [
  {
    id: 1,
    author: 'alice',
    text: 'Ship checklist for Friday release',
    at: new Date().toISOString(),
  },
];
let noteId = 2;
const sessions = new Map();

function fakeDb(queryText, values) {
  // Toy "DB" using parameterized values only (never concat).
  if (queryText.includes('FROM users WHERE username')) {
    const [username, password] = values;
    const user = USERS[username];
    if (user && user.password === password) {
      return { rows: [{ username, name: user.name }] };
    }
    return { rows: [] };
  }
  return { rows: [] };
}

function page(body) {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Northline Notes</title>
  <link rel="preconnect" href="https://fonts.googleapis.com" />
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
  <link href="https://fonts.googleapis.com/css2?family=Fraunces:opsz,wght@9..144,600;9..144,700&family=Source+Sans+3:wght@400;600;700&display=swap" rel="stylesheet" />
  <style>
    :root {
      --ink: #1a2420;
      --muted: #5b6b63;
      --line: #d5e0d9;
      --ok: #1f6f54;
      --bad: #9b2c2c;
      --panel: rgba(255,255,255,0.82);
      --bg: #eef4f0;
      font-family: "Source Sans 3", "Segoe UI", sans-serif;
      color: var(--ink);
    }
    * { box-sizing: border-box; }
    body {
      margin: 0; min-height: 100vh;
      background:
        radial-gradient(900px 420px at 0% 0%, #cfe8da 0%, transparent 55%),
        radial-gradient(800px 380px at 100% 0%, #d7e3f4 0%, transparent 50%),
        linear-gradient(165deg, #f3f7f4, #f7f3ea);
    }
    .wrap { max-width: 980px; margin: 0 auto; padding: 28px 18px 64px; }
    header { display: flex; justify-content: space-between; align-items: baseline; gap: 12px; margin-bottom: 22px; }
    .brand { font-family: Fraunces, Georgia, serif; font-size: clamp(1.6rem, 3vw, 2.1rem); letter-spacing: -0.03em; margin: 0; }
    .tag { color: var(--muted); margin: 0; }
    .grid { display: grid; gap: 14px; grid-template-columns: 1.1fr 0.9fr; }
    @media (max-width: 860px) { .grid { grid-template-columns: 1fr; } }
    .panel {
      background: var(--panel); border: 1px solid rgba(26,36,32,0.08);
      border-radius: 16px; padding: 18px; backdrop-filter: blur(8px);
    }
    h2 { margin: 0 0 10px; font-size: 1.05rem; }
    label { display:block; font-size: 0.85rem; color: var(--muted); margin: 0 0 6px; }
    input, textarea {
      width: 100%; margin-bottom: 12px; padding: 11px 12px; border-radius: 10px;
      border: 1px solid #b7c7be; font: inherit; background: #fff;
    }
    textarea { min-height: 88px; resize: vertical; }
    button, .btn {
      border: 0; border-radius: 10px; padding: 10px 14px; font: inherit; font-weight: 600;
      cursor: pointer; color: #fff; background: var(--ok); display: inline-block; text-decoration: none;
    }
    button.ghost { background: #2d3d35; }
    button.bad { background: var(--bad); }
    .row { display: flex; flex-wrap: wrap; gap: 8px; }
    .note {
      border-top: 1px solid var(--line); padding: 10px 0;
    }
    .note:first-child { border-top: 0; }
    .meta { color: var(--muted); font-size: 0.85rem; }
    .banner {
      display: none; margin: 0 0 14px; padding: 10px 12px; border-radius: 10px; font-weight: 600;
    }
    .banner.show { display: block; }
    .banner.ok { background: #d8f0e4; color: var(--ok); }
    .banner.bad { background: #f7dede; color: var(--bad); }
    pre {
      margin: 0; background: #122018; color: #d8f4e4; border-radius: 12px; padding: 12px;
      white-space: pre-wrap; word-break: break-word; min-height: 120px; font-size: 0.9rem;
    }
    .pill { display:inline-block; padding: 2px 8px; border-radius: 999px; background: #e5eee9; font-size: 0.8rem; }
  </style>
</head>
<body>
  <div class="wrap">
    ${body}
  </div>
</body>
</html>`;
}

app.get('/', (_req, res) => {
  res.type('html').send(
    page(`
    <header>
      <div>
        <h1 class="brand">Northline Notes</h1>
        <p class="tag">A small real app protected by <strong>sql-sanitizer</strong></p>
      </div>
      <span class="pill">live demo</span>
    </header>
    <div id="banner" class="banner"></div>
    <div class="grid">
      <section class="panel">
        <h2>Team login</h2>
        <form id="loginForm">
          <label for="username">Username</label>
          <input id="username" name="username" value="alice" autocomplete="username" />
          <label for="password">Password</label>
          <input id="password" name="password" type="password" value="secret" autocomplete="current-password" />
          <div class="row">
            <button type="submit">Sign in</button>
            <button type="button" class="bad" id="attackBtn">Try SQLi attack</button>
            <button type="button" class="ghost" id="obrienBtn">Login as Bob O'Brien path</button>
          </div>
        </form>
        <p class="meta" style="margin-top:12px">Attack fills <code>admin' OR '1'='1</code>. Middleware should stop it before SQL runs.</p>
      </section>
      <section class="panel">
        <h2>Live server response</h2>
        <pre id="out">Sign in to use the notes board.</pre>
      </section>
    </div>
    <section class="panel" style="margin-top:14px">
      <h2>Notes board <span class="meta" id="sessionMeta">(signed out)</span></h2>
      <form id="noteForm" style="display:none">
        <label for="note">New note</label>
        <textarea id="note" placeholder="Write a note…"></textarea>
        <div class="row">
          <button type="submit">Post note</button>
          <button type="button" class="ghost" id="refreshBtn">Refresh</button>
          <button type="button" class="ghost" id="logoutBtn">Log out</button>
        </div>
      </form>
      <div id="notes"></div>
    </section>
    <script>
      const out = document.getElementById('out');
      const banner = document.getElementById('banner');
      const notesEl = document.getElementById('notes');
      const noteForm = document.getElementById('noteForm');
      const sessionMeta = document.getElementById('sessionMeta');
      let token = localStorage.getItem('nl_token') || '';

      function showBanner(ok, text) {
        banner.className = 'banner show ' + (ok ? 'ok' : 'bad');
        banner.textContent = text;
      }
      function setOut(data) {
        out.textContent = typeof data === 'string' ? data : JSON.stringify(data, null, 2);
      }
      async function api(path, options={}) {
        const headers = Object.assign({ 'Content-Type': 'application/json' }, options.headers || {});
        if (token) headers['x-session'] = token;
        const res = await fetch(path, { ...options, headers });
        const text = await res.text();
        let json; try { json = JSON.parse(text); } catch { json = text; }
        return { status: res.status, json };
      }
      async function refreshNotes() {
        const r = await api('/api/notes');
        if (r.status !== 200) {
          notesEl.innerHTML = '<p class="meta">Sign in to load notes.</p>';
          return;
        }
        notesEl.innerHTML = (r.json.notes || []).map(n =>
          '<div class="note"><div class="meta">' + n.author + ' · ' + new Date(n.at).toLocaleString() + '</div><div>' +
          n.text.replace(/</g,'&lt;') + '</div></div>'
        ).join('') || '<p class="meta">No notes yet.</p>';
      }
      function signedIn(user) {
        token = user.token;
        localStorage.setItem('nl_token', token);
        sessionMeta.textContent = '(signed in as ' + user.username + ')';
        noteForm.style.display = 'block';
        refreshNotes();
      }
      function signedOut() {
        token = '';
        localStorage.removeItem('nl_token');
        sessionMeta.textContent = '(signed out)';
        noteForm.style.display = 'none';
        notesEl.innerHTML = '';
      }

      document.getElementById('attackBtn').onclick = () => {
        document.getElementById('username').value = "admin' OR '1'='1";
        document.getElementById('password').value = 'x';
        showBanner(false, 'Attack credentials filled — click Sign in');
        setOut('Ready to send SQLi payload to /api/login');
      };
      document.getElementById('obrienBtn').onclick = () => {
        document.getElementById('username').value = 'bob';
        document.getElementById('password').value = 'hunter2';
        showBanner(true, "Bob's display name contains an apostrophe (O'Brien) — login itself is clean");
      };
      document.getElementById('loginForm').onsubmit = async (e) => {
        e.preventDefault();
        const payload = {
          username: document.getElementById('username').value,
          password: document.getElementById('password').value,
        };
        const r = await api('/api/login', { method: 'POST', body: JSON.stringify(payload) });
        setOut(r);
        if (r.status === 403) {
          showBanner(false, 'Blocked by sql-sanitizer (HTTP 403) — request never reached the database');
          return;
        }
        if (r.status === 200 && r.json.ok) {
          showBanner(true, 'Signed in successfully');
          signedIn(r.json);
        } else {
          showBanner(false, 'Login failed');
        }
      };
      document.getElementById('noteForm').onsubmit = async (e) => {
        e.preventDefault();
        const text = document.getElementById('note').value;
        const r = await api('/api/notes', { method: 'POST', body: JSON.stringify({ text }) });
        setOut(r);
        if (r.status === 403) {
          showBanner(false, 'Note blocked by sql-sanitizer');
          return;
        }
        if (r.status === 200) {
          document.getElementById('note').value = '';
          showBanner(true, 'Note saved');
          refreshNotes();
        }
      };
      document.getElementById('refreshBtn').onclick = refreshNotes;
      document.getElementById('logoutBtn').onclick = () => { signedOut(); showBanner(true, 'Signed out'); setOut('Signed out'); };
      if (token) {
        api('/api/me').then(r => {
          if (r.status === 200) signedIn({ token, username: r.json.username });
          else signedOut();
        });
      }
    </script>
  `)
  );
});

app.post('/api/login', protect, (req, res) => {
  const username = String((req.body && req.body.username) || '');
  const password = String((req.body && req.body.password) || '');
  const q = sql`SELECT username, name FROM users WHERE username = ${username} AND password = ${password}`;
  const result = fakeDb(q.text, q.values);
  if (!result.rows.length) {
    return res.status(401).json({ ok: false, message: 'Invalid credentials', query: q });
  }
  const token = 'sess_' + Math.random().toString(36).slice(2);
  sessions.set(token, result.rows[0].username);
  return res.json({
    ok: true,
    token,
    username: result.rows[0].username,
    name: result.rows[0].name,
    query: q,
  });
});

function requireSession(req, res, next) {
  const token = req.headers['x-session'];
  const username = token && sessions.get(String(token));
  if (!username) return res.status(401).json({ error: 'Unauthorized' });
  req.user = username;
  next();
}

app.get('/api/me', requireSession, (req, res) => {
  res.json({ username: req.user, name: USERS[req.user].name });
});

app.get('/api/notes', protect, requireSession, (_req, res) => {
  res.json({ notes });
});

app.post('/api/notes', protect, requireSession, (req, res) => {
  const text = String((req.body && req.body.text) || '').trim();
  if (!text) return res.status(400).json({ error: 'Empty note' });
  const item = { id: noteId++, author: req.user, text, at: new Date().toISOString() };
  notes.unshift(item);
  res.json({ ok: true, note: item });
});

app.get('/api/detections', (_req, res) => {
  res.json({ detections, stats: protect.stats });
});

const port = Number(process.env.PORT) || 4050;
if (require.main === module) {
  app.listen(port, '0.0.0.0', () => {
    console.log(`Northline Notes (real app demo) at http://127.0.0.1:${port}`);
  });
}

module.exports = app;
