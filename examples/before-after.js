'use strict';

/**
 * Before vs after: unsafe concat login vs protected + parameterized query.
 * Run: node examples/before-after.js
 */
const express = require('express');
const sqlSanitizer = require('../index.js');
const { sql } = sqlSanitizer;

function buildUnsafeApp() {
  const app = express();
  app.use(express.json());
  // BEFORE: no middleware, string concat
  app.post('/login', (req, res) => {
    const username = req.body.username || '';
    const password = req.body.password || '';
    const unsafe =
      "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
    const bypassed = /'\s*or\s+'/i.test(username);
    res.json({
      mode: 'before',
      sql: unsafe,
      hacked: bypassed,
      user: bypassed ? { username: 'admin', role: 'admin' } : null,
    });
  });
  return app;
}

function buildSafeApp() {
  const app = express();
  app.use(express.json());
  app.use(sqlSanitizer({ preset: 'api' }));
  // AFTER: middleware + parameterized SQL
  app.post('/login', (req, res) => {
    const q = sql`SELECT * FROM users WHERE username = ${req.body.username} AND password = ${req.body.password}`;
    res.json({ mode: 'after', query: q, hacked: false });
  });
  return app;
}

async function demo() {
  const unsafe = buildUnsafeApp();
  const safe = buildSafeApp();
  const http = require('http');

  function listen(app) {
    return new Promise((resolve) => {
      const s = http.createServer(app);
      s.listen(0, '127.0.0.1', () => resolve({ s, port: s.address().port }));
    });
  }

  const attack = JSON.stringify({ username: "admin' OR '1'='1", password: 'x' });
  const u = await listen(unsafe);
  const a = await listen(safe);

  const before = await fetch(`http://127.0.0.1:${u.port}/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: attack,
  }).then((r) => r.json());

  const after = await fetch(`http://127.0.0.1:${a.port}/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: attack,
  }).then(async (r) => ({ status: r.status, body: await r.json() }));

  console.log('BEFORE (vulnerable):', before);
  console.log('AFTER (protected):', after);

  u.s.close();
  a.s.close();
}

if (require.main === module) {
  demo().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}

module.exports = { buildUnsafeApp, buildSafeApp };
