'use strict';

/**
 * Example: Express + parameterized Postgres-style queries (sql`...`).
 * Run: node examples/express-postgres.js
 */
const express = require('express');
const sqlSanitizer = require('../index.js');
const { sql } = sqlSanitizer;

const app = express();
app.set('trust proxy', 1);
app.use(express.json());
app.use(
  sqlSanitizer({
    preset: 'api',
    trustProxy: 1,
    statsRoute: '/__sql-sanitizer/stats',
  })
);

// Fake DB driver for the demo
async function dbQuery(text, values) {
  return { text, values, rows: [{ id: values[0], name: 'demo' }] };
}

app.get('/users/:id', async (req, res) => {
  const q = sql`SELECT id, name FROM users WHERE id = ${req.params.id}`;
  const result = await dbQuery(q.text, q.values);
  res.json({ ok: true, query: result });
});

app.post('/login', async (req, res) => {
  const q = sql`SELECT id FROM users WHERE email = ${req.body.email} AND password_hash = ${req.body.password}`;
  const result = await dbQuery(q.text, q.values);
  res.json({ ok: true, query: result });
});

if (require.main === module) {
  app.listen(4010, () => console.log('express-postgres example on http://127.0.0.1:4010'));
}

module.exports = app;
