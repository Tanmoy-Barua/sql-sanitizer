'use strict';

/**
 * Example: Express + MySQL/SQLite-style placeholders (sqlQ`...`).
 * Run: node examples/express-mysql.js
 */
const express = require('express');
const sqlSanitizer = require('../index.js');
const { sqlQ } = sqlSanitizer;

const app = express();
app.use(express.json());
app.use(sqlSanitizer({ preset: 'api' }));

async function dbQuery(text, values) {
  return { text, values, rows: [{ ok: true }] };
}

app.get('/products/:sku', async (req, res) => {
  const q = sqlQ`SELECT * FROM products WHERE sku = ${req.params.sku}`;
  res.json(await dbQuery(q.text, q.values));
});

if (require.main === module) {
  app.listen(4011, () => console.log('express-mysql example on http://127.0.0.1:4011'));
}

module.exports = app;
