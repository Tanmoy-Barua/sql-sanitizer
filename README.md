# sql-sanitizer

Express middleware that **detects common SQL injection patterns** in the request URL, path segments, query string, route params, body (nested JSON / GraphQL), and multipart filenames — then **blocks**, **detects**, or **monitors** them.

It also ships a small **parameterized SQL helper** (`sql` / `sqlQ`) so apps can stop string-concatenating queries.

## Installation

```bash
npm install sql-sanitizer
```

Requires Express 4+ (peer dependency). Node 14+.

## Quick start

```js
const express = require('express');
const sqlSanitizer = require('sql-sanitizer');
const { sql } = sqlSanitizer;

const app = express();
app.use(express.json());
app.use(sqlSanitizer.securityHeaders());
app.use(sqlSanitizer); // balanced + block by default

app.get('/users/:id', async (req, res) => {
  // Real protection at the DB layer:
  const q = sql`SELECT * FROM users WHERE id = ${req.params.id}`;
  // db.query(q.text, q.values)
  res.json({ query: q });
});
```

## Solving common pain points

### Fewer false positives
Default `sensitivity: 'balanced'` does **not** block normal text like `O'Brien` or `2020--2021`.  
Use `strict` or `paranoid` only if you want noisier matching.

```js
app.use(sqlSanitizer({ sensitivity: 'balanced' })); // default
app.use(sqlSanitizer({ sensitivity: 'paranoid' })); // legacy bare ', #, --
```

### Harder bypasses
Inputs are normalized before matching (URL decoding, `/**/` comment stripping), and high-signal patterns cover OR/UNION/stacked queries, time-based probes, and more.

### Path params without route-level mount
Path segments are scanned from the URL itself, so app-level `app.use(sqlSanitizer)` still catches `/users/1' OR '1'='1` even before Express fills `req.params`.

### Parameterized queries (the real fix)
Middleware is a filter. Safe SQL is still required:

```js
const { sql, sqlQ } = require('sql-sanitizer');

sql`SELECT * FROM users WHERE email = ${email}`;
// -> { text: 'SELECT * FROM users WHERE email = $1', values: [email], dialect: 'pg' }

sqlQ`SELECT * FROM users WHERE email = ${email}`;
// -> { text: 'SELECT * FROM users WHERE email = ?', values: [email], dialect: 'mysql' }
```

## Modes

| Mode | Behavior |
|------|----------|
| `block` (default) | Respond `403` (or `429` if rate-limited) |
| `detect` | Log / call `onDetection`, then `next()` |
| `monitor` | Like detect, plus `req.sqlSanitizer` and `middleware.stats` |

## Options

```js
app.use(sqlSanitizer({
  mode: 'block',
  sensitivity: 'balanced',
  allowRoutes: ['/webhooks'],
  allowFields: ['bio'],
  rateLimit: { windowMs: 60_000, max: 10 },
  logger: console,
  onDetection(event) { /* SIEM / Slack */ },
}));
```

## What it checks

- `originalUrl` / `url`
- decoded **path segments** (covers route params early)
- `query`, `params`, nested `body` (GraphQL included)
- `files` filenames (multer-style)
- optional `rawBody`

Mount after body parsers.

## License

MIT
