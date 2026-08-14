# sql-sanitizer

Express middleware that **detects common SQL injection patterns** in the request URL, query string, route params, and body, then responds with **403**.

> Note: despite the package name, this does **not** sanitize or escape SQL. It only applies heuristic pattern matching. Prefer parameterized queries / prepared statements as your primary defense.

## Installation

```bash
npm install sql-sanitizer
```

Requires Express 4+ (peer dependency).

## Usage

Mount **after** body parsers so `req.body` is available:

```js
const express = require('express');
const sqlSanitizer = require('sql-sanitizer');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(sqlSanitizer);

app.post('/login', (req, res) => {
  res.status(200).json({ ok: true });
});

app.get('/users/:id', (req, res) => {
  res.status(200).json({ ok: true });
});

app.listen(4000);
```

## What it checks

- `req.originalUrl` / `req.url` (covers path + query string text)
- `req.query`
- `req.params` (populated when this middleware is mounted on the matched route)
- `req.body` (nested objects/arrays are walked; requires a body parser first)

Matched requests receive:

```json
{ "error": "SQL injection detected in request" }
```

## Limitations

- Heuristic regex detection can produce **false positives** (for example values containing `'` or `--`).
- Attackers can still craft payloads that bypass signature checks.
- This middleware is a **supplement**, not a replacement for safe database access patterns.

## API

```js
const sqlSanitizer = require('sql-sanitizer');
const { hasSqlInjection } = require('sql-sanitizer');

hasSqlInjection("1' OR '1'='1"); // true
```

## License

MIT
