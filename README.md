# sql-sanitizer

Express middleware that **detects common SQL injection patterns** in the request URL, query string, route params, body (including nested JSON / GraphQL), and multipart filenames — then **blocks**, **detects**, or **monitors** them.

> **Honest positioning:** this is a heuristic request filter, **not** a sanitizer and **not** a replacement for parameterized queries / prepared statements. Use both.

## Installation

```bash
npm install sql-sanitizer
```

Requires Express 4+ (peer dependency). Node 14+.

## Quick start

```js
const express = require('express');
const sqlSanitizer = require('sql-sanitizer');

const app = express();
app.use(express.json());
app.use(sqlSanitizer.securityHeaders()); // optional companion
app.use(sqlSanitizer); // block mode by default

app.listen(4000);
```

ESM:

```js
import sqlSanitizer, { check, securityHeaders } from 'sql-sanitizer';
```

## Modes

| Mode | Behavior |
|------|----------|
| `block` (default) | Respond `403` (or `429` if rate-limited) |
| `detect` | Log / call `onDetection`, then `next()` |
| `monitor` | Like detect, and set `req.sqlSanitizer` + expose `middleware.stats` |

```js
app.use(sqlSanitizer({
  mode: 'detect', // try dry-run before enforcing
  logger: console,
  onDetection(event) {
    // structured event: ts, path, ip, field, pattern, sample, ...
  },
}));
```

## Allowlists

```js
app.use(sqlSanitizer({
  allowRoutes: ['/webhooks', /^\/health/],
  allowFields: ['bio', 'search'], // also matches user.bio
}));
```

## Rate limiting

Counts SQLi-like detections per client (IP by default):

```js
app.use(sqlSanitizer({
  mode: 'block',
  rateLimit: { windowMs: 60_000, max: 10 },
}));
```

After `max` detections in the window, further hits return **429**.

## What it checks

- `req.originalUrl` / `req.url`
- `req.query`, `req.params`
- `req.body` (nested objects/arrays, GraphQL `query` / `variables`)
- `req.files` filenames (multer-style)
- optional `req.rawBody`

Mount **after** body parsers (`express.json()`, `urlencoded`, multer, etc.).

## API

### `check(value)` / `hasSqlInjection(value)`

```js
const { check, hasSqlInjection } = require('sql-sanitizer');

check("1' OR '1'='1");
// { detected: true, pattern: 'sql_meta', value: "1' OR '1'='1" }

hasSqlInjection('hello'); // false
```

### `securityHeaders([options])`

Small optional header helper (`X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, …).

### TypeScript

Types ship via `index.d.ts`.

## Limitations

- False positives are possible (names with `'`, comments with `--`, etc.). Use allowlists.
- Attackers can craft bypasses; keep using parameterized SQL.
- `req.params` is only populated when this middleware runs on a matched route (URL text is still scanned via `originalUrl`).

## License

MIT
