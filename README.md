# sql-sanitizer

[![npm version](https://img.shields.io/npm/v/sql-sanitizer.svg)](https://www.npmjs.com/package/sql-sanitizer)
[![node](https://img.shields.io/node/v/sql-sanitizer.svg)](https://nodejs.org)
[![CI](https://github.com/Tanmoy-Barua/sql-sanitizer/actions/workflows/ci.yml/badge.svg)](https://github.com/Tanmoy-Barua/sql-sanitizer/actions/workflows/ci.yml)
[![license](https://img.shields.io/npm/l/sql-sanitizer.svg)](./LICENSE)

SQL injection **request filter** for **Express / Fastify / Koa / Nest**, with presets, stats/Prometheus, a CI concat scanner, and parameterized `sql` / `sqlQ` helpers.

> Heuristic middleware is a supplement — always use parameterized queries for real safety.

## Install

```bash
npm install sql-sanitizer
```

## Quick start (Express)

```js
const express = require('express');
const sqlSanitizer = require('sql-sanitizer');
const { sql } = sqlSanitizer;

const app = express();
app.set('trust proxy', 1);
app.use(express.json());
app.use(sqlSanitizer({
  preset: 'api',
  trustProxy: 1,
  statsRoute: '/__sql-sanitizer/stats',
}));

app.get('/users/:id', async (req, res) => {
  const q = sql`SELECT * FROM users WHERE id = ${req.params.id}`;
  res.json(q);
});
```

## Adapters

```js
// Fastify
fastify.addHook('preHandler', sqlSanitizer.fastify({ preset: 'api' }));
// or: await fastify.register(sqlSanitizer.fastifyPlugin({ preset: 'graphql' }));

// Koa
app.use(sqlSanitizer.koa({ preset: 'form' }));

// NestJS (Express adapter)
consumer.apply(sqlSanitizer.nest({ preset: 'api' })).forRoutes('*');
```

## Presets

| Preset | Intent |
|--------|--------|
| `api` | Balanced API defaults + rate limit |
| `form` | Allows common free-text fields (`bio`, `comment`, …) |
| `graphql` | Stricter sensitivity for GraphQL bodies |

## Stats & Prometheus

```js
const mw = sqlSanitizer({ statsRoute: '/__sql-sanitizer/stats', statsToken: 'secret' });
app.use(mw);
// GET /__sql-sanitizer/stats  (header x-sql-sanitizer-token: secret)
// GET /__sql-sanitizer/stats?format=prometheus
mw.prometheus(); // text exposition
```

## CI scanner

```bash
npx sql-sanitizer scan .
npx sql-sanitizer scan ./src --json
```

Exit code `2` when potential unsafe SQL concatenation is found.

## Trusted proxy

```js
sqlSanitizer({ trustProxy: false }); // ignore X-Forwarded-For (anti-spoof)
sqlSanitizer({ trustProxy: 1 });     // one proxy hop
sqlSanitizer({ trustProxy: true });  // trust CDN / XFF / CF-Connecting-IP
```

## Examples

See [`examples/`](./examples) — Postgres-style, MySQL-style, and before/after demo.

## Changelog

See [CHANGELOG.md](./CHANGELOG.md).

## License

MIT
