'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const express = require('express');
const sqlSanitizer = require('../index.js');

function listen(app) {
  return new Promise((resolve) => {
    const server = http.createServer(app);
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      resolve({ server, port });
    });
  });
}

function request(port, { method = 'GET', path = '/', headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request(
      { hostname: '127.0.0.1', port, path, method, headers },
      (res) => {
        let data = '';
        res.setEncoding('utf8');
        res.on('data', (chunk) => {
          data += chunk;
        });
        res.on('end', () => {
          let json = null;
          try {
            json = data ? JSON.parse(data) : null;
          } catch {
            json = data;
          }
          resolve({ status: res.statusCode, body: json, headers: res.headers });
        });
      }
    );
    req.on('error', reject);
    if (body !== undefined) req.write(body);
    req.end();
  });
}

function postJson(port, path, obj) {
  const body = JSON.stringify(obj);
  return request(port, {
    method: 'POST',
    path,
    headers: {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(body),
    },
    body,
  });
}

describe('modes: block / detect / monitor', () => {
  it('block mode returns 403', async () => {
    const app = express();
    app.use(sqlSanitizer({ mode: 'block' }));
    app.get('/x', (_req, res) => res.json({ ok: true }));
    const { server, port } = await listen(app);
    try {
      const res = await request(port, { path: "/x?q=1'%20OR%20'1'%3D'1" });
      assert.equal(res.status, 403);
    } finally {
      server.close();
    }
  });

  it('detect mode logs/calls hook but still allows request', async () => {
    const events = [];
    const app = express();
    app.use(
      sqlSanitizer({
        mode: 'detect',
        onDetection: (event) => events.push(event),
      })
    );
    app.get('/x', (_req, res) => res.json({ ok: true }));
    const { server, port } = await listen(app);
    try {
      const res = await request(port, { path: "/x?q=1'%20OR%20'1'%3D'1" });
      assert.equal(res.status, 200);
      assert.equal(events.length, 1);
      assert.equal(events[0].mode, 'detect');
      assert.equal(typeof events[0].pattern, 'string');
    } finally {
      server.close();
    }
  });

  it('monitor mode attaches req.sqlSanitizer and allows request', async () => {
    const app = express();
    const mw = sqlSanitizer({ mode: 'monitor' });
    app.use(mw);
    app.get('/x', (req, res) => res.json({ flag: req.sqlSanitizer }));
    const { server, port } = await listen(app);
    try {
      const res = await request(port, { path: "/x?q=1'%20OR%20'1'%3D'1" });
      assert.equal(res.status, 200);
      assert.equal(res.body.flag.detected, true);
      assert.equal(mw.stats.detections >= 1, true);
    } finally {
      server.close();
    }
  });
});

describe('structured logging + onDetection', () => {
  it('sends structured payload to logger.warn', async () => {
    const lines = [];
    const app = express();
    app.use(
      sqlSanitizer({
        mode: 'detect',
        logger: { warn: (payload) => lines.push(payload) },
      })
    );
    app.get('/x', (_req, res) => res.json({ ok: true }));
    const { server, port } = await listen(app);
    try {
      await request(port, { path: "/x?q='%20union%20select" });
      assert.equal(lines.length, 1);
      assert.equal(lines[0].msg, 'sql-sanitizer detection');
      assert.equal(typeof lines[0].field, 'string');
      assert.equal(typeof lines[0].ts, 'string');
    } finally {
      server.close();
    }
  });
});

describe('allowlists', () => {
  it('allowRoutes skips matching paths', async () => {
    const app = express();
    app.use(express.json());
    app.use(sqlSanitizer({ allowRoutes: ['/webhooks'] }));
    app.post('/webhooks/stripe', (_req, res) => res.json({ ok: true }));
    app.post('/login', (_req, res) => res.json({ ok: true }));
    const { server, port } = await listen(app);
    try {
      const allowed = await postJson(port, '/webhooks/stripe', { note: "O'Brien" });
      assert.equal(allowed.status, 200);
      const blocked = await postJson(port, '/login', { note: "O'Brien" });
      assert.equal(blocked.status, 403);
    } finally {
      server.close();
    }
  });

  it('allowFields skips configured fields', async () => {
    const app = express();
    app.use(express.json());
    app.use(sqlSanitizer({ allowFields: ['bio'] }));
    app.post('/profile', (_req, res) => res.json({ ok: true }));
    const { server, port } = await listen(app);
    try {
      const allowed = await postJson(port, '/profile', { bio: "O'Brien likes SQL", name: 'Ann' });
      assert.equal(allowed.status, 200);
      const blocked = await postJson(port, '/profile', { about: "O'Brien" });
      assert.equal(blocked.status, 403);
    } finally {
      server.close();
    }
  });
});

describe('modern body coverage', () => {
  it('detects SQLi inside GraphQL query body', async () => {
    const app = express();
    app.use(express.json());
    app.use(sqlSanitizer());
    app.post('/graphql', (_req, res) => res.json({ data: {} }));
    const { server, port } = await listen(app);
    try {
      const res = await postJson(port, '/graphql', {
        query: "{ user(id: \"1' OR '1'='1\") { id } }",
        variables: {},
      });
      assert.equal(res.status, 403);
    } finally {
      server.close();
    }
  });

  it('detects SQLi in nested JSON paths', async () => {
    const app = express();
    app.use(express.json());
    app.use(sqlSanitizer());
    app.post('/data', (_req, res) => res.json({ ok: true }));
    const { server, port } = await listen(app);
    try {
      const res = await postJson(port, '/data', { user: { profile: { note: "1' OR '1'='1" } } });
      assert.equal(res.status, 403);
    } finally {
      server.close();
    }
  });

  it('scans multipart-like file originalname on req.files', async () => {
    const app = express();
    app.use((req, _res, next) => {
      req.files = {
        avatar: {
          fieldname: 'avatar',
          mimetype: 'image/png',
          buffer: Buffer.from([1, 2, 3]),
          originalname: "evil' OR '1'='1.png",
        },
      };
      next();
    });
    app.use(sqlSanitizer());
    app.post('/upload', (_req, res) => res.json({ ok: true }));
    const { server, port } = await listen(app);
    try {
      const res = await request(port, { method: 'POST', path: '/upload' });
      assert.equal(res.status, 403);
    } finally {
      server.close();
    }
  });
});

describe('rate limiting', () => {
  it('returns 429 after max detections from same client in block mode', async () => {
    const mw = sqlSanitizer({
      mode: 'block',
      rateLimit: { windowMs: 60_000, max: 2 },
      clientKey: () => 'test-client',
    });
    const app = express();
    app.use(mw);
    app.get('/x', (_req, res) => res.json({ ok: true }));
    const { server, port } = await listen(app);
    try {
      assert.equal((await request(port, { path: "/x?q='" })).status, 403);
      assert.equal((await request(port, { path: "/x?q='" })).status, 403);
      const limited = await request(port, { path: "/x?q='" });
      assert.equal(limited.status, 429);
      assert.equal(mw.stats.rateLimited >= 1, true);
    } finally {
      server.close();
    }
  });
});

describe('security headers', () => {
  it('sets baseline headers', async () => {
    const app = express();
    app.use(sqlSanitizer.securityHeaders());
    app.get('/', (_req, res) => res.json({ ok: true }));
    const { server, port } = await listen(app);
    try {
      const res = await request(port, { path: '/' });
      assert.equal(res.status, 200);
      assert.equal(res.headers['x-frame-options'], 'SAMEORIGIN');
      assert.equal(res.headers['x-content-type-options'], 'nosniff');
      assert.equal(res.headers['referrer-policy'], 'no-referrer');
    } finally {
      server.close();
    }
  });
});

describe('ESM export surface', () => {
  it('createMiddleware and check are available', () => {
    assert.equal(typeof sqlSanitizer.createMiddleware, 'function');
    assert.equal(typeof sqlSanitizer.check, 'function');
    assert.equal(typeof sqlSanitizer.securityHeaders, 'function');
  });
});
