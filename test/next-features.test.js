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
      resolve({ server, port: server.address().port });
    });
  });
}

function request(port, { method = 'GET', path = '/', headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ hostname: '127.0.0.1', port, path, method, headers }, (res) => {
      let data = '';
      res.setEncoding('utf8');
      res.on('data', (c) => (data += c));
      res.on('end', () => {
        let json = data;
        try {
          json = data ? JSON.parse(data) : null;
        } catch (_e) {
          /* keep text */
        }
        resolve({ status: res.statusCode, body: json, headers: res.headers, text: data });
      });
    });
    req.on('error', reject);
    if (body !== undefined) req.write(body);
    req.end();
  });
}

describe('1) framework adapters', () => {
  it('exports fastify, koa, and nest adapters', () => {
    assert.equal(typeof sqlSanitizer.fastify, 'function');
    assert.equal(typeof sqlSanitizer.fastifyPlugin, 'function');
    assert.equal(typeof sqlSanitizer.koa, 'function');
    assert.equal(typeof sqlSanitizer.nest, 'function');
  });

  it('nest adapter blocks SQLi like Express middleware', async () => {
    const app = express();
    app.use(sqlSanitizer.nest({ mode: 'block' }));
    app.get('/x', (_req, res) => res.json({ ok: true }));
    const { server, port } = await listen(app);
    try {
      const bad = await request(port, { path: "/x?q=1'%20OR%20'1'%3D'1" });
      assert.equal(bad.status, 403);
      const good = await request(port, { path: '/x?q=hello' });
      assert.equal(good.status, 200);
    } finally {
      server.close();
    }
  });

  it('koa adapter blocks and allows correctly', async () => {
    const mw = sqlSanitizer.koa({ mode: 'block' });
    const calls = [];
    const ctxAllow = {
      originalUrl: '/ok',
      url: '/ok',
      path: '/ok',
      query: { q: 'hello' },
      params: {},
      headers: {},
      ip: '127.0.0.1',
      request: { body: undefined, headers: {} },
      req: { socket: { remoteAddress: '127.0.0.1' } },
      status: 0,
      body: null,
    };
    await mw(ctxAllow, async () => {
      calls.push('next');
    });
    assert.deepEqual(calls, ['next']);

    const ctxBlock = {
      ...ctxAllow,
      originalUrl: "/x?q=1'%20OR%20'1'%3D'1",
      url: "/x?q=1'%20OR%20'1'%3D'1",
      path: '/x',
      query: { q: "1' OR '1'='1" },
      status: 0,
      body: null,
    };
    await mw(ctxBlock, async () => {
      calls.push('should-not-run');
    });
    assert.equal(ctxBlock.status, 403);
    assert.equal(calls.includes('should-not-run'), false);
  });
});

describe('2) presets', () => {
  it('applies form preset allowFields for bio', async () => {
    const app = express();
    app.use(express.json());
    app.use(sqlSanitizer({ preset: 'form' }));
    app.post('/p', (_req, res) => res.json({ ok: true }));
    const { server, port } = await listen(app);
    try {
      const body = JSON.stringify({ bio: "O'Brien" });
      const res = await request(port, {
        method: 'POST',
        path: '/p',
        headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
        body,
      });
      assert.equal(res.status, 200);
      assert.equal(sqlSanitizer.getPreset('graphql').sensitivity, 'strict');
    } finally {
      server.close();
    }
  });
});

describe('3) stats dashboard + prometheus', () => {
  it('serves JSON stats and prometheus text', async () => {
    const mw = sqlSanitizer({
      mode: 'block',
      statsRoute: '/__sql-sanitizer/stats',
      statsToken: 'secret',
    });
    const app = express();
    app.use(mw);
    app.get('/x', (_req, res) => res.json({ ok: true }));
    const { server, port } = await listen(app);
    try {
      await request(port, { path: "/x?q=1'%20OR%20'1'%3D'1" });
      const denied = await request(port, { path: '/__sql-sanitizer/stats' });
      assert.equal(denied.status, 401);
      const ok = await request(port, {
        path: '/__sql-sanitizer/stats',
        headers: { 'x-sql-sanitizer-token': 'secret' },
      });
      assert.equal(ok.status, 200);
      assert.equal(ok.body.stats.detections >= 1, true);

      const prom = await request(port, {
        path: '/__sql-sanitizer/stats?format=prometheus',
        headers: { 'x-sql-sanitizer-token': 'secret' },
      });
      assert.equal(prom.status, 200);
      assert.match(prom.text, /sql_sanitizer_detections_total/);
      assert.match(mw.prometheus(), /sql_sanitizer_blocked_total/);
    } finally {
      server.close();
    }
  });
});

describe('4) CI concat scanner', () => {
  it('detects unsafe SQL concatenation samples', () => {
    const findings = sqlSanitizer.scanContent(
      'demo.js',
      'const q = "SELECT * FROM users WHERE id = " + userId;\n'
    );
    assert.ok(findings.length >= 1);
    assert.equal(findings[0].pattern, 'plus_concat_sql');
  });

  it('flags template literal SQL interpolation', () => {
    const findings = sqlSanitizer.scanContent(
      'demo.js',
      'const q = `SELECT * FROM users WHERE name = \'${name}\'`;\n'
    );
    assert.ok(findings.some((f) => f.pattern === 'template_sql_interpolation'));
  });
});

describe('5) trusted proxy / client IP', () => {
  it('ignores spoofed X-Forwarded-For when trustProxy is false', () => {
    const ip = sqlSanitizer.resolveClientIp(
      {
        headers: { 'x-forwarded-for': '1.2.3.4' },
        socket: { remoteAddress: '10.0.0.8' },
      },
      { trustProxy: false }
    );
    assert.equal(ip, '10.0.0.8');
  });

  it('uses cf-connecting-ip when trustProxy is enabled', () => {
    const ip = sqlSanitizer.resolveClientIp(
      {
        headers: {
          'cf-connecting-ip': '203.0.113.9',
          'x-forwarded-for': '1.2.3.4',
        },
        socket: { remoteAddress: '10.0.0.8' },
      },
      { trustProxy: true }
    );
    assert.equal(ip, '203.0.113.9');
  });
});
