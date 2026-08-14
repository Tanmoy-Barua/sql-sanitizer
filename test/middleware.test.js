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
      {
        hostname: '127.0.0.1',
        port,
        path,
        method,
        headers,
      },
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
    if (body !== undefined) {
      req.write(body);
    }
    req.end();
  });
}

describe('sqlSanitizer middleware (compat)', () => {
  it('allows clean GET requests with bare export', async () => {
    const app = express();
    app.use(sqlSanitizer);
    app.get('/ok', (_req, res) => res.status(200).json({ ok: true }));

    const { server, port } = await listen(app);
    try {
      const res = await request(port, { path: '/ok?name=alice' });
      assert.equal(res.status, 200);
      assert.deepEqual(res.body, { ok: true });
    } finally {
      server.close();
    }
  });

  it('rejects SQL injection in the query string', async () => {
    const app = express();
    app.use(sqlSanitizer);
    app.get('/ok', (_req, res) => res.status(200).json({ ok: true }));

    const { server, port } = await listen(app);
    try {
      const res = await request(port, { path: "/ok?q=1'%20OR%20'1'%3D'1" });
      assert.equal(res.status, 403);
      assert.equal(res.body.error, 'SQL injection detected in request');
    } finally {
      server.close();
    }
  });

  it('rejects SQL injection in path segments even with app-level middleware', async () => {
    const app = express();
    // Path segments are scanned without waiting for Express to populate req.params.
    app.use(sqlSanitizer);
    app.get('/users/:id', (_req, res) => res.status(200).json({ ok: true }));

    const { server, port } = await listen(app);
    try {
      const res = await request(port, { path: "/users/1'%20OR%20'1'%3D'1" });
      assert.equal(res.status, 403);
    } finally {
      server.close();
    }
  });

  it('rejects SQL injection in JSON body when body parser runs first', async () => {
    const app = express();
    app.use(express.json());
    app.use(sqlSanitizer);
    app.post('/login', (_req, res) => res.status(200).json({ ok: true }));

    const { server, port } = await listen(app);
    try {
      const payload = JSON.stringify({ username: "admin' OR '1'='1", password: 'x' });
      const res = await request(port, {
        method: 'POST',
        path: '/login',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(payload),
        },
        body: payload,
      });
      assert.equal(res.status, 403);
    } finally {
      server.close();
    }
  });

  it('allows clean JSON body', async () => {
    const app = express();
    app.use(express.json());
    app.use(sqlSanitizer);
    app.post('/login', (req, res) => res.status(200).json({ user: req.body.username }));

    const { server, port } = await listen(app);
    try {
      const payload = JSON.stringify({ username: 'alice', password: 'secret' });
      const res = await request(port, {
        method: 'POST',
        path: '/login',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(payload),
        },
        body: payload,
      });
      assert.equal(res.status, 200);
      assert.deepEqual(res.body, { user: 'alice' });
    } finally {
      server.close();
    }
  });
});
