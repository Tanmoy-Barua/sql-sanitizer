'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { hasSqlInjection, check, normalizeForDetection } = require('../index.js');

describe('balanced detection (default) — fewer false positives', () => {
  it('allows common legitimate apostrophe / hyphen text', () => {
    assert.equal(hasSqlInjection("O'Brien"), false);
    assert.equal(hasSqlInjection('2020--2021'), false);
    assert.equal(hasSqlInjection('C#'), false);
    assert.equal(hasSqlInjection('hello-world'), false);
    assert.equal(hasSqlInjection('/api/users?limit=10'), false);
  });

  it('still catches classic injection payloads', () => {
    assert.equal(hasSqlInjection("1' OR '1'='1"), true);
    assert.equal(hasSqlInjection("admin' OR '1'='1"), true);
    assert.equal(hasSqlInjection("admin'--"), true);
    assert.equal(hasSqlInjection("' UNION SELECT username FROM users"), true);
    assert.equal(hasSqlInjection('1) UNION SELECT username FROM users'), true);
    assert.equal(hasSqlInjection("1; DROP TABLE users"), true);
    assert.equal(hasSqlInjection('1 OR 1=1'), true);
  });

  it('catches obfuscated / encoded bypass attempts', () => {
    assert.equal(hasSqlInjection("1%27%20OR%20%271%27%3D%271"), true);
    assert.equal(hasSqlInjection('1%2527%20OR%20%25271'), true); // double-encoded '
    assert.equal(hasSqlInjection('1/**/OR/**/1=1'), true);
    assert.equal(hasSqlInjection('UNI/**/ON SEL/**/ECT 1'), true);
    assert.equal(check("1'%20or%20'1'='1").detected, true);
  });

  it('normalizeForDetection decodes and strips comment tricks', () => {
    const n = normalizeForDetection('UNI/**/ON%20SELECT');
    assert.match(n.toLowerCase().replace(/\s+/g, ''), /unionselect/);
  });
});

describe('sensitivity modes', () => {
  it('paranoid flags bare apostrophes like the old behavior', () => {
    assert.equal(hasSqlInjection("O'Brien", { sensitivity: 'paranoid' }), true);
    assert.equal(hasSqlInjection('topic#drop', { sensitivity: 'paranoid' }), true);
  });

  it('strict catches comment+keyword but not bare O\'Brien', () => {
    assert.equal(hasSqlInjection("O'Brien", { sensitivity: 'strict' }), false);
    assert.equal(hasSqlInjection('-- select password', { sensitivity: 'strict' }), true);
  });
});

describe('check() API', () => {
  it('returns structured result', () => {
    const ok = check('safe');
    assert.equal(ok.detected, false);
    assert.equal(ok.pattern, null);
    const bad = check("1' OR '1'='1");
    assert.equal(bad.detected, true);
    assert.equal(typeof bad.pattern, 'string');
  });
});
