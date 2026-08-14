'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { hasSqlInjection, collectValues } = require('../index.js');

describe('hasSqlInjection', () => {
  it('returns false for nullish and empty values', () => {
    assert.equal(hasSqlInjection(null), false);
    assert.equal(hasSqlInjection(undefined), false);
    assert.equal(hasSqlInjection(''), false);
  });

  it('returns false for benign strings', () => {
    assert.equal(hasSqlInjection('hello'), false);
    assert.equal(hasSqlInjection('user-123'), false);
    assert.equal(hasSqlInjection('/api/users?limit=10'), false);
  });

  it('detects SQL meta characters', () => {
    assert.equal(hasSqlInjection("O'Brien"), true);
    assert.equal(hasSqlInjection('1--'), true);
    assert.equal(hasSqlInjection('topic#drop'), true);
    assert.equal(hasSqlInjection('%27or%201'), true);
  });

  it('detects equals followed by SQL meta', () => {
    assert.equal(hasSqlInjection("id=1'"), true);
    assert.equal(hasSqlInjection('x=1;'), true);
  });

  it('detects classic OR injection (\\w* fix)', () => {
    assert.equal(hasSqlInjection("1'or'1'='1"), true);
    assert.equal(hasSqlInjection("admin' OR '1'='1"), true);
    assert.equal(hasSqlInjection("x'or'y"), true);
  });

  it('detects union-based patterns', () => {
    assert.equal(hasSqlInjection("'union"), true);
    assert.equal(hasSqlInjection("' UNION SELECT"), true);
    assert.equal(hasSqlInjection('1) UNION SELECT username FROM users'), true);
  });
});

describe('collectValues', () => {
  it('flattens nested objects and arrays', () => {
    const out = [];
    collectValues({ a: 1, nested: { b: "ok", list: ['x', 2] } }, out);
    assert.deepEqual(out.sort(), ['1', '2', 'a', 'b', 'list', 'nested', 'ok', 'x'].sort());
  });
});
