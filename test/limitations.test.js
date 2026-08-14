'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { sql, sqlQ, looksLikeConcatenatedSql, collectPathSegments } = require('../index.js');

describe('parameterized sql helpers', () => {
  it('sql`...` builds $n placeholders', () => {
    const id = 7;
    const name = "O'Brien";
    const q = sql`SELECT * FROM users WHERE id = ${id} AND name = ${name}`;
    assert.equal(q.text, 'SELECT * FROM users WHERE id = $1 AND name = $2');
    assert.deepEqual(q.values, [7, "O'Brien"]);
    assert.equal(q.dialect, 'pg');
  });

  it('sqlQ`...` builds ? placeholders', () => {
    const q = sqlQ`SELECT * FROM users WHERE id = ${42}`;
    assert.equal(q.text, 'SELECT * FROM users WHERE id = ?');
    assert.deepEqual(q.values, [42]);
  });

  it('looksLikeConcatenatedSql flags unsafe construction samples', () => {
    const unsafeSource = 'SELECT * FROM users WHERE name = \'" + userInput + "\'';
    assert.equal(looksLikeConcatenatedSql(unsafeSource), true);
    assert.equal(looksLikeConcatenatedSql('SELECT * FROM users WHERE id = $1'), false);
  });
});

describe('path segment collection', () => {
  it('extracts decoded path segments without req.params', () => {
    const out = [];
    collectPathSegments(
      {
        originalUrl: "/users/1'%20OR%20'1'%3D'1/profile",
      },
      out
    );
    assert.ok(out.some((item) => item.path.startsWith('path[')));
    assert.ok(out.some((item) => /or/i.test(item.value) || item.value.includes("'")));
  });
});
