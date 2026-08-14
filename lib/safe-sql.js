'use strict';

/**
 * Build a parameterized query from a tagged template.
 * This is the real fix for SQL injection at the database layer.
 *
 * @example
 * const { text, values } = sql`SELECT * FROM users WHERE id = ${id}`;
 * // text: "SELECT * FROM users WHERE id = $1"
 * // values: [id]
 *
 * @param {TemplateStringsArray} strings
 * @param {...unknown} values
 * @returns {{ text: string, values: unknown[], dialect: 'pg' }}
 */
function sql(strings, ...values) {
  if (!strings || !Array.isArray(strings.raw || strings)) {
    throw new TypeError('sql`...` must be used as a tagged template');
  }

  let text = '';
  const params = [];
  for (let i = 0; i < strings.length; i += 1) {
    text += strings[i];
    if (i < values.length) {
      params.push(values[i]);
      text += `$${params.length}`;
    }
  }

  return { text, values: params, dialect: 'pg' };
}

/**
 * Same as sql`...` but uses `?` placeholders (mysql / sqlite style).
 * @param {TemplateStringsArray} strings
 * @param {...unknown} values
 * @returns {{ text: string, values: unknown[], dialect: 'mysql' }}
 */
function sqlQ(strings, ...values) {
  if (!strings || !Array.isArray(strings.raw || strings)) {
    throw new TypeError('sqlQ`...` must be used as a tagged template');
  }

  let text = '';
  const params = [];
  for (let i = 0; i < strings.length; i += 1) {
    text += strings[i];
    if (i < values.length) {
      params.push(values[i]);
      text += '?';
    }
  }

  return { text, values: params, dialect: 'mysql' };
}

/**
 * Reject classic unsafe string-concat SQL construction.
 * Returns true when the string looks like concatenated dynamic SQL.
 * @param {string} query
 */
function looksLikeConcatenatedSql(query) {
  if (typeof query !== 'string' || !query) {
    return false;
  }
  // Heuristic: quotes wrapping interpolated-looking fragments already in a full statement.
  return (
    /\b(select|insert|update|delete|drop)\b[\s\S]{0,200}('|")\s*\+|^\s*('|")[\s\S]*\+\s*('|")/i.test(
      query
    ) || /\+\s*['"][\s\S]*\b(select|from|where)\b/i.test(query)
  );
}

module.exports = {
  sql,
  sqlQ,
  looksLikeConcatenatedSql,
};
