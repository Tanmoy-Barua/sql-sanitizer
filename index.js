'use strict';

// Heuristic patterns inspired by common SQLi signature checks.
// These are not a substitute for parameterized queries.
const SQL_META = /(%27)|(')|(--)|(%23)|(#)/i;
const SQL_META_WITH_EQUALS = /((%3D)|(=))[^\n]*((%27)|(')|(--)|(%3B)|(;))/i;
// Fixed: was `w*` (literal w) instead of `\w*` (word characters).
const SQL_OR = /\w*((%27)|('))((%6F)|o|(%4F))((%72)|r|(%52))/i;
const SQL_UNION = /((%27)|('))union/i;
const SQL_UNION_SELECT = /\bunion\b[\s/%*+\w]*\bselect\b/i;

/**
 * @param {unknown} value
 * @returns {boolean}
 */
function hasSqlInjection(value) {
  if (value === null || value === undefined) {
    return false;
  }

  const text = typeof value === 'string' ? value : String(value);
  if (!text) {
    return false;
  }

  return (
    SQL_META.test(text) ||
    SQL_META_WITH_EQUALS.test(text) ||
    SQL_OR.test(text) ||
    SQL_UNION.test(text) ||
    SQL_UNION_SELECT.test(text)
  );
}

/**
 * Recursively collect stringifiable values from objects/arrays.
 * @param {unknown} input
 * @param {string[]} out
 */
function collectValues(input, out) {
  if (input === null || input === undefined) {
    return;
  }

  const type = typeof input;
  if (type === 'string' || type === 'number' || type === 'boolean') {
    out.push(String(input));
    return;
  }

  if (Array.isArray(input)) {
    for (const item of input) {
      collectValues(item, out);
    }
    return;
  }

  if (type === 'object') {
    for (const key of Object.keys(input)) {
      out.push(key);
      collectValues(input[key], out);
    }
  }
}

/**
 * Express middleware that rejects requests matching SQLi heuristics.
 * Mount after body parsers (e.g. express.json()) so req.body is populated.
 *
 * @param {import('express').Request} req
 * @param {import('express').Response} res
 * @param {import('express').NextFunction} next
 */
function middleware(req, res, next) {
  const message = { error: 'SQL injection detected in request' };
  const candidates = [];

  if (typeof req.originalUrl === 'string' && req.originalUrl) {
    candidates.push(req.originalUrl);
  } else if (typeof req.url === 'string' && req.url) {
    candidates.push(req.url);
  }

  collectValues(req.query, candidates);
  collectValues(req.params, candidates);
  collectValues(req.body, candidates);

  for (const value of candidates) {
    if (hasSqlInjection(value)) {
      return res.status(403).json(message);
    }
  }

  return next();
}

module.exports = middleware;
module.exports.hasSqlInjection = hasSqlInjection;
module.exports.collectValues = collectValues;
