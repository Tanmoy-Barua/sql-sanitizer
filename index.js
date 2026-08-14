'use strict';

const { hasSqlInjection, check, normalizeForDetection } = require('./lib/detect');
const { collectValues, collectFromRequest, collectPathSegments } = require('./lib/collect');
const { createMiddleware } = require('./lib/middleware');
const { securityHeaders } = require('./lib/security-headers');
const { sql, sqlQ, looksLikeConcatenatedSql } = require('./lib/safe-sql');

const defaultMiddleware = createMiddleware({ mode: 'block', sensitivity: 'balanced' });

/**
 * Express middleware / factory.
 *
 * @param {object|import('express').Request} [reqOrOptions]
 * @param {import('express').Response} [res]
 * @param {import('express').NextFunction} [next]
 */
function sqlSanitizer(reqOrOptions, res, next) {
  const looksLikeRequest =
    reqOrOptions &&
    typeof reqOrOptions === 'object' &&
    typeof next === 'function' &&
    res &&
    typeof res.status === 'function' &&
    (typeof reqOrOptions.method === 'string' ||
      typeof reqOrOptions.url === 'string' ||
      typeof reqOrOptions.originalUrl === 'string');

  if (looksLikeRequest) {
    return defaultMiddleware(reqOrOptions, res, next);
  }

  return createMiddleware(reqOrOptions || {});
}

sqlSanitizer.hasSqlInjection = hasSqlInjection;
sqlSanitizer.check = check;
sqlSanitizer.normalizeForDetection = normalizeForDetection;
sqlSanitizer.collectValues = collectValues;
sqlSanitizer.collectFromRequest = collectFromRequest;
sqlSanitizer.collectPathSegments = collectPathSegments;
sqlSanitizer.createMiddleware = createMiddleware;
sqlSanitizer.securityHeaders = securityHeaders;
sqlSanitizer.sql = sql;
sqlSanitizer.sqlQ = sqlQ;
sqlSanitizer.looksLikeConcatenatedSql = looksLikeConcatenatedSql;

module.exports = sqlSanitizer;
module.exports.hasSqlInjection = hasSqlInjection;
module.exports.check = check;
module.exports.normalizeForDetection = normalizeForDetection;
module.exports.collectValues = collectValues;
module.exports.collectFromRequest = collectFromRequest;
module.exports.collectPathSegments = collectPathSegments;
module.exports.createMiddleware = createMiddleware;
module.exports.securityHeaders = securityHeaders;
module.exports.sql = sql;
module.exports.sqlQ = sqlQ;
module.exports.looksLikeConcatenatedSql = looksLikeConcatenatedSql;
module.exports.default = sqlSanitizer;
