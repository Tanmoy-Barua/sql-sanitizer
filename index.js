'use strict';

const { hasSqlInjection, check } = require('./lib/detect');
const { collectValues, collectFromRequest } = require('./lib/collect');
const { createMiddleware } = require('./lib/middleware');
const { securityHeaders } = require('./lib/security-headers');

const defaultMiddleware = createMiddleware({ mode: 'block' });

/**
 * Express middleware / factory.
 *
 * Usage:
 *   app.use(sqlSanitizer)
 *   app.use(sqlSanitizer())
 *   app.use(sqlSanitizer({ mode: 'detect', allowFields: ['bio'] }))
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
sqlSanitizer.collectValues = collectValues;
sqlSanitizer.collectFromRequest = collectFromRequest;
sqlSanitizer.createMiddleware = createMiddleware;
sqlSanitizer.securityHeaders = securityHeaders;

module.exports = sqlSanitizer;
module.exports.hasSqlInjection = hasSqlInjection;
module.exports.check = check;
module.exports.collectValues = collectValues;
module.exports.collectFromRequest = collectFromRequest;
module.exports.createMiddleware = createMiddleware;
module.exports.securityHeaders = securityHeaders;
module.exports.default = sqlSanitizer;
