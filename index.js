'use strict';

const { hasSqlInjection, check, normalizeForDetection } = require('./lib/detect');
const { collectValues, collectFromRequest, collectPathSegments } = require('./lib/collect');
const { createMiddleware } = require('./lib/middleware');
const { securityHeaders } = require('./lib/security-headers');
const { sql, sqlQ, looksLikeConcatenatedSql } = require('./lib/safe-sql');
const { fastify, fastifyPlugin, koa, nest } = require('./lib/adapters');
const { PRESETS, getPreset, applyPreset } = require('./lib/presets');
const { toPrometheus, createStatsHandler } = require('./lib/stats');
const { resolveClientIp, defaultClientKey } = require('./lib/client-ip');
const { scanDirectory, scanContent } = require('./lib/scan-concat');

const defaultMiddleware = createMiddleware({ mode: 'block', sensitivity: 'balanced' });

/**
 * Express middleware / factory.
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
sqlSanitizer.fastify = fastify;
sqlSanitizer.fastifyPlugin = fastifyPlugin;
sqlSanitizer.koa = koa;
sqlSanitizer.nest = nest;
sqlSanitizer.PRESETS = PRESETS;
sqlSanitizer.getPreset = getPreset;
sqlSanitizer.applyPreset = applyPreset;
sqlSanitizer.toPrometheus = toPrometheus;
sqlSanitizer.createStatsHandler = createStatsHandler;
sqlSanitizer.resolveClientIp = resolveClientIp;
sqlSanitizer.defaultClientKey = defaultClientKey;
sqlSanitizer.scanDirectory = scanDirectory;
sqlSanitizer.scanContent = scanContent;

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
module.exports.fastify = fastify;
module.exports.fastifyPlugin = fastifyPlugin;
module.exports.koa = koa;
module.exports.nest = nest;
module.exports.PRESETS = PRESETS;
module.exports.getPreset = getPreset;
module.exports.applyPreset = applyPreset;
module.exports.toPrometheus = toPrometheus;
module.exports.createStatsHandler = createStatsHandler;
module.exports.resolveClientIp = resolveClientIp;
module.exports.defaultClientKey = defaultClientKey;
module.exports.scanDirectory = scanDirectory;
module.exports.scanContent = scanContent;
module.exports.default = sqlSanitizer;
