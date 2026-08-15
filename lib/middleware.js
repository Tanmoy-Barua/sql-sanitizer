'use strict';

const { check } = require('./detect');
const { routeAllowed, collectFromRequest } = require('./collect');
const { createRateLimiter } = require('./rate-limit');
const { resolveClientIp } = require('./client-ip');
const { applyPreset } = require('./presets');
const { createStatsHandler } = require('./stats');

const MODES = new Set(['block', 'detect', 'monitor']);
const SENSITIVITIES = new Set(['balanced', 'strict', 'paranoid']);

/**
 * @param {object} [userOptions]
 */
function normalizeOptions(userOptions) {
  const options = applyPreset(userOptions);
  const mode = MODES.has(options.mode) ? options.mode : 'block';
  const sensitivity = SENSITIVITIES.has(options.sensitivity) ? options.sensitivity : 'balanced';

  let rateLimit = null;
  if (options.rateLimit && typeof options.rateLimit === 'object') {
    rateLimit = createRateLimiter(options.rateLimit);
  }

  const trustProxy =
    options.trustProxy === undefined ? true : options.trustProxy;

  return {
    mode,
    sensitivity,
    trustProxy,
    allowRoutes: Array.isArray(options.allowRoutes) ? options.allowRoutes : [],
    allowFields: Array.isArray(options.allowFields) ? options.allowFields : [],
    onDetection: typeof options.onDetection === 'function' ? options.onDetection : null,
    logger: options.logger === null ? null : options.logger || null,
    rateLimit,
    clientKey: typeof options.clientKey === 'function' ? options.clientKey : null,
    statsRoute: options.statsRoute || null,
    statsToken: options.statsToken || null,
    errorMessage:
      options.errorMessage && typeof options.errorMessage === 'object'
        ? options.errorMessage
        : { error: 'SQL injection detected in request' },
    rateLimitMessage:
      options.rateLimitMessage && typeof options.rateLimitMessage === 'object'
        ? options.rateLimitMessage
        : { error: 'Too many suspicious requests' },
  };
}

function createStats() {
  return {
    totalRequests: 0,
    detections: 0,
    blocked: 0,
    rateLimited: 0,
    byPattern: Object.create(null),
  };
}

/**
 * @param {object} [userOptions]
 */
function createMiddleware(userOptions) {
  const options = normalizeOptions(userOptions);
  const stats = createStats();

  function logDetection(event) {
    if (!options.logger) {
      return;
    }
    const payload = {
      level: 'warn',
      msg: 'sql-sanitizer detection',
      ...event,
    };
    if (typeof options.logger.warn === 'function') {
      options.logger.warn(payload);
    } else if (typeof options.logger.log === 'function') {
      options.logger.log(payload);
    } else if (typeof options.logger === 'function') {
      options.logger(payload);
    }
  }

  function clientKeyFor(req) {
    return resolveClientIp(req, {
      trustProxy: options.trustProxy,
      clientKey: options.clientKey || undefined,
    });
  }

  function middleware(req, res, next) {
    stats.totalRequests += 1;

    const path = req.path || (req.originalUrl ? req.originalUrl.split('?')[0] : '/') || '/';

    // Optional built-in stats dashboard / prometheus endpoint
    if (options.statsRoute && path === options.statsRoute) {
      return createStatsHandler(middleware, {
        token: options.statsToken || undefined,
      })(req, res);
    }

    if (routeAllowed(path, options.allowRoutes)) {
      return next();
    }

    const candidates = collectFromRequest(req, { allowFields: options.allowFields });
    /** @type {null | { path: string, value: string, pattern: string }} */
    let hit = null;

    for (const candidate of candidates) {
      const result = check(candidate.value, { sensitivity: options.sensitivity });
      if (result.detected) {
        hit = {
          path: candidate.path,
          value: candidate.value,
          pattern: result.pattern || 'unknown',
        };
        break;
      }
    }

    if (!hit) {
      if (options.mode === 'monitor') {
        req.sqlSanitizer = { detected: false, stats };
      }
      return next();
    }

    stats.detections += 1;
    stats.byPattern[hit.pattern] = (stats.byPattern[hit.pattern] || 0) + 1;

    const client = clientKeyFor(req);
    let rate = null;
    if (options.rateLimit) {
      rate = options.rateLimit.hit(client);
    }

    const event = {
      ts: new Date().toISOString(),
      mode: options.mode,
      sensitivity: options.sensitivity,
      method: req.method,
      path,
      ip: client,
      field: hit.path,
      pattern: hit.pattern,
      sample: hit.value.slice(0, 200),
      rateLimit: rate,
    };

    logDetection(event);
    if (options.onDetection) {
      try {
        options.onDetection(event, req);
      } catch (_err) {
        // Never break the request pipeline because a user hook threw.
      }
    }

    if (options.mode === 'monitor') {
      req.sqlSanitizer = { detected: true, event, stats };
    }

    if (rate && rate.limited) {
      stats.rateLimited += 1;
      if (options.mode === 'block') {
        stats.blocked += 1;
        return res.status(429).json(options.rateLimitMessage);
      }
      if (options.mode === 'monitor') {
        req.sqlSanitizer.rateLimited = true;
      }
      return next();
    }

    if (options.mode === 'block') {
      stats.blocked += 1;
      return res.status(403).json(options.errorMessage);
    }

    return next();
  }

  middleware.stats = stats;
  middleware.options = options;
  middleware.statsHandler = createStatsHandler(middleware, {
    token: options.statsToken || undefined,
  });
  middleware.prometheus = function prometheus() {
    const { toPrometheus } = require('./stats');
    return toPrometheus(stats);
  };
  if (options.rateLimit) {
    middleware.resetRateLimit = () => options.rateLimit.reset();
  }

  return middleware;
}

module.exports = {
  createMiddleware,
  MODES,
  SENSITIVITIES,
};
