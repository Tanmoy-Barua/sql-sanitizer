'use strict';

/**
 * Simple in-memory sliding-window counter keyed by client id.
 */
function createRateLimiter(options = {}) {
  const windowMs = Number(options.windowMs) > 0 ? Number(options.windowMs) : 60_000;
  const max = Number(options.max) > 0 ? Number(options.max) : 10;
  /** @type {Map<string, number[]>} */
  const hits = new Map();

  function prune(key, now) {
    const list = hits.get(key);
    if (!list) {
      return [];
    }
    const kept = list.filter((ts) => now - ts <= windowMs);
    if (kept.length === 0) {
      hits.delete(key);
    } else {
      hits.set(key, kept);
    }
    return kept;
  }

  return {
    windowMs,
    max,
    /**
     * Record a detection hit.
     * @param {string} key
     * @returns {{ count: number, limited: boolean, remaining: number }}
     */
    hit(key) {
      const now = Date.now();
      const id = key || 'unknown';
      const list = prune(id, now);
      list.push(now);
      hits.set(id, list);
      const count = list.length;
      return {
        count,
        limited: count > max,
        remaining: Math.max(0, max - count),
      };
    },
    /**
     * @param {string} key
     */
    get(key) {
      const list = prune(key || 'unknown', Date.now());
      return {
        count: list.length,
        limited: list.length > max,
        remaining: Math.max(0, max - list.length),
      };
    },
    reset() {
      hits.clear();
    },
  };
}

/**
 * @param {import('express').Request} req
 * @returns {string}
 */
function defaultClientKey(req) {
  const xf = req.headers && req.headers['x-forwarded-for'];
  if (typeof xf === 'string' && xf.trim()) {
    return xf.split(',')[0].trim();
  }
  if (Array.isArray(xf) && xf[0]) {
    return String(xf[0]);
  }
  return (req.ip || (req.socket && req.socket.remoteAddress) || 'unknown').toString();
}

module.exports = {
  createRateLimiter,
  defaultClientKey,
};
