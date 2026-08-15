'use strict';

/**
 * Resolve client IP with trusted-proxy awareness.
 *
 * @param {object} req
 * @param {{ trustProxy?: boolean|number|string, clientKey?: Function }} [options]
 * @returns {string}
 */
function resolveClientIp(req, options = {}) {
  if (typeof options.clientKey === 'function') {
    return options.clientKey(req);
  }

  const trustProxy = options.trustProxy;
  const headers = (req && req.headers) || {};

  // Cloudflare / common CDN headers (only when proxy trust is enabled)
  if (trustProxy) {
    const cf = headers['cf-connecting-ip'];
    if (typeof cf === 'string' && cf.trim()) {
      return cf.trim();
    }
    const trueClient = headers['true-client-ip'];
    if (typeof trueClient === 'string' && trueClient.trim()) {
      return trueClient.trim();
    }
    const realIp = headers['x-real-ip'];
    if (typeof realIp === 'string' && realIp.trim()) {
      return realIp.trim();
    }
  }

  const xf = headers['x-forwarded-for'];
  if (trustProxy && xf) {
    const parts = (Array.isArray(xf) ? xf.join(',') : String(xf))
      .split(',')
      .map((p) => p.trim())
      .filter(Boolean);

    if (parts.length > 0) {
      // trustProxy: true → leftmost (original client)
      // trustProxy: N → take from the right, N hops
      if (trustProxy === true || trustProxy === 'always') {
        return parts[0];
      }
      if (typeof trustProxy === 'number' && trustProxy > 0) {
        const idx = Math.max(0, parts.length - trustProxy);
        return parts[idx];
      }
      // trustProxy: 'loopback' or other string → leftmost
      return parts[0];
    }
  }

  // When trustProxy is false/undefined, ignore forwarded headers (prevents spoofing).
  if (req && req.ip) {
    return String(req.ip);
  }
  if (req && req.socket && req.socket.remoteAddress) {
    return String(req.socket.remoteAddress);
  }
  return 'unknown';
}

/**
 * Backward-compatible default (trusts X-Forwarded-For first hop).
 * Prefer resolveClientIp with explicit trustProxy in new code.
 * @param {object} req
 */
function defaultClientKey(req) {
  return resolveClientIp(req, { trustProxy: true });
}

module.exports = {
  resolveClientIp,
  defaultClientKey,
};
