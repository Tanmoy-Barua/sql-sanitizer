'use strict';

/**
 * Lightweight security headers middleware (optional companion).
 * @param {object} [options]
 * @param {boolean} [options.frameguard=true]
 * @param {boolean} [options.noSniff=true]
 * @param {boolean} [options.xssFilter=true]
 * @param {boolean} [options.referrerPolicy=true]
 * @param {string} [options.referrerPolicyValue='no-referrer']
 * @param {boolean|string} [options.contentSecurityPolicy=false]
 */
function securityHeaders(options = {}) {
  const opts = options && typeof options === 'object' ? options : {};
  const frameguard = opts.frameguard !== false;
  const noSniff = opts.noSniff !== false;
  const xssFilter = opts.xssFilter !== false;
  const referrerPolicy = opts.referrerPolicy !== false;
  const referrerPolicyValue = opts.referrerPolicyValue || 'no-referrer';
  const csp = opts.contentSecurityPolicy;

  return function securityHeadersMiddleware(req, res, next) {
    if (frameguard) {
      res.setHeader('X-Frame-Options', 'SAMEORIGIN');
    }
    if (noSniff) {
      res.setHeader('X-Content-Type-Options', 'nosniff');
    }
    if (xssFilter) {
      res.setHeader('X-XSS-Protection', '0');
    }
    if (referrerPolicy) {
      res.setHeader('Referrer-Policy', referrerPolicyValue);
    }
    if (csp === true) {
      res.setHeader('Content-Security-Policy', "default-src 'self'");
    } else if (typeof csp === 'string' && csp) {
      res.setHeader('Content-Security-Policy', csp);
    }
    return next();
  };
}

module.exports = {
  securityHeaders,
};
