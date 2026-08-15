'use strict';

/**
 * Format middleware stats as Prometheus text exposition.
 * @param {object} stats
 * @param {string} [prefix]
 */
function toPrometheus(stats, prefix = 'sql_sanitizer') {
  const lines = [];
  const s = stats || {};
  lines.push(`# HELP ${prefix}_requests_total Total requests inspected`);
  lines.push(`# TYPE ${prefix}_requests_total counter`);
  lines.push(`${prefix}_requests_total ${Number(s.totalRequests) || 0}`);

  lines.push(`# HELP ${prefix}_detections_total SQLi heuristic detections`);
  lines.push(`# TYPE ${prefix}_detections_total counter`);
  lines.push(`${prefix}_detections_total ${Number(s.detections) || 0}`);

  lines.push(`# HELP ${prefix}_blocked_total Requests blocked`);
  lines.push(`# TYPE ${prefix}_blocked_total counter`);
  lines.push(`${prefix}_blocked_total ${Number(s.blocked) || 0}`);

  lines.push(`# HELP ${prefix}_rate_limited_total Rate-limited detections`);
  lines.push(`# TYPE ${prefix}_rate_limited_total counter`);
  lines.push(`${prefix}_rate_limited_total ${Number(s.rateLimited) || 0}`);

  lines.push(`# HELP ${prefix}_detections_by_pattern_total Detections by pattern id`);
  lines.push(`# TYPE ${prefix}_detections_by_pattern_total counter`);
  const byPattern = s.byPattern || {};
  for (const [pattern, count] of Object.entries(byPattern)) {
    const safe = String(pattern).replace(/\\/g, '\\\\').replace(/"/g, '\\"');
    lines.push(`${prefix}_detections_by_pattern_total{pattern="${safe}"} ${Number(count) || 0}`);
  }

  return `${lines.join('\n')}\n`;
}

/**
 * Express handler for stats JSON or Prometheus.
 * @param {object} middleware - createMiddleware() result with .stats
 * @param {{ format?: 'json'|'prometheus', token?: string }} [options]
 */
function createStatsHandler(middleware, options = {}) {
  const format = options.format === 'prometheus' ? 'prometheus' : 'json';
  const token = options.token;

  return function statsHandler(req, res) {
    if (token) {
      const provided =
        (req.headers && (req.headers['x-sql-sanitizer-token'] || req.headers['authorization'])) ||
        (req.query && req.query.token);
      const normalized = String(provided || '').replace(/^Bearer\s+/i, '');
      if (normalized !== token) {
        return res.status(401).json({ error: 'Unauthorized' });
      }
    }

    if (format === 'prometheus' || (req.query && req.query.format === 'prometheus')) {
      res.setHeader('Content-Type', 'text/plain; version=0.0.4; charset=utf-8');
      return res.status(200).send(toPrometheus(middleware.stats));
    }

    return res.status(200).json({
      ok: true,
      stats: middleware.stats,
      options: {
        mode: middleware.options && middleware.options.mode,
        sensitivity: middleware.options && middleware.options.sensitivity,
        trustProxy: middleware.options && middleware.options.trustProxy,
      },
    });
  };
}

module.exports = {
  toPrometheus,
  createStatsHandler,
};
