'use strict';

/**
 * @param {string} path
 * @param {Array<string|RegExp>} allowRoutes
 */
function routeAllowed(path, allowRoutes) {
  if (!Array.isArray(allowRoutes) || allowRoutes.length === 0) {
    return false;
  }

  const normalized = path || '/';
  for (const rule of allowRoutes) {
    if (typeof rule === 'string') {
      if (normalized === rule) {
        return true;
      }
      if (normalized.startsWith(`${rule}/`)) {
        return true;
      }
    } else if (rule instanceof RegExp && rule.test(normalized)) {
      return true;
    }
  }
  return false;
}

/**
 * @param {string} fieldPath
 * @param {Set<string>} allowFields
 */
function fieldAllowed(fieldPath, allowFields) {
  if (!allowFields || allowFields.size === 0) {
    return false;
  }
  if (allowFields.has(fieldPath)) {
    return true;
  }
  for (const allowed of allowFields) {
    if (fieldPath === allowed || fieldPath.endsWith(`.${allowed}`)) {
      return true;
    }
  }
  return false;
}

/**
 * Decode a path/query fragment safely.
 * @param {string} value
 */
function safeDecode(value) {
  let current = value;
  for (let i = 0; i < 3; i += 1) {
    try {
      const decoded = decodeURIComponent(current.replace(/\+/g, ' '));
      if (decoded === current) {
        return current;
      }
      current = decoded;
    } catch (_err) {
      return current;
    }
  }
  return current;
}

/**
 * Extract path segments even when Express has not populated req.params yet.
 * This removes the need to mount the middleware on each matched route.
 *
 * @param {import('express').Request} req
 * @param {Array<{ path: string, value: string }>} out
 */
function collectPathSegments(req, out) {
  const rawPath =
    (typeof req.path === 'string' && req.path) ||
    (typeof req.originalUrl === 'string' && req.originalUrl.split('?')[0]) ||
    (typeof req.url === 'string' && req.url.split('?')[0]) ||
    '';

  if (!rawPath) {
    return;
  }

  const decodedPath = safeDecode(rawPath);
  const segments = decodedPath.split('/').filter(Boolean);
  segments.forEach((segment, index) => {
    out.push({ path: `path[${index}]`, value: segment });
    // Also keep an undecoded variant if different (double-encoding cases).
    const rawSegments = rawPath.split('/').filter(Boolean);
    if (rawSegments[index] && rawSegments[index] !== segment) {
      out.push({ path: `path[${index}].raw`, value: rawSegments[index] });
    }
  });
}

/**
 * Collect candidate strings with field paths.
 *
 * @param {unknown} input
 * @param {string} basePath
 * @param {Set<string>} allowFields
 * @param {Array<{ path: string, value: string }>} out
 */
function collectCandidates(input, basePath, allowFields, out) {
  if (input === null || input === undefined) {
    return;
  }

  const type = typeof input;
  if (type === 'string' || type === 'number' || type === 'boolean') {
    if (!fieldAllowed(basePath, allowFields)) {
      out.push({ path: basePath || '(value)', value: String(input) });
    }
    return;
  }

  if (typeof Buffer !== 'undefined' && Buffer.isBuffer(input)) {
    if (!fieldAllowed(basePath, allowFields)) {
      out.push({ path: basePath || '(buffer)', value: input.toString('utf8') });
    }
    return;
  }

  if (Array.isArray(input)) {
    input.forEach((item, index) => {
      const next = basePath ? `${basePath}[${index}]` : `[${index}]`;
      collectCandidates(item, next, allowFields, out);
    });
    return;
  }

  if (type === 'object') {
    for (const key of Object.keys(input)) {
      const next = basePath ? `${basePath}.${key}` : key;
      const val = input[key];

      collectCandidates(key, basePath ? `${basePath}.(key)` : '(key)', allowFields, out);

      if (
        val &&
        typeof val === 'object' &&
        !Array.isArray(val) &&
        (val.mimetype || val.fieldname) &&
        (val.buffer || val.path || val.stream)
      ) {
        if (val.originalname) {
          collectCandidates(val.originalname, `${next}.originalname`, allowFields, out);
        }
        if (val.filename) {
          collectCandidates(val.filename, `${next}.filename`, allowFields, out);
        }
        continue;
      }

      collectCandidates(val, next, allowFields, out);
    }
  }
}

/**
 * @param {import('express').Request} req
 * @param {{ allowFields?: string[] }} options
 */
function collectFromRequest(req, options = {}) {
  const allowFields = new Set(options.allowFields || []);
  /** @type {Array<{ path: string, value: string }>} */
  const out = [];

  if (typeof req.originalUrl === 'string' && req.originalUrl) {
    out.push({ path: 'originalUrl', value: req.originalUrl });
  } else if (typeof req.url === 'string' && req.url) {
    out.push({ path: 'url', value: req.url });
  }

  // Always scan path segments so route params are covered without route-level mount.
  collectPathSegments(req, out);

  collectCandidates(req.query, 'query', allowFields, out);
  collectCandidates(req.params, 'params', allowFields, out);
  collectCandidates(req.body, 'body', allowFields, out);

  if (req.files) {
    collectCandidates(req.files, 'files', allowFields, out);
  }

  if (typeof req.rawBody === 'string') {
    collectCandidates(req.rawBody, 'rawBody', allowFields, out);
  }

  return out;
}

/**
 * @param {unknown} input
 * @param {string[]} out
 */
function collectValues(input, out) {
  const tmp = [];
  collectCandidates(input, '', new Set(), tmp);
  for (const item of tmp) {
    out.push(item.value);
  }
}

module.exports = {
  routeAllowed,
  fieldAllowed,
  safeDecode,
  collectPathSegments,
  collectCandidates,
  collectFromRequest,
  collectValues,
};
