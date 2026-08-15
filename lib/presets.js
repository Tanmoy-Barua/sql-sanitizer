'use strict';

/**
 * Named option presets for common app shapes.
 * User options always win over preset values.
 */
const PRESETS = {
  api: {
    sensitivity: 'balanced',
    mode: 'block',
    allowFields: [],
    rateLimit: { windowMs: 60_000, max: 20 },
  },
  form: {
    sensitivity: 'balanced',
    mode: 'block',
    // Common free-text fields that often contain apostrophes
    allowFields: ['bio', 'about', 'description', 'comment', 'message', 'notes'],
    rateLimit: { windowMs: 60_000, max: 30 },
  },
  graphql: {
    sensitivity: 'strict',
    mode: 'block',
    allowRoutes: [],
    allowFields: [],
    rateLimit: { windowMs: 60_000, max: 40 },
  },
};

/**
 * @param {string} [name]
 * @returns {object}
 */
function getPreset(name) {
  if (!name || typeof name !== 'string') {
    return {};
  }
  const key = name.toLowerCase();
  if (!Object.prototype.hasOwnProperty.call(PRESETS, key)) {
    throw new Error(`Unknown sql-sanitizer preset "${name}". Use: ${Object.keys(PRESETS).join(', ')}`);
  }
  // shallow clone nested rateLimit
  const preset = PRESETS[key];
  return {
    ...preset,
    allowFields: Array.isArray(preset.allowFields) ? preset.allowFields.slice() : [],
    allowRoutes: Array.isArray(preset.allowRoutes) ? preset.allowRoutes.slice() : [],
    rateLimit: preset.rateLimit ? { ...preset.rateLimit } : undefined,
  };
}

/**
 * @param {object} [userOptions]
 */
function applyPreset(userOptions) {
  const options = userOptions && typeof userOptions === 'object' ? { ...userOptions } : {};
  if (!options.preset) {
    return options;
  }
  const base = getPreset(options.preset);
  const merged = {
    ...base,
    ...options,
  };
  // Deep-merge allow lists if both provided
  if (base.allowFields && options.allowFields) {
    merged.allowFields = Array.from(new Set([...(base.allowFields || []), ...options.allowFields]));
  }
  if (base.allowRoutes && options.allowRoutes) {
    merged.allowRoutes = [...(base.allowRoutes || []), ...options.allowRoutes];
  }
  if (base.rateLimit && options.rateLimit) {
    merged.rateLimit = { ...base.rateLimit, ...options.rateLimit };
  }
  delete merged.preset;
  return merged;
}

module.exports = {
  PRESETS,
  getPreset,
  applyPreset,
};
