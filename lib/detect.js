'use strict';

/** @typedef {'balanced' | 'strict' | 'paranoid'} Sensitivity */

/**
 * Normalize common obfuscations before pattern matching.
 * Returns spaced form (block comments -> spaces) and compact form
 * (block comments removed) for keyword-splitting obfuscation tricks.
 * @param {string} input
 * @returns {{ spaced: string, compact: string }}
 */
function normalizeVariants(input) {
  let s = String(input);
  s = s.replace(/\u0000/g, '');

  for (let i = 0; i < 3; i += 1) {
    try {
      const decoded = decodeURIComponent(s.replace(/\+/g, ' '));
      if (decoded === s) {
        break;
      }
      s = decoded;
    } catch (_err) {
      break;
    }
  }

  const spaced = s
    .replace(/\/\*!?[\s\S]*?\*\//g, ' ')
    .replace(/[\t\r\f\v]+/g, ' ')
    .replace(/ {2,}/g, ' ');
  const compact = s
    .replace(/\/\*!?[\s\S]*?\*\//g, '')
    .replace(/[\t\r\f\v]+/g, ' ')
    .replace(/ {2,}/g, ' ');

  return { spaced, compact };
}

/**
 * @param {string} input
 * @returns {string}
 */
function normalizeForDetection(input) {
  const { spaced, compact } = normalizeVariants(input);
  // Prefer compact when it reveals glued keywords like UNION SELECT.
  if (/\bunion\s*select\b/i.test(compact) || /\bor\d+\s*=\s*\d+/i.test(compact)) {
    return compact;
  }
  return spaced;
}

/**
 * High-signal attack patterns (default / balanced).
 * Intentionally does NOT flag a lone apostrophe (O'Brien) or year ranges (2020--2021).
 */
const BALANCED_PATTERNS = [
  {
    id: 'sql_or',
    re: /('|"|%27|%22)\s*(or|and)\b/i,
  },
  {
    id: 'sql_or_digits',
    re: /\bor\b\s+\d+\s*=\s*\d+/i,
  },
  {
    id: 'sql_union_select',
    re: /\bunion\b[\s/\w*+]*\bselect\b/i,
  },
  {
    id: 'sql_stacked',
    re: /;\s*(select|insert|update|delete|drop|alter|create|truncate|exec|execute)\b/i,
  },
  {
    id: 'sql_comment_auth',
    // admin'--  /  admin'#  /  ' OR 1=1--
    re: /('|%27)\s*(--|#|%23)/i,
  },
  {
    id: 'sql_boolean_tautology',
    re: /('|%27)\s*(or|and)\s*('|%27)?\s*\d+\s*=\s*\d+/i,
  },
  {
    id: 'sql_time_based',
    re: /\b(sleep|benchmark)\s*\(|\bwaitfor\s+delay\b/i,
  },
  {
    id: 'sql_sensitive_funcs',
    re: /\b(information_schema|load_file\s*\(|into\s+(out|dump)file\b|pg_sleep\s*\()/i,
  },
  {
    id: 'sql_equals_quote_chain',
    // id=1' OR '1'='1
    re: /((%3D)|(=))[^\n]{0,40}((%27)|('))[^\n]{0,40}((%27)|(')|(--)|(%3B)|(;))/i,
  },
];

/** Extra patterns for strict mode. */
const STRICT_EXTRA_PATTERNS = [
  {
    id: 'sql_bare_comment_kw',
    re: /--\s*(select|union|or|and|drop|insert|delete|update)\b/i,
  },
  {
    id: 'sql_hash_comment_kw',
    re: /#\s*(select|union|or|and|drop|insert|delete|update)\b/i,
  },
  {
    id: 'sql_hex_string',
    re: /0x[0-9a-f]{4,}/i,
  },
  {
    id: 'sql_char_concat',
    re: /\bchar\s*\(\s*\d+/i,
  },
];

/** Old aggressive meta matching (paranoid). */
const PARANOID_EXTRA_PATTERNS = [
  { id: 'sql_meta', re: /(%27)|(')|(--)|(%23)|(#)/i },
  {
    id: 'sql_meta_with_equals',
    re: /((%3D)|(=))[^\n]*((%27)|(')|(--)|(%3B)|(;))/i,
  },
];

/**
 * @param {Sensitivity} [sensitivity]
 */
function patternsFor(sensitivity) {
  const level = sensitivity || 'balanced';
  if (level === 'paranoid') {
    return BALANCED_PATTERNS.concat(STRICT_EXTRA_PATTERNS, PARANOID_EXTRA_PATTERNS);
  }
  if (level === 'strict') {
    return BALANCED_PATTERNS.concat(STRICT_EXTRA_PATTERNS);
  }
  return BALANCED_PATTERNS;
}

/**
 * @param {unknown} value
 * @param {{ sensitivity?: Sensitivity }} [options]
 * @returns {boolean}
 */
function hasSqlInjection(value, options) {
  return check(value, options).detected;
}

/**
 * Inspect a value for SQLi heuristics.
 * @param {unknown} value
 * @param {{ sensitivity?: Sensitivity }} [options]
 * @returns {{ detected: boolean, pattern: string | null, value: string | null, normalized: string | null }}
 */
function check(value, options) {
  if (value === null || value === undefined) {
    return { detected: false, pattern: null, value: null, normalized: null };
  }

  const text = typeof value === 'string' ? value : String(value);
  if (!text) {
    return { detected: false, pattern: null, value: null, normalized: null };
  }

  const { spaced, compact } = normalizeVariants(text);
  const normalized = normalizeForDetection(text);
  const sensitivity = (options && options.sensitivity) || 'balanced';
  const patterns = patternsFor(sensitivity);
  const variants = Array.from(new Set([text, spaced, compact, normalized]));

  for (const variant of variants) {
    for (const pattern of patterns) {
      if (pattern.re.test(variant)) {
        return {
          detected: true,
          pattern: pattern.id,
          value: text,
          normalized,
        };
      }
    }
  }

  return { detected: false, pattern: null, value: text, normalized };
}

module.exports = {
  BALANCED_PATTERNS,
  STRICT_EXTRA_PATTERNS,
  PARANOID_EXTRA_PATTERNS,
  normalizeVariants,
  normalizeForDetection,
  patternsFor,
  hasSqlInjection,
  check,
};
