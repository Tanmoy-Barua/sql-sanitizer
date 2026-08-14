'use strict';

const PATTERNS = [
  { id: 'sql_meta', re: /(%27)|(')|(--)|(%23)|(#)/i },
  { id: 'sql_meta_with_equals', re: /((%3D)|(=))[^\n]*((%27)|(')|(--)|(%3B)|(;))/i },
  { id: 'sql_or', re: /\w*((%27)|('))((%6F)|o|(%4F))((%72)|r|(%52))/i },
  { id: 'sql_union', re: /((%27)|('))union/i },
  { id: 'sql_union_select', re: /\bunion\b[\s/%*+\w]*\bselect\b/i },
];

/**
 * @param {unknown} value
 * @returns {boolean}
 */
function hasSqlInjection(value) {
  return check(value).detected;
}

/**
 * Inspect a value for SQLi heuristics.
 * @param {unknown} value
 * @returns {{ detected: boolean, pattern: string | null, value: string | null }}
 */
function check(value) {
  if (value === null || value === undefined) {
    return { detected: false, pattern: null, value: null };
  }

  const text = typeof value === 'string' ? value : String(value);
  if (!text) {
    return { detected: false, pattern: null, value: null };
  }

  for (const pattern of PATTERNS) {
    if (pattern.re.test(text)) {
      return { detected: true, pattern: pattern.id, value: text };
    }
  }

  return { detected: false, pattern: null, value: text };
}

module.exports = {
  PATTERNS,
  hasSqlInjection,
  check,
};
