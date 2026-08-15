'use strict';

const fs = require('fs');
const path = require('path');

const DEFAULT_EXTENSIONS = new Set(['.js', '.cjs', '.mjs', '.ts', '.tsx', '.jsx']);
const IGNORE_DIR_NAMES = new Set([
  'node_modules',
  '.git',
  'dist',
  'build',
  'coverage',
  '.next',
  'vendor',
]);

/**
 * Heuristic patterns for unsafe SQL string concatenation / interpolation in source.
 */
const PATTERNS = [
  {
    id: 'plus_concat_sql',
    // "SELECT ..." + user  OR  'DELETE ...' + 
    re: /(['"`])\s*(select|insert|update|delete|drop|alter|create|truncate|with)\b[\s\S]{0,120}?\1\s*\+/gi,
  },
  {
    id: 'plus_before_sql',
    re: /\+\s*(['"`])\s*(select|insert|update|delete|drop|alter|create|truncate|with)\b/gi,
  },
  {
    id: 'template_sql_interpolation',
    // `SELECT ... ${user}` 
    re: /`[^`]*\b(select|insert|update|delete|drop|alter|create|truncate|with)\b[^`]*\$\{/gi,
  },
];

/**
 * @param {string} filePath
 * @param {string} content
 */
function scanContent(filePath, content) {
  const findings = [];
  const lines = content.split(/\r?\n/);

  for (const pattern of PATTERNS) {
    pattern.re.lastIndex = 0;
    let match;
    while ((match = pattern.re.exec(content)) !== null) {
      const before = content.slice(0, match.index);
      const line = before.split(/\r?\n/).length;
      const col = before.length - before.lastIndexOf('\n');
      findings.push({
        file: filePath,
        line,
        column: col,
        pattern: pattern.id,
        sample: (lines[line - 1] || match[0]).trim().slice(0, 200),
      });
    }
  }

  return findings;
}

/**
 * @param {string} dir
 * @param {{ extensions?: string[], ignore?: string[] }} [options]
 */
function walkFiles(dir, options = {}) {
  const extensions = new Set(options.extensions || [...DEFAULT_EXTENSIONS]);
  const ignore = new Set([...(options.ignore || []), ...IGNORE_DIR_NAMES]);
  const out = [];

  function walk(current) {
    let entries;
    try {
      entries = fs.readdirSync(current, { withFileTypes: true });
    } catch (_err) {
      return;
    }
    for (const entry of entries) {
      if (ignore.has(entry.name)) continue;
      const full = path.join(current, entry.name);
      if (entry.isDirectory()) {
        walk(full);
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name);
        if (extensions.has(ext)) out.push(full);
      }
    }
  }

  walk(dir);
  return out;
}

/**
 * Scan a directory tree for likely unsafe SQL concatenation.
 * @param {string} rootDir
 * @param {object} [options]
 */
function scanDirectory(rootDir, options = {}) {
  const root = path.resolve(rootDir);
  const files = walkFiles(root, options);
  const findings = [];
  for (const file of files) {
    let content;
    try {
      content = fs.readFileSync(file, 'utf8');
    } catch (_err) {
      continue;
    }
    // Skip our own safe helper definitions / tests that intentionally mention concat.
    if (file.includes(`${path.sep}lib${path.sep}safe-sql.js`)) continue;
    findings.push(...scanContent(path.relative(root, file) || file, content));
  }
  return { root, filesScanned: files.length, findings };
}

module.exports = {
  PATTERNS,
  scanContent,
  scanDirectory,
  walkFiles,
};
