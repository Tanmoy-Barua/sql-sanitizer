#!/usr/bin/env node
'use strict';

const path = require('path');
const { scanDirectory } = require('../lib/scan-concat');

function printHelp() {
  console.log(`Usage: sql-sanitizer scan [dir] [--json]

Scan source files for unsafe SQL string concatenation / interpolation.

Examples:
  sql-sanitizer scan .
  sql-sanitizer scan ./src --json
`);
}

function main(argv) {
  const args = argv.slice(2);
  if (args.length === 0 || args[0] === '-h' || args[0] === '--help') {
    printHelp();
    process.exit(args.length === 0 ? 1 : 0);
  }

  if (args[0] !== 'scan') {
    console.error(`Unknown command "${args[0]}". Try: sql-sanitizer scan`);
    process.exit(1);
  }

  const json = args.includes('--json');
  const dirArg = args.slice(1).find((a) => !a.startsWith('--')) || '.';
  const result = scanDirectory(path.resolve(process.cwd(), dirArg));

  if (json) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    console.log(`Scanned ${result.filesScanned} files in ${result.root}`);
    if (result.findings.length === 0) {
      console.log('No unsafe SQL concatenation patterns found.');
    } else {
      console.log(`Found ${result.findings.length} potential issue(s):\n`);
      for (const f of result.findings) {
        console.log(`- ${f.file}:${f.line}:${f.column} [${f.pattern}]`);
        console.log(`  ${f.sample}`);
      }
    }
  }

  process.exit(result.findings.length > 0 ? 2 : 0);
}

main(process.argv);
