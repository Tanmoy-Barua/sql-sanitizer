# AGENTS.md

## Cursor Cloud specific instructions

`sql-sanitizer` is a single-file Express middleware library (`index.js`) that
detects SQL-injection patterns in a request's URL and body and responds `403`
when a match is found, otherwise calls `next()`. It is consumed as
`app.use(require('sql-sanitizer'))` in a host Express app (see `README.md`).

- There are no runtime dependencies in `package.json`; `npm install` is a no-op
  beyond creating the lockfile. `express` is only needed to exercise the
  middleware and is NOT a declared dependency.
- There is no lint config and no test suite. `npm test` intentionally exits
  non-zero (`echo "Error: no test specified" && exit 1`).
- To run/demo the middleware end-to-end, install express on demand
  (`npm install express`), then mount the middleware in a tiny Express app
  (mirror the `README.md` usage) and hit it with `curl`. `node_modules/` is not
  in `.gitignore`, so avoid staging it when committing.
- Injection is flagged when the URL or JSON-stringified body matches the regexes
  in `hasSqlInjection` (quotes/comments `'` `--` `#`, `=...';`, typical
  `' or`, `'union`). Use `express.json()` before the middleware so body checks
  apply to JSON payloads.
