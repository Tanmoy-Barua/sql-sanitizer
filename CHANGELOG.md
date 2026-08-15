# Changelog

## 1.4.0

### Added
- Framework adapters: `fastify()`, `fastifyPlugin()`, `koa()`, `nest()`
- Config presets: `preset: 'api' | 'form' | 'graphql'`
- Stats dashboard via `statsRoute` / `statsHandler`, plus `prometheus()` / `toPrometheus()`
- CLI: `sql-sanitizer scan [dir]` for unsafe SQL concatenation detection
- Trusted proxy IP resolution: `trustProxy`, `cf-connecting-ip`, `x-real-ip`, `true-client-ip`
- Official examples under `examples/`
- CI + npm publish GitHub Actions, engines badge docs

### Notes
- Default detection remains `sensitivity: 'balanced'`
- Prefer parameterized `sql` / `sqlQ` helpers at the database layer

## 1.3.0

- Balanced / strict / paranoid sensitivity
- Path-segment scanning without route-level mount
- Encoding / comment-obfuscation normalization
- `sql` / `sqlQ` parameterized helpers

## 1.2.0

- Modes: block / detect / monitor
- Allowlists, rate limiting, security headers, TypeScript + ESM

## 1.0.0

- Initial Express SQLi heuristic middleware
