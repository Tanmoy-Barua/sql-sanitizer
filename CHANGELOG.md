# Changelog

## 2.0.0

Major feature release expanding sql-sanitizer from Express-only middleware into a broader Node security toolkit.

### Added
- Framework adapters: `fastify()`, `fastifyPlugin()`, `koa()`, `nest()`
- Config presets: `preset: 'api' | 'form' | 'graphql'`
- Stats dashboard via `statsRoute` / `statsHandler`, plus `prometheus()` / `toPrometheus()`
- CLI: `sql-sanitizer scan [dir]` for unsafe SQL concatenation detection
- Trusted proxy IP resolution: `trustProxy`, `cf-connecting-ip`, `x-real-ip`, `true-client-ip`
- Official examples under `examples/` (including Northline Notes realtime demo)
- CI + npm publish GitHub Actions

### Includes from 1.x hardening
- Balanced / strict / paranoid sensitivity
- Path-segment scanning, encoding/comment normalization
- Modes: block / detect / monitor
- Allowlists, rate limiting, security headers
- Parameterized `sql` / `sqlQ` helpers
- TypeScript types + ESM exports

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
