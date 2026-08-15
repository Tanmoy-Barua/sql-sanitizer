# Examples

| File | What it shows |
|------|----------------|
| `express-postgres.js` | Express + `sql\`...\`` ($1 placeholders) + stats route |
| `express-mysql.js` | Express + `sqlQ\`...\`` (? placeholders) |
| `before-after.js` | Same SQLi payload: vulnerable concat vs middleware + parameterized SQL |

```bash
node examples/before-after.js
node examples/express-postgres.js
node examples/express-mysql.js
```
