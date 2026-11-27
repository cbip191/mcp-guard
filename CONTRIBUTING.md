# Contributing to `@4sails/mcp-guard`

Thanks for helping harden MCP tooling! Because `mcp-guard` sits in the critical path of developer coding agents, please follow these engineering rules on every pull request.

## Non-Negotiable Engineering Rules

1. **Zero npm dependencies:** `package.json` must remain strictly zero-dependency (no `dependencies`, `devDependencies`, `optionalDependencies`, `peerDependencies`, or `bundledDependencies`). Use Node.js 20+ built-ins (`node:test`, `node:assert/strict`, `node:child_process`, `node:fs`, `node:http`).
2. **Strict `stdout` vs `stderr` discipline:** Never write logs or debug output to `stdout` (`console.log`, `console.info`, `process.stdout.write`) inside `src/`. MCP JSON-RPC traffic flows over `stdout`; audit telemetry belongs strictly on `stderr`.
3. **Never commit realistic literal secrets (`GH013`):** GitHub Push Protection is enabled on this repository. Construct all synthetic test tokens at runtime (for example, `["sk", "test", "51N9xExample..."].join("_")`).
4. **Regex safety & invariants:**
   - Every rule in `SECRET_RULES` and `PII_RULES` **must** include the `/g` flag and have a unique `id`.
   - Every rule in `INJECTION_PATTERNS` must **not** include the `/g` flag and must specify a valid `severity` and `tier`.
   - Every new rule **must** include both positive tests and realistic engineering false-positive regression tests, and must pass `test/redos.test.mjs` (`<50ms` on 50 KB adversarial input).
5. **TypeScript parity:** Any export added or changed in `src/index.mjs` must be reflected in `src/index.d.ts` and exercised in `test/types.check.ts`.
6. **Code formatting:** 2-space indentation, LF line endings, no tabs, no trailing whitespace, trailing newline (see `.editorconfig` and `.gitattributes`).

## Local Workflow

```bash
# 1. Create a feature branch from main
git checkout -b fix/short-description

# 2. Run the full static check, test suite, and demo before pushing
npm run check
npm test
npm run demo
```

## Pull Requests

- Use clear conventional titles (`fix(redact): ...`, `feat(proxy): ...`, `docs: ...`).
- Link the issue (`Closes #<n>`) and fill out the PR checklist.
- Keep PRs focused and small so security behavior is easy to audit.

## Releases & npm Provenance

Tagged releases (`v*.*.*`) are published automatically via [`.github/workflows/release.yml`](./.github/workflows/release.yml) using **npm OIDC Trusted Publishing** (`npm publish --provenance --access public`) with no long-lived npm tokens stored in GitHub Secrets:

1. One-time package setup on npmjs.com: under `@4sails/mcp-guard` → **Settings → Trusted Publisher → GitHub Actions**, authorize repository `cbip191/mcp-guard` and workflow filename `release.yml`.
2. Bump `package.json`, `CHANGELOG.md`, and `SECURITY.md` via PR, merge to `main`, and push an annotated tag matching `v<version>` (`git tag -a vX.Y.Z -m "..." && git push origin vX.Y.Z`).
3. Verify provenance after publish with `npm audit signatures`.

By participating in this project, you agree to abide by our [Code of Conduct](./CODE_OF_CONDUCT.md).
