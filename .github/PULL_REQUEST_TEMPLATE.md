## Summary
<!-- Briefly describe what this PR changes and why. -->

Closes #

## Security & Quality Checklist
- [ ] Zero npm dependencies added to `package.json`
- [ ] `npm run check` passes (syntax, stdout discipline, `.d.ts` export parity, rule invariants, formatting)
- [ ] `npm test` and `npm run demo` pass locally
- [ ] Any synthetic test secrets are constructed at runtime (no literal tokens that trigger GitHub Push Protection)
- [ ] New detection rules include both positive cases and realistic engineering false-positive regression tests
- [ ] Updated `src/index.d.ts` and `test/types.check.ts` if public exports changed
