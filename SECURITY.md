# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| `1.x`   | Yes       |
| `< 1.0` | No        |

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Report vulnerabilities privately through GitHub Security Advisories:

- **Private Advisory Form:** https://github.com/cbip191/mcp-guard/security/advisories/new

We aim to acknowledge reports within **72 hours** and provide an initial severity assessment and remediation timeline shortly after.

## Scope

### In Scope
- **Proxy fail-open bugs:** Any framing, parsing, batch, or stream-lifecycle edge case where secrets or blocked messages bypass inspection.
- **Secret-redaction bypasses:** Deterministic secret rules failing to match valid credential formats or leaking raw secrets into `finding.path`, `error.data`, or `stdout`.
- **ACL fail-open bugs:** `filterFactsForPrincipal` or `guardMcpResponse` permitting unauthorized facts or skipping enforcement when `callerScopes` is provided.
- **Quarantine escape:** Bypassing `[MCP_GUARD_UNTRUSTED_DATA]` boundary escaping in `taintUntrustedPayload`.
- **Denial of Service (ReDoS / memory exhaustion):** Inputs causing catastrophic regex backtracking or unbounded buffering in `src/redact.mjs`, `src/injection.mjs`, or `src/proxy.mjs`.

### Out of Scope (Use Normal Bug / Enhancement Issues)
- Novel natural-language prompt-injection phrasings that do not break quarantine boundary escaping (please file as a feature/rule enhancement).
- Requests to add detection for new third-party vendor token formats (use the **New Secret Rule** issue template).

## Disclosure Policy

Once a fix is verified and released, we will publish the advisory and credit the reporter (unless anonymity is requested).

## Supply-Chain & Provenance Verification

Releases are built and published from GitHub Actions via npm OIDC Trusted Publishing with Sigstore provenance attestations (`.github/workflows/release.yml`). Consumers can verify published tarballs with:

```bash
npm audit signatures
```
