# VDR-004: Custom Auth Headers Leak on Cross-Origin Redirect in undici

- **Target**: [nodejs/undici](https://github.com/nodejs/undici) (Node.js built-in HTTP client since v18)
- **Severity**: Medium
- **CWE**: [CWE-200](https://cwe.mitre.org/data/definitions/200.html) - Exposure of Sensitive Information
- **CVE**: Not requested (closed by maintainer as `not planned`)
- **Discovered**: 2026-03-20
- **Researcher**: Dennis Sepede - [Securitix Solutions](https://securitixsolutions.com)

## Summary

Both `undici.request()` and `undici.fetch()` strip only `authorization`, `cookie`, `proxy-authorization`, and `host` on cross-origin redirect. Custom authentication headers (`X-API-Key`, `X-Auth-Token`, `Api-Key`, `Token`, etc.) are forwarded verbatim to the redirect target, leaking credentials to attacker-controlled hosts.

Since `undici` is the built-in HTTP client in Node.js since v18, every Node.js application using `fetch()` or `undici.request()` with custom auth headers is potentially affected.

## Affected Code

- `lib/handler/redirect-handler.js:201-213` (`undici.request()`) - length-based shortcut: only checks headers with length 4 (host), 13 (authorization), 6 (cookie), or 19 (proxy-authorization); any custom auth header with a different length is never checked.
- `lib/web/fetch/index.js:1312-1322` (`undici.fetch()`) - hardcoded list deletes only `authorization`, `proxy-authorization`, `cookie`, `host`.

## Status

| Date | Event |
|------|-------|
| 2026-03-20 | Vulnerability discovered and confirmed with working PoC |
| 2026-03-20 | Reported via GitHub issue [#4917](https://github.com/nodejs/undici/issues/4917) |
| 2026-03-20 | Closed by maintainer as `not planned`; spec-compliance argument |
| - | No fix planned upstream |

## Position

The WHATWG Fetch spec only mandates stripping `Authorization`. In server-side Node.js usage (no CORS enforcement), custom auth headers carry real credentials that should be protected. This is a pragmatic gap, not a spec violation - the report is preserved as a reference for downstream library authors who may want to apply defense-in-depth.

## Recommendation

Application developers using `undici.fetch()` or `undici.request()` with custom auth headers should:

- Use a `redirect: 'manual'` policy and re-issue the request only after validating the redirect target
- Or wrap the client to strip a configurable list of `sensitiveHeaders` before forwarding redirects

## References

- [GitHub issue #4917](https://github.com/nodejs/undici/issues/4917)
- [CWE-200: Exposure of Sensitive Information](https://cwe.mitre.org/data/definitions/200.html)
- [WHATWG Fetch spec - HTTP-redirect fetch](https://fetch.spec.whatwg.org/#http-redirect-fetch)
