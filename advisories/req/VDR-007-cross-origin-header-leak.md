# VDR-007: Custom Auth Headers Leak on Cross-Domain Redirect in imroc/req

- **Target**: [imroc/req](https://github.com/imroc/req)
- **Severity**: High (CVSS 3.1: 7.4)
- **CWE**: [CWE-200](https://cwe.mitre.org/data/definitions/200.html) - Exposure of Sensitive Information
- **CVE**: Pending
- **Discovered**: 2026-03-20
- **Researcher**: Dennis Sepede - [Securitix Solutions](https://securitixsolutions.com)

## Summary

Custom authentication headers set via `SetCommonHeader()` or `SetHeader()` (`X-API-Key`, `X-Auth-Token`, etc.) are forwarded to cross-domain redirect targets without being stripped. Go's `net/http` only strips standard sensitive headers (`Authorization`, `Cookie`, `Proxy-Authorization`) on cross-domain redirects, and `req`'s `SetRedirectPolicy` only counts redirects - it does NOT strip any header.

## Affected Code

- `middleware.go:528-540` - `parseRequestHeader()` merges client headers into the outgoing request
- `client.go:334` - `CheckRedirect` only counts redirects, no header stripping
- Stdlib limitation: only hardcoded sensitive headers are stripped, custom ones pass through

## Status

| Date | Event |
|------|-------|
| 2026-03-20 | Vulnerability discovered and confirmed with working PoC |
| 2026-03-20 | Reported via GitHub issue [#489](https://github.com/imroc/req/issues/489) |
| - | Awaiting maintainer response |

## Recommendation

Add header stripping to the default redirect policy for known auth-pattern headers, or expose a `SensitiveHeaders` option that the application can extend.

## References

- [GitHub issue #489](https://github.com/imroc/req/issues/489)
- [CWE-200: Exposure of Sensitive Information](https://cwe.mitre.org/data/definitions/200.html)
