# VDR-006: Custom Auth Headers Leak on Cross-Domain Redirect in gorequest

- **Target**: [parnurzeal/gorequest](https://github.com/parnurzeal/gorequest)
- **Severity**: High (CVSS 3.1: 7.4)
- **CWE**: [CWE-200](https://cwe.mitre.org/data/definitions/200.html) - Exposure of Sensitive Information
- **CVE**: Pending
- **Discovered**: 2026-03-20
- **Researcher**: Dennis Sepede - [Securitix Solutions](https://securitixsolutions.com)

## Summary

Custom authentication headers set via `Set()` or `AppendHeader()` (`API-Key`, `X-Auth-Token`, etc.) are forwarded to cross-domain redirect targets without being stripped. Go's `net/http` only strips the standard set (`Authorization`, `Cookie`, `Proxy-Authorization`) on cross-domain redirects, and the default `http.Client` used by `gorequest` has no `CheckRedirect` configured.

The library's own test suite uses `Set("API-Key", "fookey")` (`gorequest_test.go:259-260`), confirming custom auth headers are an intended use pattern.

## Affected Code

- `gorequest.go` - `Set()` and `AppendHeader()` register arbitrary header names
- Default `http.Client` - no `CheckRedirect` configured, inheriting `net/http`'s hardcoded strip list

## Status

| Date | Event |
|------|-------|
| 2026-03-20 | Vulnerability discovered and confirmed with working PoC |
| 2026-03-20 | Reported via GitHub issue [#298](https://github.com/parnurzeal/gorequest/issues/298) |
| - | Awaiting maintainer response |

## Recommendation

Provide a `SensitiveHeaders` option, or strip headers matching common auth patterns (e.g. names containing `key`, `token`, `auth`) by default in a `CheckRedirect` policy.

## References

- [GitHub issue #298](https://github.com/parnurzeal/gorequest/issues/298)
- [CWE-200: Exposure of Sensitive Information](https://cwe.mitre.org/data/definitions/200.html)
- [Go net/http RFC 7235 strip list](https://pkg.go.dev/net/http#Request)
