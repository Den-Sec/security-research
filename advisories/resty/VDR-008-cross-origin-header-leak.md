# VDR-008: Custom Auth Header Leak via SetHeaderAuthorizationKey on Cross-Domain Redirect in resty

- **Target**: [go-resty/resty](https://github.com/go-resty/resty)
- **Severity**: Medium
- **CWE**: [CWE-200](https://cwe.mitre.org/data/definitions/200.html) - Exposure of Sensitive Information
- **CVE**: Pending
- **Discovered**: 2026-03-20
- **Researcher**: Dennis Sepede - [Securitix Solutions](https://securitixsolutions.com)

## Summary

When `SetHeaderAuthorizationKey()` is used to configure a custom HTTP header name for authentication tokens (e.g., `X-API-Key`, `X-Auth-Token`), the credential is leaked to cross-domain redirect targets. Go's `net/http` only strips the standard sensitive header set (`Authorization`, `Cookie`, `Proxy-Authorization`); resty's custom header name configured via `SetHeaderAuthorizationKey()` is NOT recognized as sensitive and is forwarded verbatim.

## Affected Code

- `client.go:597` - `SetHeaderAuthorizationKey()` allows changing the header name
- `middleware.go:288` - `addCredentials()` places auth token in user-configurable header
- `redirect.go:97-105` - `checkHostAndAddHeaders()` copies all headers without credential check
- Go stdlib `net/http/client.go:814-815` - hardcoded strip list does not include custom names

## Proof of Concept (summary)

Tested with Go test servers on `127.0.0.1` -> `127.0.0.2` cross-domain redirect. All four custom header names tested (`X-API-Key`, `X-Auth-Token`, `X-Custom-Authorization`, `Api-Key`) leaked credentials to the redirect target. Standard `Authorization` was correctly stripped by Go's stdlib.

## Status

| Date | Event |
|------|-------|
| 2026-03-20 | Vulnerability discovered and confirmed with working PoC |
| 2026-03-20 | Reported via GitHub issue [#1128](https://github.com/go-resty/resty/issues/1128) |
| 2026-03-22 | Issue closed by maintainer; fix in progress |
| 2026-03-28 | Fix merged: [PR #1136 - strip sensitive headers on cross-domain redirects by default](https://github.com/go-resty/resty/pull/1136) |

## Resolution

Fixed upstream by [PR #1136](https://github.com/go-resty/resty/pull/1136) (merged 2026-03-28). Resty now strips configured authentication headers by default when redirecting to a different domain.

## References

- [GitHub issue #1128](https://github.com/go-resty/resty/issues/1128)
- [GitHub PR #1136 (merged)](https://github.com/go-resty/resty/pull/1136)
- [CWE-200: Exposure of Sensitive Information](https://cwe.mitre.org/data/definitions/200.html)
