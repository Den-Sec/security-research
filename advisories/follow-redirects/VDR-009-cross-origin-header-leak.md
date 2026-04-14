# VDR-009: Custom Auth Headers Leaked to Cross-Domain Redirect Targets in follow-redirects

- **Target**: [follow-redirects/follow-redirects](https://github.com/follow-redirects/follow-redirects) (redirect-handling dependency for `axios`)
- **Severity**: Medium
- **CWE**: [CWE-200](https://cwe.mitre.org/data/definitions/200.html) - Exposure of Sensitive Information
- **GHSA**: [GHSA-r4q5-vmmm-2653](https://github.com/follow-redirects/follow-redirects/security/advisories/GHSA-r4q5-vmmm-2653)
- **Discovered**: 2026-03-20
- **Researcher**: Dennis Sepede - [Securitix Solutions](https://securitixsolutions.com) (credited as `Den-Sec`)

## Summary

When an HTTP request follows a cross-domain redirect (301/302/307/308), `follow-redirects` only strips `authorization`, `proxy-authorization`, and `cookie` headers. Any custom authentication header (e.g., `X-API-Key`, `X-Auth-Token`, `Api-Key`, `Token`) is forwarded verbatim to the redirect target.

Since `follow-redirects` is the redirect-handling dependency for **axios** (105K+ stars), this vulnerability affects the entire axios ecosystem on Node.js.

## Affected Code

`index.js`, lines 469-476:

```javascript
if (redirectUrl.protocol !== currentUrlParts.protocol &&
   redirectUrl.protocol !== "https:" ||
   redirectUrl.host !== currentHost &&
   !isSubdomain(redirectUrl.host, currentHost)) {
  removeMatchingHeaders(/^(?:(?:proxy-)?authorization|cookie)$/i, this._options.headers);
}
```

The regex matches only `authorization`, `proxy-authorization`, and `cookie`. Custom headers like `X-API-Key` are not matched.

## Attack Scenario

1. Application uses axios with custom auth header: `headers: { 'X-API-Key': 'sk-live-secret123' }`
2. Server returns `302 Location: https://evil.com/steal`
3. `follow-redirects` sends `X-API-Key: sk-live-secret123` to `evil.com`
4. Attacker captures the API key

## Status

| Date | Event |
|------|-------|
| 2026-03-20 | Vulnerability discovered and confirmed with working PoC |
| 2026-03-20 | Reported privately via GitHub Security Advisory |
| 2026-04-13 | GHSA-r4q5-vmmm-2653 published, severity Medium |
| - | Fix coordinated with maintainers |

## Recommendation

Application developers using axios should use the `sensitiveHeaders` option (added by the upstream fix) to extend the strip list with their custom auth headers, or use a custom `transformRequest` to clear them when targeting external endpoints.

## References

- [GHSA-r4q5-vmmm-2653](https://github.com/follow-redirects/follow-redirects/security/advisories/GHSA-r4q5-vmmm-2653)
- [CWE-200: Exposure of Sensitive Information](https://cwe.mitre.org/data/definitions/200.html)
