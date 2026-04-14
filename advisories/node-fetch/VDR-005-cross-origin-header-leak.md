# VDR-005: Custom Auth Headers and proxy-authorization Leak on Cross-Origin Redirect in node-fetch

- **Target**: [node-fetch/node-fetch](https://github.com/node-fetch/node-fetch)
- **Severity**: Medium
- **CWE**: [CWE-200](https://cwe.mitre.org/data/definitions/200.html) - Exposure of Sensitive Information
- **CVE**: Pending
- **Discovered**: 2026-03-20
- **Researcher**: Dennis Sepede - [Securitix Solutions](https://securitixsolutions.com)

## Summary

`node-fetch` strips `authorization`, `www-authenticate`, `cookie`, and `cookie2` on cross-origin redirect (`src/index.js:200-213`), but does NOT strip:

1. **`proxy-authorization`** - proxy credentials forwarded to redirect target
2. **Custom authentication headers** - `X-API-Key`, `X-Auth-Token`, etc. forwarded verbatim

## Affected Code

`src/index.js`, lines 200-213:

```javascript
if (!isDomainOrSubdomain(request.url, locationURL) || !isSameProtocol(request.url, locationURL)) {
    for (const name of ['authorization', 'www-authenticate', 'cookie', 'cookie2']) {
        requestOptions.headers.delete(name);
    }
}
```

The deletion list is hardcoded; only the four headers above are stripped, regardless of how the application uses `node-fetch` for authentication.

## Comparison

| Client | Strips standard auth | Strips `proxy-authorization` | Strips custom auth headers |
|--------|---------------------|-----------------------------|---------------------------|
| curl | yes | yes | yes (unless `--location-trusted`) |
| follow-redirects | yes | yes | no |
| Python `requests` | yes | yes | no |
| `node-fetch` | yes | **no** | **no** |

## Status

| Date | Event |
|------|-------|
| 2026-03-20 | Vulnerability discovered and confirmed with working PoC |
| 2026-03-20 | Reported via GitHub issue [#1880](https://github.com/node-fetch/node-fetch/issues/1880) |
| - | Awaiting maintainer response |

## Recommendation

Add `proxy-authorization` to the strip list. For custom auth headers, expose a `sensitiveHeaders` option that applications can extend (mirrors the pattern adopted by `axios`/`follow-redirects` after [GHSA-r4q5-vmmm-2653](https://github.com/follow-redirects/follow-redirects/security/advisories/GHSA-r4q5-vmmm-2653)).

## References

- [GitHub issue #1880](https://github.com/node-fetch/node-fetch/issues/1880)
- [CWE-200: Exposure of Sensitive Information](https://cwe.mitre.org/data/definitions/200.html)
