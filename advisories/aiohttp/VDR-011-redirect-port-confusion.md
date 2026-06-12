# VDR-011: Credentials Preserved Across HTTP->HTTPS Redirect with Port Change in aiohttp

- **Target**: [aio-libs/aiohttp](https://github.com/aio-libs/aiohttp) (async HTTP client/server for Python)
- **Severity**: Medium
- **CWE**: [CWE-522](https://cwe.mitre.org/data/definitions/522.html) - Insufficiently Protected Credentials
- **GHSA**: GHSA-c688-4x73-hg84 (private advisory, reporter credit accepted - see Status)
- **Discovered**: 2026-03-20
- **Fixed**: 2026-03-26 ([PR #12275](https://github.com/aio-libs/aiohttp/pull/12275))
- **Researcher**: Dennis Sepede - [Securitix Solutions](https://securitixsolutions.com) (credited as `Den-Sec`)

## Summary

aiohttp strips authentication credentials when a request follows a redirect to a different origin. The redirect-handling code carried a special case for the common "HTTP to HTTPS upgrade on the same host", where credentials were intentionally preserved. The condition that recognised that case - `is_same_host_https_redirect` - compared only the **hostname** and the **scheme**, never the **port**.

Per [RFC 6454](https://www.rfc-editor.org/rfc/rfc6454), a web origin is the tuple `(scheme, host, port)`; a change of port is a change of origin. Because the same-host shortcut ignored the port, a redirect from `http://host:8080` to `https://host:9443` was treated as a legitimate same-host upgrade, the origin-mismatch stripping was skipped, and the credentials were forwarded to what is, in origin terms, a different destination.

## Affected Code

The code lived on the `master` (v4 development) line. At the last vulnerable commit ([`b26c9aee`](https://github.com/aio-libs/aiohttp/blob/b26c9aee4cf1cb280fa771855ab7be95f1ae1d22/aiohttp/client.py#L872-L895)), `aiohttp/client.py` lines 872-895:

```python
is_same_host_https_redirect = (
    url.host == parsed_redirect_url.host
    and parsed_redirect_url.scheme == "https"
    and url.scheme == "http"
)
...
if (
    not is_same_host_https_redirect
    and url.origin() != redirect_origin
):
    auth = None
    headers.pop(hdrs.AUTHORIZATION, None)
    headers.pop(hdrs.COOKIE, None)
    headers.pop(hdrs.PROXY_AUTHORIZATION, None)
```

`is_same_host_https_redirect` matches on `url.host` (hostname) and scheme only. When it is true, `not is_same_host_https_redirect` short-circuits the stripping condition to false even though `url.origin() != redirect_origin` holds - so the credentials are kept across the port change.

The same-host shortcut was introduced in 2021 by [PR #5848](https://github.com/aio-libs/aiohttp/pull/5848) (commit `98d97cc9f`) to keep auth headers on HTTP->HTTPS upgrades; the port was not considered at the time.

## Attack Scenario

1. A client issues an authenticated request to `http://service.internal:8080` (auth header or Basic credentials).
2. The endpoint responds with `301/302 Location: https://service.internal:9443/...` - same hostname, HTTP->HTTPS, different port.
3. `is_same_host_https_redirect` is true (host and scheme match), the origin-mismatch stripping is skipped, and aiohttp replays the credentials to `:9443`.
4. The credentials reach a different origin than the one the caller authenticated to. Where a port boundary separates trust domains (a sidecar, a co-located service, another tenant), this is a credential exposure.

## Resolution

Fixed on 2026-03-26 in [PR #12275](https://github.com/aio-libs/aiohttp/pull/12275) (commit [`8b10afd4`](https://github.com/aio-libs/aiohttp/commit/8b10afd473a6805cd2c2b6bf918543942941a869)), titled *"Fix credential leak on same-host redirects with different ports"*. The fix removes the `is_same_host_https_redirect` shortcut entirely, so credentials are now stripped whenever the full origin differs:

```python
if url.origin() != redirect_origin:
    auth = None
    headers.pop(hdrs.AUTHORIZATION, None)
    headers.pop(hdrs.COOKIE, None)
    headers.pop(hdrs.PROXY_AUTHORIZATION, None)
```

`url.origin()` includes the port, so a same-host redirect to a different port is now correctly treated as a cross-origin redirect.

## Status

| Date | Event |
|------|-------|
| 2026-03-20 | Vulnerability discovered and reported privately via GitHub Security Advisory (GHSA-c688-4x73-hg84) |
| 2026-03-26 | Fixed on `master` in PR #12275, six days after the report |
| 2026-06-11 | Reporter credit accepted (`Den-Sec`) |
| - | **Closed without CVE**: the affected code existed only on the `master` / v4 development line and was never part of a tagged release (the introducing commit appears in no release tag), so the maintainers resolved it within v4 and assigned no CVE. |

Because the advisory is closed (not published), it does not appear in the public GitHub Advisory Database. This document, with its source permalinks, is the public and citable record of the research.

## References

- [Vulnerable code at `b26c9aee`](https://github.com/aio-libs/aiohttp/blob/b26c9aee4cf1cb280fa771855ab7be95f1ae1d22/aiohttp/client.py#L872-L895)
- [PR #12275 - the fix](https://github.com/aio-libs/aiohttp/pull/12275)
- [PR #5848 - introduced the same-host shortcut (2021)](https://github.com/aio-libs/aiohttp/pull/5848)
- [CWE-522: Insufficiently Protected Credentials](https://cwe.mitre.org/data/definitions/522.html)
- [RFC 6454: The Web Origin Concept](https://www.rfc-editor.org/rfc/rfc6454)
