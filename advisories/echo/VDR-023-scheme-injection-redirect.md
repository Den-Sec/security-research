# VDR-023: Arbitrary Scheme Injection in WWWRedirect/NonWWWRedirect via X-Forwarded-Proto in labstack/echo

- **Target**: [labstack/echo](https://github.com/labstack/echo) (Go web framework)
- **Severity**: Medium (CVSS 3.1: 4.7)
- **CWE**: [CWE-601](https://cwe.mitre.org/data/definitions/601.html) - URL Redirection to Untrusted Site
- **CVE**: [CVE-2026-118658](https://www.cve.org/CVERecord?id=CVE-2026-118658)
- **GHSA**: [GHSA-23wf-92cp-8pcj](https://github.com/labstack/echo/security/advisories/GHSA-23wf-92cp-8pcj)
- **CVSS Vector**: `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N`
- **Affected**: `github.com/labstack/echo/v4` < 4.15.2, `github.com/labstack/echo/v5` < 5.1.1
- **Patched**: 4.15.2, 5.1.1
- **Discovered**: 2026-03-20
- **Researcher**: Dennis Sepede - [Securitix Solutions](https://securitixsolutions.com) (reported as `Den-Sec`)

## Summary

`Context.Scheme()` trusts the `X-Forwarded-Proto`, `X-Forwarded-Protocol` and `X-Url-Scheme` request headers and returns their value verbatim, without checking that it is a web scheme. The `WWWRedirect()` and `NonWWWRedirect()` middlewares use that value to build the redirect URL, so a client can inject an arbitrary URI scheme into the `Location` response header.

## Affected Code

- `context.go` - `Scheme()` returns the attacker-controlled header value as-is
- `middleware/redirect.go` - `redirectWWW` / `redirectNonWWW` concatenate the unsanitised scheme into the redirect target

## Proof of Concept

```
GET /path HTTP/1.1
Host: example.com
X-Forwarded-Proto: javascript

HTTP/1.1 301 Moved Permanently
Location: javascript://www.example.com/path
```

Confirmed injectable schemes: `javascript`, `data`, `vbscript`, `file`, `ftp`, `ssh`, `telnet`, `gopher`. Tested on Echo v5.0.4 against a running HTTP server.

Only `WWWRedirect()` and `NonWWWRedirect()` (and their `WithConfig` variants) are affected. `HTTPSRedirect`, `HTTPSWWWRedirect` and `HTTPSNonWWWRedirect` hardcode `https://` and are not affected.

## Impact

- Redirect to arbitrary-scheme URLs when the application is not behind a proxy that overwrites `X-Forwarded-Proto`
- Cache poisoning when a CDN caches redirect responses keyed only on the path
- Exploitation requires one of the vulnerable middlewares and user interaction, which is reflected in the CVSS score

## Fix

`Context.Scheme()` now accepts only `http`, `https`, `ws` or `wss` from the forwarded headers and falls back to `http` for any other value ([#2953](https://github.com/labstack/echo/pull/2953)).

**Workaround** for unpatched deployments: have the edge proxy overwrite or remove `X-Forwarded-Proto`, `X-Forwarded-Protocol` and `X-Url-Scheme`.

## Status

| Date | Event |
|------|-------|
| 2026-03-20 | Reported privately via GitHub Security Advisory (submitted as High) |
| 2026-09-27 | Advisory published by the maintainer, rescored to Medium 4.7 |
| 2026-10-28 | CVE-2026-118658 published |
