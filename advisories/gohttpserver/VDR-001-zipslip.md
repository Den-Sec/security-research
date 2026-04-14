# VDR-001: Zip Slip - Arbitrary File Write in gohttpserver

- **Target**: [codeskyblue/gohttpserver](https://github.com/codeskyblue/gohttpserver)
- **Severity**: Critical (CVSS 3.1: 9.1)
- **CWE**: [CWE-22](https://cwe.mitre.org/data/definitions/22.html) - Path Traversal
- **CVE**: [CVE-2026-38600](https://www.cve.org/CVERecord?id=CVE-2026-38600)
- **Discovered**: 2026-03-19
- **Researcher**: Dennis Sepede - [Securitix Solutions](https://securitixsolutions.com)

## Summary

The upload endpoint in `gohttpserver` (all versions through v1.3.0) allows an unauthenticated attacker to write arbitrary files to any location on the host filesystem by uploading a crafted ZIP archive with the `unzip=true` parameter. The `sanitizedName()` function in `zip.go` does not reject `..` path traversal sequences, and `unzipFile()` does not validate that extracted paths remain within the destination directory.

This directly leads to Remote Code Execution by overwriting system-level files such as cron jobs, SSH authorized keys, or application code.

## Status

| Date | Event |
|------|-------|
| 2026-03-19 | Vulnerability discovered and confirmed with working PoC |
| 2026-03-19 | Report submitted via GitHub issue requesting Private Vulnerability Reporting |
| 2026-03-19 | Maintainer notified via direct email |
| 2026-04-13 | Public technical disclosure on issue #232 (no maintainer response) |
| 2026-04-14 | CVE-2026-38600 assigned by MITRE |
| 2026-04-13 | Community fix in fork: [abesnier/gohttpserver PR #233](https://github.com/codeskyblue/gohttpserver/pull/233) |
| - | Upstream maintainer: no response, project unmaintained |

## Details

Full advisory details will be published after coordinated disclosure (90 days or after fix release).

## References

- [Snyk: Zip Slip Vulnerability](https://security.snyk.io/research/zip-slip-vulnerability)
- [CWE-22: Path Traversal](https://cwe.mitre.org/data/definitions/22.html)
