# VDR-002: Hardcoded Session Secret in gohttpserver

- **Target**: [codeskyblue/gohttpserver](https://github.com/codeskyblue/gohttpserver)
- **Severity**: Critical (CVSS 3.1: 9.1)
- **CWE**: [CWE-798](https://cwe.mitre.org/data/definitions/798.html) - Use of Hard-coded Credentials
- **CVE**: Pending
- **Discovered**: 2026-03-19
- **Researcher**: Dennis Sepede - [Securitix Solutions](https://securitixsolutions.com)

## Summary

`gohttpserver` (all versions through v1.3.0) initializes its session cookie store with a hardcoded secret key that is identical across every installation. Since this value is visible in the public source code, any remote attacker can forge valid signed session cookies to impersonate arbitrary users, completely bypassing OpenID authentication and all per-user access controls.

## Status

| Date | Event |
|------|-------|
| 2026-03-19 | Vulnerability discovered during source code audit |
| 2026-03-19 | Report submitted via GitHub Security Advisory |
| TBD | Maintainer acknowledgment |
| TBD | Fix released |

## Details

Full advisory details will be published after coordinated disclosure (90 days or after fix release).

## References

- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [OWASP: Use of Hard-coded Password](https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password)
