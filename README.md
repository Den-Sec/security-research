# Security Research

Vulnerability research and responsible disclosures by **Dennis Sepede** - [Securitix Solutions](https://securitixsolutions.com).

## Advisories

| ID | Target | Vulnerability | Severity | Identifier | Status | Date |
|----|--------|--------------|----------|------------|--------|------|
| VDR-001 | [gohttpserver](advisories/gohttpserver/) | Zip Slip - Arbitrary File Write | Critical (9.1) | [CVE-2026-38600](https://www.cve.org/CVERecord?id=CVE-2026-38600) | No upstream fix (project unmaintained) | 2026-03-19 |
| VDR-002 | [gohttpserver](advisories/gohttpserver/) | Hardcoded Session Secret - Auth Bypass | Critical (9.1) | [CVE-2026-38601](https://www.cve.org/CVERecord?id=CVE-2026-38601) | No upstream fix (project unmaintained) | 2026-03-19 |
| VDR-003 | [im3x/Scriptables](advisories/im3x-scriptables/) | OS Command Injection via Filename | Critical (9.8) | [CVE-2026-38595](https://www.cve.org/CVERecord?id=CVE-2026-38595) | No upstream fix (project unmaintained) | 2026-04-14 |
| VDR-004 | [nodejs/undici](advisories/undici/) | Custom Auth Headers Leak on Cross-Origin Redirect | Medium | - | Closed by maintainer (`not planned`) | 2026-03-20 |
| VDR-005 | [node-fetch](advisories/node-fetch/) | Custom Auth Headers + proxy-authorization Leak on Cross-Origin Redirect | Medium | Pending | Awaiting maintainer | 2026-03-20 |
| VDR-006 | [parnurzeal/gorequest](advisories/gorequest/) | Custom Auth Headers Leak on Cross-Domain Redirect | High (7.4) | Pending | Awaiting maintainer | 2026-03-20 |
| VDR-007 | [imroc/req](advisories/req/) | Custom Auth Headers Leak on Cross-Domain Redirect | High (7.4) | Pending | Awaiting maintainer | 2026-03-20 |
| VDR-008 | [go-resty/resty](advisories/resty/) | Custom Auth Header Leak via SetHeaderAuthorizationKey | Medium | Pending | Fixed in [PR #1136](https://github.com/go-resty/resty/pull/1136) | 2026-03-20 |
| VDR-009 | [follow-redirects](advisories/follow-redirects/) | Custom Auth Headers Leak (axios dependency) | Medium | [GHSA-r4q5-vmmm-2653](https://github.com/follow-redirects/follow-redirects/security/advisories/GHSA-r4q5-vmmm-2653) | Coordinated disclosure | 2026-03-20 |
| VDR-010 | [phpk/godoos](advisories/godoos/) | Critical Path Traversal on 14+ unauthenticated endpoints | Critical (9.8) | Pending | Awaiting maintainer | 2026-03-20 |

### Pending CVE assignment

The following four vulnerabilities have been submitted to MITRE and are awaiting CVE assignment. Public advisories will be published once CVE IDs are issued.

| Target | Vulnerability | CWE |
|--------|--------------|-----|
| Tzahi12345/YoutubeDL-Material | Argument Injection via customArgs/additionalArgs | CWE-88 |
| develon2015/Youtube-dl-REST | OS Command Injection via recode parameter | CWE-78 |
| LiangYang666/ChatGPT-Web | Insecure Deserialization via .pkl upload | CWE-502 |
| ltzheng/agent-studio | Insecure Deserialization via jsonpickle.decode | CWE-502 |

## Methodology

All vulnerabilities are discovered through manual source code review and confirmed with working proof-of-concept exploits before disclosure. Reports are submitted via GitHub Security Advisory or the project's designated security contact, following a 90-day coordinated disclosure policy.

## Responsible Disclosure Policy

- Vulnerabilities are reported privately to maintainers before any public disclosure
- Maintainers are given 90 days to release a fix
- Public disclosure occurs after the fix is released or after the 90-day deadline
- Proof-of-concept code is minimal and non-weaponized

## Contact

- **Website**: [securitixsolutions.com](https://securitixsolutions.com)
- **GitHub**: [@Den-Sec](https://github.com/Den-Sec)
