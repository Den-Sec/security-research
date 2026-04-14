# Security Research

Vulnerability research and responsible disclosures by **Dennis Sepede** - [Securitix Solutions](https://securitixsolutions.com).

## Advisories

| ID | Target | Vulnerability | Severity | CVE | Date |
|----|--------|--------------|----------|-----|------|
| VDR-001 | [gohttpserver](advisories/gohttpserver/) | Zip Slip - Arbitrary File Write | Critical (9.1) | [CVE-2026-38600](https://www.cve.org/CVERecord?id=CVE-2026-38600) | 2026-03-19 |
| VDR-002 | [gohttpserver](advisories/gohttpserver/) | Hardcoded Session Secret - Auth Bypass | Critical (9.1) | [CVE-2026-38601](https://www.cve.org/CVERecord?id=CVE-2026-38601) | 2026-03-19 |
| VDR-003 | [im3x/Scriptables](advisories/im3x-scriptables/) | OS Command Injection via Filename | Critical (9.8) | [CVE-2026-38595](https://www.cve.org/CVERecord?id=CVE-2026-38595) | 2026-04-14 |

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
