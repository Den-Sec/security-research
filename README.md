# Security Research

> **Defense is built by those who know how to attack.**

Vulnerability research and coordinated disclosures by **Dennis Sepede** - Co-Founder &amp; CTO of [Securitix Solutions](https://securitixsolutions.com). Every finding comes from **manual source-code review** and a **working proof-of-concept**, disclosed under a 90-day coordinated policy - with a growing focus on AI/LLM security.

![Assigned CVEs](https://img.shields.io/badge/Assigned_CVEs-16-6d28d9?style=flat-square)
&nbsp;![Critical CVEs](https://img.shields.io/badge/Critical_CVEs-11-c0392b?style=flat-square)
&nbsp;![Published advisories](https://img.shields.io/badge/Published_advisories-23-6d28d9?style=flat-square)
&nbsp;![Targets](https://img.shields.io/badge/Targets_%26_programs-40%2B-0b0a0f?style=flat-square)

## Assigned CVEs

| CVE | Target | Vulnerability | Severity |
|-----|--------|--------------|----------|
| [CVE-2026-118658](https://www.cve.org/CVERecord?id=CVE-2026-118658) | labstack/echo | Arbitrary scheme injection in WWWRedirect/NonWWWRedirect via X-Forwarded-Proto | Medium 4.7 |
| [CVE-2026-51088](https://www.cve.org/CVERecord?id=CVE-2026-51088) | Tzahi12345/YoutubeDL-Material | Argument Injection to RCE via customArgs | **Critical 9.8** |
| [CVE-2026-51089](https://www.cve.org/CVERecord?id=CVE-2026-51089) | LiangYang666/ChatGPT-Web | Pickle deserialization RCE | **Critical 9.8** |
| [CVE-2026-51090](https://www.cve.org/CVERecord?id=CVE-2026-51090) | ltzheng/agent-studio | jsonpickle deserialization RCE | **Critical 9.8** |
| [CVE-2026-51091](https://www.cve.org/CVERecord?id=CVE-2026-51091) | develon2015/Youtube-dl-REST | OS Command Injection via recode | **Critical 9.8** |
| [CVE-2026-51092](https://www.cve.org/CVERecord?id=CVE-2026-51092) | kudlav/videoeditor | OS Command Injection via upload filename | **Critical 9.8** |
| [CVE-2026-51093](https://www.cve.org/CVERecord?id=CVE-2026-51093) | maxpumperla/elephas | Pickle deserialization RCE | **Critical 9.8** |
| [CVE-2026-51094](https://www.cve.org/CVERecord?id=CVE-2026-51094) | Tiendil/feeds.fun | Server-Side Request Forgery | High 7.7 |
| [CVE-2026-51095](https://www.cve.org/CVERecord?id=CVE-2026-51095) | antmicro/protoplaster | Pickle deserialization RCE | **Critical 9.8** |
| [CVE-2026-51096](https://www.cve.org/CVERecord?id=CVE-2026-51096) | Tanq16/local-content-share | Path Traversal (read/write/delete) | **Critical 9.8** |
| [CVE-2026-51097](https://www.cve.org/CVERecord?id=CVE-2026-51097) | stepfun-ai/Step-Video-T2V | Pickle deserialization RCE | **Critical 9.8** |
| [CVE-2026-51098](https://www.cve.org/CVERecord?id=CVE-2026-51098) | wizsk/goshare | Path Traversal (arbitrary file read) | High 7.5 |
| [CVE-2026-40895](https://www.cve.org/CVERecord?id=CVE-2026-40895) | follow-redirects (axios dependency) | Custom auth headers leak on cross-domain redirect | Medium 6.9 |
| [CVE-2026-38595](https://www.cve.org/CVERecord?id=CVE-2026-38595) | im3x/Scriptables | OS Command Injection via filename | **Critical 9.8** |
| [CVE-2026-38600](https://www.cve.org/CVERecord?id=CVE-2026-38600) | gohttpserver | Zip Slip - arbitrary file write &rarr; RCE | **Critical 9.1** |
| [CVE-2026-38601](https://www.cve.org/CVERecord?id=CVE-2026-38601) | gohttpserver | Hardcoded session secret - auth bypass | High 7.5 |

MITRE also issued five duplicate IDs (CVE-2026-51099 to CVE-2026-51103) for vulnerabilities already listed above.

## 6 libraries, one leak

A single bug class - **custom authentication headers leaking across cross-origin redirects** ([CWE-200](https://cwe.mitre.org/data/definitions/200.html)) - surfaced through manual review across **six** widely-used HTTP client libraries. These clients strip `Authorization`, `Cookie`, `Proxy-Authorization` and `Host` on redirect, but forward custom auth headers (`X-API-Key`, `X-Auth-Token`, `Api-Key`, ...) verbatim to the redirect target, leaking credentials to attacker-controlled hosts.

`undici` &middot; `node-fetch` &middot; `follow-redirects` &middot; `parnurzeal/gorequest` &middot; `imroc/req` &middot; `go-resty/resty`

Outcomes span the full spectrum of real-world disclosure: a coordinated [GHSA for follow-redirects](https://github.com/follow-redirects/follow-redirects/security/advisories/GHSA-r4q5-vmmm-2653), an upstream fix in [go-resty PR #1136](https://github.com/go-resty/resty/pull/1136), and spec-compliance pushback from others - each documented per advisory below.

## Advisories

| ID | Target | Vulnerability | Severity | Identifier | Status | Date |
|----|--------|--------------|----------|------------|--------|------|
| VDR-001 | [gohttpserver](advisories/gohttpserver/) | Zip Slip - Arbitrary File Write | Critical (9.1) | [CVE-2026-38600](https://www.cve.org/CVERecord?id=CVE-2026-38600) | No upstream fix (project unmaintained) | 2026-03-19 |
| VDR-002 | [gohttpserver](advisories/gohttpserver/) | Hardcoded Session Secret - Auth Bypass | High (7.5) | [CVE-2026-38601](https://www.cve.org/CVERecord?id=CVE-2026-38601) | No upstream fix (project unmaintained) | 2026-03-19 |
| VDR-003 | [im3x/Scriptables](advisories/im3x-scriptables/) | OS Command Injection via Filename | Critical (9.8) | [CVE-2026-38595](https://www.cve.org/CVERecord?id=CVE-2026-38595) | No upstream fix (project unmaintained) | 2026-04-14 |
| VDR-004 | [nodejs/undici](advisories/undici/) | Custom Auth Headers Leak on Cross-Origin Redirect | Medium | - | Closed by maintainer (`not planned`) | 2026-03-20 |
| VDR-005 | [node-fetch](advisories/node-fetch/) | Custom Auth Headers + proxy-authorization Leak on Cross-Origin Redirect | Medium | Pending | Awaiting maintainer | 2026-03-20 |
| VDR-006 | [parnurzeal/gorequest](advisories/gorequest/) | Custom Auth Headers Leak on Cross-Domain Redirect | High (7.4) | Pending | Awaiting maintainer | 2026-03-20 |
| VDR-007 | [imroc/req](advisories/req/) | Custom Auth Headers Leak on Cross-Domain Redirect | High (7.4) | Pending | Awaiting maintainer | 2026-03-20 |
| VDR-008 | [go-resty/resty](advisories/resty/) | Custom Auth Header Leak via SetHeaderAuthorizationKey | Medium | Pending | Fixed in [PR #1136](https://github.com/go-resty/resty/pull/1136) | 2026-03-20 |
| VDR-009 | [follow-redirects](advisories/follow-redirects/) | Custom Auth Headers Leak (axios dependency) | Medium | [GHSA-r4q5-vmmm-2653](https://github.com/follow-redirects/follow-redirects/security/advisories/GHSA-r4q5-vmmm-2653) | Coordinated disclosure | 2026-03-20 |
| VDR-010 | [phpk/godoos](advisories/godoos/) | Critical Path Traversal on 14+ unauthenticated endpoints | Critical (9.8) | Pending | Awaiting maintainer | 2026-03-20 |
| VDR-011 | [aiohttp](advisories/aiohttp/) | Credentials preserved across HTTP->HTTPS redirect with port change | Medium | - | Fixed on `master` (PR #12275) | 2026-03-20 |
| VDR-011 | [stepfun-ai/Step-Video-T2V](advisories/step-video-t2v/) | Unauthenticated pickle deserialization RCE | Critical (9.8) | [CVE-2026-51097](https://www.cve.org/CVERecord?id=CVE-2026-51097) | Published | 2026-06-05 |
| VDR-013 | [local-content-share](advisories/local-content-share/) | Unauthenticated path traversal (read/write/delete) | Critical (9.8) | [CVE-2026-51096](https://www.cve.org/CVERecord?id=CVE-2026-51096) | Published | 2026-06-05 |
| VDR-014 | [wizsk/goshare](advisories/goshare/) | Unauthenticated path traversal (file read) | High (7.5) | [CVE-2026-51098](https://www.cve.org/CVERecord?id=CVE-2026-51098) | Published | 2026-06-05 |
| VDR-015 | [antmicro/protoplaster](advisories/protoplaster/) | Unauthenticated pickle deserialization RCE | Critical (9.8) | [CVE-2026-51095](https://www.cve.org/CVERecord?id=CVE-2026-51095) | Published | 2026-06-05 |
| VDR-016 | [kudlav/videoeditor](advisories/videoeditor/) | OS command injection via upload filename | Critical (9.8) | [CVE-2026-51092](https://www.cve.org/CVERecord?id=CVE-2026-51092) | Published | 2026-06-05 |
| VDR-017 | [Tiendil/feeds.fun](advisories/feeds-fun/) | Server-Side Request Forgery | High (7.7) | [CVE-2026-51094](https://www.cve.org/CVERecord?id=CVE-2026-51094) | Published | 2026-06-05 |
| VDR-018 | [maxpumperla/elephas](advisories/elephas/) | Unauthenticated pickle deserialization RCE | Critical (9.8) | [CVE-2026-51093](https://www.cve.org/CVERecord?id=CVE-2026-51093) | Published | 2026-06-05 |
| VDR-019 | [ltzheng/agent-studio](advisories/agent-studio/) | Unauthenticated jsonpickle deserialization RCE | Critical (9.8) | [CVE-2026-51090](https://www.cve.org/CVERecord?id=CVE-2026-51090) | Published | 2026-04-14 |
| VDR-020 | [LiangYang666/ChatGPT-Web](advisories/chatgpt-web/) | Unauthenticated pickle deserialization RCE | Critical (9.8) | [CVE-2026-51089](https://www.cve.org/CVERecord?id=CVE-2026-51089) | Published | 2026-04-14 |
| VDR-021 | [Tzahi12345/YoutubeDL-Material](advisories/youtubedl-material/) | Argument injection to RCE via customArgs | Critical (9.8) | [CVE-2026-51088](https://www.cve.org/CVERecord?id=CVE-2026-51088) | Published | 2026-04-14 |
| VDR-022 | [develon2015/Youtube-dl-REST](advisories/youtube-dl-rest/) | OS command injection via recode | Critical (9.8) | [CVE-2026-51091](https://www.cve.org/CVERecord?id=CVE-2026-51091) | Published | 2026-04-14 |
| VDR-023 | [labstack/echo](advisories/echo/) | Arbitrary scheme injection in redirect middlewares | Medium (4.7) | [CVE-2026-118658](https://www.cve.org/CVERecord?id=CVE-2026-118658) | Fixed in 4.15.2 / 5.1.1 | 2026-03-20 |

## Methodology

All vulnerabilities are discovered through manual source code review and confirmed with working proof-of-concept exploits before disclosure. Reports are submitted via GitHub Security Advisory or the project's designated security contact, following a 90-day coordinated disclosure policy.

## Responsible Disclosure Policy

- Vulnerabilities are reported privately to maintainers before any public disclosure
- Maintainers are given 90 days to release a fix
- Public disclosure occurs after the fix is released or after the 90-day deadline
- Proof-of-concept code is minimal and non-weaponized

## Contact

- **Website**: [dennissepede.com](https://dennissepede.com) &middot; [securitixsolutions.com](https://securitixsolutions.com)
- **LinkedIn**: [dennis-sepede-cybersecurity](https://linkedin.com/in/dennis-sepede-cybersecurity)
- **GitHub**: [@Den-Sec](https://github.com/Den-Sec)
