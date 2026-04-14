# VDR-003: OS Command Injection via Filename in im3x/Scriptables

- **Target**: [im3x/Scriptables](https://github.com/im3x/Scriptables)
- **Severity**: Critical (CVSS 3.1: 9.8)
- **CWE**: [CWE-78](https://cwe.mitre.org/data/definitions/78.html) - OS Command Injection
- **CVE**: [CVE-2026-38595](https://www.cve.org/CVERecord?id=CVE-2026-38595)
- **Discovered**: 2026-04-14
- **Researcher**: Dennis Sepede - [Securitix Solutions](https://securitixsolutions.com)

## Summary

`im3x/Scriptables` (all versions through the `v2-dev` branch) exposes an unauthenticated `POST /sync` endpoint that interpolates the uploaded filename directly into a shell command string passed to `child_process.execSync()`. An attacker can craft a filename containing shell metacharacters (e.g. backticks, `$()`, semicolons) to execute arbitrary OS commands on the host with the privileges of the Node.js process.

The server binds to `0.0.0.0:5566` by default and ships with no authentication, so any network-reachable instance is exploitable without prior access.

A secondary path traversal vulnerability ([CWE-22](https://cwe.mitre.org/data/definitions/22.html)) is present in the `GET /sync` handler via the `name` query parameter, allowing arbitrary file read from the host filesystem.

## Status

| Date | Event |
|------|-------|
| 2026-04-14 | Vulnerability discovered during source code audit |
| 2026-04-14 | CVE request submitted to MITRE (no private channel available) |
| 2026-04-14 | CVE-2026-38595 assigned by MITRE |
| - | Upstream maintainer: project unmaintained (last commit December 2020) |

## Affected Component

- `app.js` - `POST /sync` handler invoking `child_process.execSync()` with attacker-controlled filename
- `app.js` - `GET /sync` handler using the `name` query parameter without path normalization (secondary CWE-22)

## Impact

- **Remote Code Execution** with the privileges of the Scriptables Node.js process, no authentication required
- Secondary: **Arbitrary File Read** via path traversal on `GET /sync`

## Recommendation

The project is unmaintained (last commit December 2020) and no fix is planned. Users running Scriptables should:

- Take any internet-exposed instance offline immediately
- Never expose the default port (`5566`) to untrusted networks
- Migrate to an actively maintained alternative

## Details

Full PoC and exploitation walkthrough will be published after a coordinated disclosure window. Given the project is abandoned and the codebase is public, the technical details above are sufficient for users to assess their exposure and remediate.

## References

- [CWE-78: OS Command Injection](https://cwe.mitre.org/data/definitions/78.html)
- [CWE-22: Path Traversal](https://cwe.mitre.org/data/definitions/22.html)
- [Upstream repository](https://github.com/im3x/Scriptables)
