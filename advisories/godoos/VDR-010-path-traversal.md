# VDR-010: Critical Unauthenticated Path Traversal in GodoOS (14+ endpoints)

- **Target**: [phpk/godoos](https://github.com/phpk/godoos)
- **Severity**: Critical (CVSS 3.1: 9.8 - `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`)
- **CWE**: [CWE-22](https://cwe.mitre.org/data/definitions/22.html) - Path Traversal
- **CVE**: Pending
- **Discovered**: 2026-03-20
- **Researcher**: Dennis Sepede - [Securitix Solutions](https://securitixsolutions.com)

## Summary

GodoOS exposes 14+ unauthenticated file-operation endpoints that pass user-controlled paths directly to `filepath.Join(basePath, userInput)` with no traversal validation. Combined with no authentication and `Access-Control-Allow-Origin: *`, any browser visiting an attacker page or any network-reachable client can read, write, delete, rename or chmod arbitrary files on the host filesystem.

The intended `validateFilePath()` in `godo/files/os.go:58` only checks if the path is empty - it does NOT block `..` traversal sequences.

## Affected Endpoints (all unauthenticated)

- `GET /file/readfile?path=` - arbitrary file read
- `POST /file/writefile?path=` - arbitrary file write
- `GET /file/unlink?path=` - arbitrary file deletion
- `GET /file/rmdir?dirPath=` - arbitrary directory deletion
- `POST /file/rename?oldPath=&newPath=` - arbitrary file move
- `POST /file/copyfile?srcPath=&dstPath=` - arbitrary file copy
- `POST /file/mkdir?dirPath=` - arbitrary directory creation
- `POST /file/chmod` - arbitrary permission change
- `POST /file/appendfile?filePath=` - arbitrary file append
- `POST /file/unzip?path=` - Zip Slip ([CWE-22](https://cwe.mitre.org/data/definitions/22.html))
- `GET /file/read?path=`, `GET /file/stat?path=`, `GET /file/search?path=`, `POST /file/zip?path=`

## Affected Code

- `godo/files/os.go:58` - `validateFilePath()` only rejects empty paths
- All file handlers - `filepath.Join(basePath, userInput)` without normalization or `HasPrefix` containment check
- `godo/files/unzip.go:77` and `godo/files/unzip.go:176` - no `HasPrefix` check after `filepath.Join` with archive entry names (Zip Slip)

## Status

| Date | Event |
|------|-------|
| 2026-03-20 | Vulnerability discovered and confirmed with working PoC |
| 2026-03-20 | Reported via GitHub issue [#10](https://github.com/phpk/godoos/issues/10) |
| - | Awaiting maintainer response |

## Impact

- **Arbitrary file read** with the privileges of the GodoOS process - read SSH keys, configuration, credentials
- **Arbitrary file write** - overwrite system files, drop web shells, plant cron jobs
- **Arbitrary file deletion** - destructive denial of service
- Browser-based exploitation thanks to `Access-Control-Allow-Origin: *` (no origin check, no token)

## Recommendation

- Add a `HasPrefix(filepath.Clean(filepath.Join(basePath, userInput)), basePath)` containment check to `validateFilePath()` and apply it before every file operation
- Add authentication to all file endpoints
- Tighten CORS to specific allowed origins (or remove the wildcard)
- Validate ZIP entry paths against the destination directory before extraction

## References

- [GitHub issue #10](https://github.com/phpk/godoos/issues/10)
- [CWE-22: Path Traversal](https://cwe.mitre.org/data/definitions/22.html)
- [Snyk: Zip Slip Vulnerability](https://security.snyk.io/research/zip-slip-vulnerability)
