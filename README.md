# Friendly Guard Proxy

Friendly Guard Proxy is a Go reverse proxy that protects your application from bot traffic and abuse.
It is deployed in front of one upstream application and requires no changes to that application.

The proxy handles route enforcement, calls the Friendly Guard decision API, serves the returned
interstitial ([explained below](#browser-check-and-challenge)), and issues a local pass cookie after an `ALLOW` decision. The API owns decision IDs,
browser-check and challenge state, proof validation, and interstitial HTML. The state exchanged with the browser is an
opaque screening context; Friendly Guard Proxy does not parse or persist it.

```text
Browser -> Load balancer (optional) -> Friendly Guard Proxy -> Upstream application
                                             |
                                             +-------------> Friendly Guard API
```

## Requirements

- Go 1.26 or newer when building from source.
- A Friendly Guard sitekey and server-side API key.
- One HTTP or HTTPS upstream origin.
- TLS termination in front of Friendly Guard Proxy for production deployments. The binary itself serves HTTP.

## Quick Start

Build the binary from this directory:

```sh
go build -o friendly-guard-proxy ./cmd/friendly-guard-proxy
```

Create a `friendly-guard-proxy.yml` configuration file. You can base it on the example in `example.friendly-guard-proxy.yml`.

Start Friendly Guard Proxy:

```sh
FRIENDLY_GUARD_API_KEY=<API_KEY> ./friendly-guard-proxy
```

Use `-config /path/to/config.yml` to load a different file and `-log-level debug` to enable per-request debug logs.

## Configuration

Environment variables are expanded before YAML is decoded. Unknown YAML fields are rejected, and the proxy
refuses to start without at least one guarded route. This prevents a misspelled security setting from silently disabling
protection.

| Field                                | Required | Default   | Description                                                                                                                            |
| ------------------------------------ | -------- | --------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| `server.listen`                      | No       | `:8080`   | Address on which the proxy serves HTTP.                                                                                                |
| `upstream.origin`                    | Yes      |           | HTTP or HTTPS upstream URL. A path in this URL becomes a base path for proxied requests.                                               |
| `friendly_guard_api.api_endpoint`    | No       | `eu`      | `eu` (`https://eu.frcapi.com`), `global` (`https://global.frcapi.com`), or a full Friendly Guard API URL.                              |
| `friendly_guard_api.sitekey`         | Yes      |           | Sitekey protected by this proxy instance.                                                                                              |
| `friendly_guard_api.api_key`         | Yes      |           | API key used to authenticate requests to the Friendly Guard decision API.                                                              |
| `friendly_guard_api.timeout_seconds` | No       | `5`       | Timeout for each decision API request.                                                                                                 |
| `pass_signing_secret`                | No       | Generated | Secret used to sign local pass cookies. Must be at least 32 bytes when set. If unset, the proxy generates an ephemeral 32-byte secret. |
| `pass_request_limit`                 | No       | `100`     | Protected upstream requests allowed per pass before re-screening. Set to `0` to disable rate limiting.                                 |
| `guarded_routes`                     | Yes      |           | Non-empty list of Go regular expressions identifying protected URL paths.                                                              |
| `trusted_proxies`                    | No       | Empty     | CIDR ranges allowed to supply trusted forwarding headers.                                                                              |
| `failure_mode`                       | No       | `open`    | Behavior for transient decision failures and unknown outcomes: `open` or `closed`.                                                     |
| `dry_run`                            | No       | `false`   | Record decisions without enforcing valid `BLOCK` or `CHALLENGE` outcomes.                                                              |
| `block_redirect_url`                 | No       |           | Full HTTP(S) URL to redirect the browser to after a `BLOCK` decision.                                                                  |

Changing `pass_signing_secret` invalidates all existing pass cookies. A configured secret must be at least
32 bytes. Every replica must use the same secret. A pass signed by one replica is rejected by another replica
that has a different secret, and the browser is sent through screening again. If the secret is unset, the proxy
logs a warning and generates an in-memory 32-byte secret for the lifetime of that process, so pass cookies are
invalidated on restart and are not valid on any other replica. Set an explicit secret before running more than
one replica.

## Request Flow

Friendly Guard Proxy makes its enforcement decision before proxying a request.

1. The proxy handles the exact paths `/__friendly-guard/v1/healthz` and `/__friendly-guard/v1/continue` itself. These exact paths
   are never sent upstream.
2. Checks the `friendly_guard_pass` cookie. Invalid, expired, wrongly bound, or wrong-site cookies are cleared.
3. Checks the request path against every `guarded_routes` expression.
4. An unprotected route or an `OPTIONS` request is proxied immediately.
5. A protected request with a valid pass is proxied if its request limit has not been exhausted (or if rate limiting is disabled).
6. An exhausted pass is cleared and treated like a missing pass.
7. A protected request without a pass is handled according to its method:
   - `GET` enters the decision flow.
   - `HEAD`, `POST`, `PUT`, `PATCH`, `DELETE`, and other methods receive `403 Forbidden`.

Friendly Guard Proxy does not buffer and replay unsafe request bodies through an interstitial. Applications should first serve a
protected `GET` that obtains a pass, after which forms and API calls on protected routes can proceed normally.

### Route Matching

Queries are not part of route matching. Friendly Guard Proxy tests each regular expression against both the original URL path and its
`path.Clean` normalized form. The request is protected if either form matches.

For example, with `^/protected(/.*)?$`, all of these requests are protected:

```text
/protected/
/protected/../public
/public/../protected
/public%3F/../protected
```

This prevents the proxy and an upstream router from reaching different security decisions when one of them
normalizes dot segments. The proxy still forwards the original path unchanged; normalization is only an
additional protection check.
Encoded question marks (`%3F`) are path characters and remain part of path normalization; actual query strings are excluded.
Anchor route expressions with `^` and `$` when the whole path should match.

### Prescreen

For a protected `GET` without a valid pass, Friendly Guard Proxy sends `POST /api/v2/guard/prescreen` to the configured API endpoint.
The request contains the sitekey and a request context with:

- Canonical client IP.
- Method, scheme, host, and normalized path.
- `User-Agent`, `Accept`, `Accept-Language`, `Signature`, `Signature-Input`, `Signature-Agent` and `Sec-Fetch-*` request headers.

Authorization headers, cookies, request bodies, and query strings are not included in this context.

The prescreen decision has one of these outcomes:

| Outcome | Friendly Guard Proxy behavior                                                                            |
| ------- | -------------------------------------------------------------------------------------------------------- |
| `ALLOW` | Set a 15-minute pass cookie and proxy the original request.                                              |
| `BLOCK` | Redirect to `block_redirect_url` when configured; otherwise return a non-cacheable `403 Forbidden` page. |
| `CHECK` | Return the non-cacheable interstitial HTML on the protected URL.                                         |

### Browser Check And Challenge

An interstitial is a temporary page shown in place of a requested protected page while Friendly Guard checks the browser.

The interstitial runs the Friendly Captcha SDK on the protected URL. It obtains a risk token and posts it, together with
the opaque screening context, to the same-origin endpoint:

```text
POST /__friendly-guard/v1/continue
```

The continuation endpoint forwards the sitekey, screening context, and proof fields to `POST /api/v2/guard/decide`.

| Outcome     | Friendly Guard Proxy behavior                                                                                                                              |
| ----------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ALLOW`     | Set the pass cookie and return `{ "outcome": "ALLOW" }`. The interstitial reloads the current protected URL.                                               |
| `BLOCK`     | Do not issue a pass. The interstitial redirects to `block_redirect_url` when configured; otherwise it displays the blocked state.                          |
| `CHALLENGE` | Return the rotated screening context. The interstitial starts the Friendly Captcha widget and submits its response through the same continuation endpoint. |

After a successful challenge, the final `ALLOW` response sets the pass cookie and the browser reloads the same URL.
The proxy does not store the original URL and does not use a redirect query parameter.

### Dry Run

Set `dry_run: true` to evaluate Friendly Guard without enforcing `BLOCK` or `CHALLENGE` decisions and without presenting captcha
challenges. Protected non-`GET` methods without a pass still receive `403 Forbidden` and never reach the decision API. The proxy still
performs prescreening for protected `GET` requests and returns the browser-check interstitial for `CHECK`, allowing the decision API
to evaluate the risk token. A valid `BLOCK` or `CHALLENGE` response is then treated as `ALLOW`: the proxy issues a pass and the browser
continues to the protected route. The decision API thus still receives the requests and records its original outcomes before the proxy overrides enforcement.

Because dry run allows `CHALLENGE` instead of presenting the captcha, it cannot observe challenge-completion results. In particular,
challenge-phase blocks caused by invalid, expired, duplicate, or unsuccessful captcha responses do not occur in this mode. Use the
number of `CHALLENGE` decisions as the measure of requests that would have experienced additional friction.

## Pass Cookie

Friendly Guard Proxy issues a stateless JWT in the `friendly_guard_pass` cookie. The cookie has fixed behavior:

- `HttpOnly`
- `SameSite=Lax`
- `Path=/`
- `Secure` when the proxy determines that the external request used HTTPS

The JWT is signed with HS256 using the configured pass signing secret. It contains issued-at and expiry timestamps, is scoped to
the configured sitekey through its audience, and is bound to the browser's User-Agent.

Every pass, including fail-open passes, has a fixed lifetime of 15 minutes. The cookie is only a clearance signal; it must not
be treated as application authentication or authorization by the upstream.

When rate limiting is enabled, the proxy keeps a bounded in-memory request count keyed by each signed
pass's JWT ID (`jti`). The protected request that receives a pass from prescreen counts as the first request; a pass
received from the continuation endpoint starts counting when the interstitial reloads the protected page. After
`pass_request_limit` protected requests, the next protected `GET` starts a new screening flow. Unsafe methods continue
to receive `403` until a new pass is obtained.

Request counts are local to each proxy process and are not retained across restarts. Each replica enforces
`pass_request_limit` on its own, so the effective limit across a fleet is higher than the configured value.

When TLS terminates at a load balancer, that load balancer must be configured as a trusted proxy and must set `X-Forwarded-Proto: https` for the proxy to add the `Secure` attribute.

## Failure Behavior

`failure_mode` applies to network errors, timeouts, decision API `5xx` responses whose body is valid JSON, and unknown decision outcomes.

### `open`

Friendly Guard Proxy issues a 15-minute pass when a transient failure occurs:

- During prescreen, the proxy sets the pass and proxies the original request.
- During continuation, the proxy sets the pass and returns `ALLOW` so the interstitial can reload without looping.

### `closed`

Friendly Guard Proxy does not issue a pass and returns an error response.

Decision API `4xx` responses, malformed JSON, missing required response fields, and invalid client continuation payloads
never fail open.

Fail-open improves availability but deliberately permits traffic during a Friendly Guard outage. Choose the mode as
part of the application's security and availability policy.

## Reverse Proxy Behavior

Friendly Guard Proxy uses Go's `httputil.ReverseProxy` and preserves ordinary reverse-proxy semantics:

- Request methods, bodies, query strings, and the original path are forwarded.
- Upstream response status, headers, cookies, body, and streaming behavior are preserved.
- Hop-by-hop headers are removed by the Go reverse proxy.
- The `Forwarded` header is removed and is not rewritten.
- An unavailable upstream returns `502 Bad Gateway`.

`upstream.origin` determines the outbound scheme and host. Its optional path is prepended as a base path. The outbound
`Host` is the upstream host, while the original external host is sent as `X-Forwarded-Host`.

The proxy replaces the canonical proxy identity headers before forwarding:

- `X-Real-IP`: the resolved client IP.
- `X-Forwarded-For`: the sanitized client and trusted-proxy chain, with the direct peer appended.
- `X-Forwarded-Host`: the external host.
- `X-Forwarded-Proto`: the external scheme.

Upstream applications should use these canonical headers from the proxy and must not prioritize unrelated
client-IP headers that may have arrived from the public request.

## Trusted Proxies

Forwarding headers are attacker-controlled unless the direct socket peer is trusted. Friendly Guard Proxy therefore uses
`trusted_proxies` as a network trust boundary.

When the direct peer is not trusted:

- `X-Forwarded-For`, `X-Forwarded-Host`, and `X-Forwarded-Proto` are ignored.
- The socket peer is the client IP.
- The inbound host and direct TLS state determine the external host and scheme.

When the direct peer is trusted:

- Friendly Guard Proxy scans `X-Forwarded-For` from right to left, skips configured trusted proxies, and selects the first untrusted IP
  as the client. If every address in the chain is a trusted proxy, the leftmost address is the client.
- If `X-Forwarded-For` is absent, the proxy accepts a valid single `X-Real-IP` value from the trusted peer as the client.
- Values to the left of that client are discarded because they may have been supplied by the visitor. Malformed values in that
  discarded portion are ignored.
- A malformed address encountered while scanning from the right, including a malformed client address, invalidates XFF and causes
  the proxy to fall back to the socket peer.
- The proxy accepts bare IPv4 and IPv6 addresses in XFF. Configure the load balancer not to include client ports.
- The proxy uses the first `X-Forwarded-Host` value and the first `X-Forwarded-Proto` value. It does not reject additional header
  values, a comma-separated list, or a scheme other than `http` or `https`. The trusted proxy should still send one value for each,
  and `X-Forwarded-Proto: https` when the external request used HTTPS.

Configure the narrowest possible CIDRs for the load balancer or proxy instances. If Friendly Guard Proxy directly
receives public traffic, leave `trusted_proxies` empty so all forwarding headers are ignored.

## Operational Endpoints

### `GET /__friendly-guard/v1/healthz`

Returns `200 OK` with the body `ok` followed by a newline. This is a process health check and does not call the upstream or Friendly Guard API.

### `POST /__friendly-guard/v1/continue`

Reserved for the browser-check and challenge flow. It only accepts `application/json` and is never proxied upstream.

Friendly Guard Proxy handles `SIGINT` and `SIGTERM` with graceful HTTP shutdown. Use `-log-level` with `debug`, `info`,
`warn`, or `error` to control log verbosity. Debug logs include request-level routing and decision logs; normal
informational logs are limited to startup and significant events. API keys, pass cookies, screening contexts, risk
tokens, and captcha responses are not logged.

## Building

```sh
go build -o friendly-guard-proxy ./cmd/friendly-guard-proxy
```

Use `./friendly-guard-proxy -version` to print the version and build metadata.
Source builds default to version `0.0.0`; GoReleaser injects the release version,
commit date, and full commit hash.

To build release artifacts locally without publishing, install GoReleaser v2 and run:

```sh
goreleaser release --snapshot --clean
```

Artifacts are written to `dist/`.

## Testing

```sh
go test ./...
```

The tests start local HTTP servers and do not need a running upstream, a Friendly Guard API, or a configuration file.

## License

Friendly Guard Proxy is licensed under the [MIT License](./LICENSE).
