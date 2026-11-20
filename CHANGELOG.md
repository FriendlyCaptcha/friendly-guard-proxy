## 0.2.2

- Give fail-open passes a fixed two-minute lifetime.

## 0.2.1

- Add the `pass_ttl_seconds` configuration option for controlling pass cookie lifetime. The default remains 15 minutes.

## 0.2.0

- Add optional query parameter conditions to guarded routes.
- **Breaking configuration change:** prefix existing route entries with `path:`, e.g. `- '^/protected$'` becomes `- path: '^/protected$'`.

## 0.1.1

- Compress the interstitial with gzip when the browser accepts it.
- Send a `Link: <api origin>; rel=preconnect` header with the interstitial.

## 0.1.0

Initial release.
