# nullbore-server

The NullBore relay/discovery server. Accepts client connections, brokers tunnels, enforces TTLs, and exposes a REST API.

## Architecture

- **Protocol:** WebSocket over TLS for tunnel connections
- **API:** REST (JSON) for tunnel management
- **Auth:** Bearer token (API keys)
- **Storage:** In-memory tunnel registry (persistent state via dashboard DB)
- **Modes:** per tunnel — `relay` (default: the relay terminates TLS and proxies HTTP) or `tls-passthrough` (end-to-end TLS: the relay routes by SNI and forwards ciphertext; see below). Direct handoff (relay as rendezvous only) is still planned for v3

## Quick Start

```bash
go build -o nullbore-server ./cmd/server
./nullbore-server --port 8443
```

## Docker

```bash
docker build -t nullbore-server .
docker run -p 8443:8443 nullbore-server
```

## Configuration

Environment variables:

| Var | Default | Description |
|-----|---------|-------------|
| `NULLBORE_PORT` | `8443` | Server listen port |
| `NULLBORE_HOST` | `0.0.0.0` | Bind address |
| `NULLBORE_TLS_CERT` | `` | TLS certificate path |
| `NULLBORE_TLS_KEY` | `` | TLS key path |
| `NULLBORE_API_KEYS` | `` | Comma-separated valid API keys (dev mode) |

## TLS passthrough (end-to-end encryption)

A tunnel created with `"mode": "tls-passthrough"` is routed by the TLS
ClientHello's SNI **without terminating TLS**. The relay peeks the
ClientHello, matches the hostname with the same rules as HTTP Host routing
(`<slug>.<base-domain>`, `<leaf>.<account>.<account-domain>`, custom
domains), and pipes the raw bytes — ClientHello included — through the
tunnel to your local port. Your own server completes the handshake with your
own certificate and key; the relay never holds a key for the session and
only ever sees ciphertext.

```bash
curl -X POST https://tunnel.nullbore.com/v1/tunnels \
  -H "Authorization: Bearer $NULLBORE_API_KEY" \
  -d '{"local_port": 8443, "mode": "tls-passthrough"}'
```

- **Your local service must speak TLS itself** (the tunnel client just
  carries bytes; no client change is needed). Bring your own certificate:
  self-signed plus fingerprint pinning in your app works, as does a publicly
  trusted certificate you obtain yourself.
- **Paid tiers only** (`basic`/`plus`/`pro`, same gate as idle TTL; `403`
  otherwise). Callers without a tier — e.g. static `--api-keys` deployments —
  are currently rejected too.
- **Only on a TLS-enabled relay** (`--tls-cert`/`--tls-key` or ACME). The
  mode is per tunnel; there is no server flag. Persisted with the tunnel, so
  it survives restarts.
- **Kept:** TTL/expiry, idle-TTL touch, suspension, the owner's IP allowlist
  (checked against the TCP peer — there is no `X-Forwarded-For` without
  HTTP), per-tunnel rate limiting (one token per connection), byte counting
  / bandwidth accounting, offline handling.
- **Unavailable**, because they need plaintext: basic auth
  (`auth_user`/`auth_pass` with this mode is a `400`), request inspection and
  replay (`request_log` never records anything for these tunnels; enabling
  inspection is a `400`), body-size limits, response-status sniffing.
- **Failures are silent closes.** The relay holds no certificate for the
  hostname, so it cannot send a readable error for a suspended, expired,
  rate-limited, IP-blocked or offline tunnel — the client sees the TLS
  handshake fail.
- **Never exposed in cleartext by accident.** If a passthrough tunnel is
  reached any way other than by SNI — plain HTTP, Host-header routing after
  the relay (or a proxy in front of it) terminated TLS, or `/t/{slug}` — the
  relay answers with the same generic `404` as a nonexistent tunnel. A `421`
  would be more descriptive but would confirm the tunnel exists, so `404` is
  used to keep every non-match indistinguishable.
- **What the relay can still see:** the SNI hostname (the ClientHello is
  plaintext; ECH is not supported), client IP, timing and byte counts.
- Like relay mode, a single relayed connection is closed after 10 minutes
  (`relayTimeout`), so clients should reconnect long-lived sessions.

### DNS: the hostname must not be proxied

The guarantee holds only if the ClientHello reaches the relay intact. A
hostname proxied by Cloudflare (orange cloud) or any other TLS-terminating
CDN/load balancer is **not** end-to-end: the proxy terminates the user's TLS
with its own certificate and can read the traffic (with Cloudflare "Full"
SSL it would then re-encrypt to your server; with "Full (strict)" the
self-signed origin certificate is rejected). Passthrough hostnames must be
**DNS-only** records pointing at the relay's own address (or a CDN mode that
forwards raw TCP without terminating TLS). DNS is managed outside this
server.

For account tunnels there is a dedicated end-to-end namespace,
`{tunnel}.{account}.e2e.{account-domain}` (e.g.
`books.abookify.e2e.nullbore.com`), so an account's passthrough hostnames
can be DNS-only while its ordinary `{tunnel}.{account}.{account-domain}`
hostnames stay behind the CDN. One DNS-only wildcard per account
(`*.{account}.e2e.{account-domain}` → relay IP) covers it. The e2e namespace
only ever routes tls-passthrough tunnels; anything else there, and any
plain-HTTP or TLS-terminated request to it, gets the generic 404.

### Verifying it

Run from outside your LAN. The presented fingerprint must equal your own
certificate's, and a request pinned to your key must succeed — a completed
handshake with your certificate proves the peer holds your private key:

```bash
openssl s_client -connect <host>:443 -servername <host> </dev/null 2>/dev/null \
  | openssl x509 -noout -fingerprint -sha256
curl --pinnedpubkey "sha256//<base64 SPKI of your cert>" https://<host>/
```

Informational: `<host>` should resolve to the relay's own IP, and responses
should carry no `server: cloudflare` / `cf-*` headers.

## API

See [API docs](../nullbore-dashboard/README.md) for the full REST spec.

## License

MIT
