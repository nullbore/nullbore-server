# nullbore-server

The NullBore relay/discovery server. Accepts client connections, brokers tunnels, enforces TTLs, and exposes a REST API.

## Architecture

- **Protocol:** WebSocket over TLS for tunnel connections
- **API:** REST (JSON) for tunnel management
- **Auth:** Bearer token (API keys)
- **Storage:** In-memory tunnel registry (persistent state via dashboard DB)
- **Mode:** Relay-only in v1; direct handoff planned for v3

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

## API

See [API docs](../nullbore-dashboard/README.md) for the full REST spec.

## License

MIT
