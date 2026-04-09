# identity

[![Self-Tests](https://github.com/k8shell-io/identity/actions/workflows/self-tests.yaml/badge.svg)](https://github.com/k8shell-io/identity/actions/workflows/self-tests.yaml)

The k8Shell Identity service. Manages user identities, authenticates users via SSH public key or password, issues JWTs, and stores per-user tokens as Kubernetes Secrets so other k8shell components can verify access without hitting the database.

## Concepts

### Identity providers

Identity is built around pluggable providers. A provider is the source of truth for a user record.

| Type | Description |
|---|---|
| **Local** (`file`) | Users loaded from YAML files on disk. No onboarding. Good for development and testing. |
| **Remote** (`idp`)  | gRPC-connected external provider (e.g. GitHub). Supports device-flow and web-flow onboarding. |

A user record is cached in Postgres after the first login. On subsequent requests the cache is refreshed when `expires_at` has passed.

### JWT token lifecycle

On login the service issues a JWT and stores:
- The JTI (`current_token_id`) and expiry in Postgres (when DB is configured).
- The token string in a Kubernetes Secret named `identity-token-<username>`.

#### Background refresh

A background loop continuously re-issues tokens for users whose tokens are near expiry. The coordination mechanism depends on whether a database is available:

**DB path** (`db.enabled: true`)

All instances run the refresh loop independently. Coordination uses `SELECT FOR UPDATE SKIP LOCKED` on the `identity.users` table:
1. Each instance atomically claims a batch of users whose `token_expires_at < now + lookahead` and writes a short-lived `token_refresh_claimed_until` lease.
2. Only the claiming instance processes each user - others skip locked rows.
3. On success, `current_token_id` and `token_expires_at` are updated and the claim is cleared.

This spreads refresh work across all instances with no coordination overhead beyond Postgres.

**No-DB path** (file provider only)

All user state is in memory. To prevent multiple instances from simultaneously issuing different tokens for the same user (last-writer-wins on the Secret, but callers holding the losing token would be invalidated), exactly one instance runs the refresh loop at a time using a **Kubernetes Lease** (leader election):
- `LeaseDuration`: 60s — how long a lease is valid.
- `RenewDeadline`: 30s — how long the leader tries to renew before giving up.
- `RetryPeriod`: 5s — how often non-leaders attempt to acquire the lease.

If the leader crashes (without graceful shutdown), the lease expires in up to ~65s before a new leader is elected.

#### On-demand handling (missing secret)

When a client requests a token and the Kubernetes Secret does not exist (e.g. manually deleted), the service recovers without waiting for the next scheduled tick:

| Situation | Behaviour |
|---|---|
| **DB path — any instance** | Marks `token_expires_at = NOW()` in DB (clears any claim), evicts local cache, triggers immediate refresh cycle on this instance. Polls the Secret for up to 10s. |
| **No-DB path — leader instance** | Issues and stores the token immediately. |
| **No-DB path — non-leader instance** | Evicts local cache, signals the local refresh goroutine (no-op if this is not the leader). Polls the Secret for up to 10s while the leader re-issues it. |

The 10s poll timeout is chosen to cover the worst-case leader response time (`RetryPeriod` + Kubernetes API latency).

### gRPC API

The service exposes two gRPC services defined in a separate common repository at `pkg/api/identity/v1`:

- `IdentityService` (`identity.proto`) — user lookup, authentication, onboarding, credential management. Consumed by other k8shell components.
- `IdentityProviderService` (`idp.proto`) — implemented by remote identity providers. Identity connects to them as a client.

## Repository layout

```
internal/
  db/          # Postgres access (users, external credentials, token refresh)
  providers/
    file/      # File-backed identity provider
  server/      # gRPC server, JWT issuance, Kubernetes secret management
db/migrations/ # SQL migrations (golang-migrate)
config/        # Example configuration and user files
docker/        # Dockerfile (alpine + distroless stages)
```

## Prerequisites

- Go 1.24+
- Docker
- A running Postgres instance (see `backend/compose.yaml`)

## Local development

**Start Postgres:**
```bash
docker compose -f backend/compose.yaml up -d
```

**Run database migrations** (use [golang-migrate](https://github.com/golang-migrate/migrate)):
```bash
migrate -path db/migrations -database "postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable" up
```

**Build and run:**
```bash
make build
./bin/identity --config config/config.yaml --logtext
```

**Configuration** is a YAML file. Secrets and connection parameters can be injected via environment variables or `!file` references. See `config/config.yaml` for the full reference.

## Makefile targets

| Target | Description |
|---|---|
| `make build` | Compile binary to `bin/identity` |
| `make test` | Run unit tests with coverage |
| `make test-static` | Run `golangci-lint` and `gosec` |
| `make test-self` | Static analysis + build + smoke tests (used in CI) |
| `make image` | Build Docker image (Alpine by default) |
| `RUNTIME=distroless make image` | Build production-hardened distroless image |
| `make vendor` | Vendor Go dependencies |

## Docker images

Two runtime stages are available in `docker/identity/Dockerfile`:

| Stage | Base | Use case |
|---|---|---|
| `alpine` | `alpine:3.21.3` | Development, debugging (has a shell) |
| `distroless` | `distroless/static-debian12:nonroot` | Production (no shell, runs as non-root) |

Both stages use the same statically compiled binary (`CGO_ENABLED=0`, `-ldflags="-s -w"`).

## Running in Kubernetes

Deployment configuration and Helm charts for identity and the other k8shell services are maintained in the [k8shell-io/charts](https://github.com/k8shell-io/charts) repository.

## License

AGPL-3.0-or-later. See [LICENSE](LICENSE).
