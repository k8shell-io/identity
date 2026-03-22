# identity

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

On login the service issues a JWT (RS256 by default) and stores:
- The JTI (`current_token_id`) and expiry in Postgres.
- The token string in a Kubernetes Secret named `<secretPrefix><username>`.

A background loop continuously re-issues tokens for users whose tokens are near expiry:
- **DB configured** — uses `SELECT FOR UPDATE SKIP LOCKED` so multiple instances share the work.
- **File provider only** — uses Kubernetes Lease leader election so exactly one instance runs the loop.

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
