# identity

[![Self-Tests](https://github.com/k8shell-io/identity/actions/workflows/self-tests.yaml/badge.svg)](https://github.com/k8shell-io/identity/actions/workflows/self-tests.yaml)

The k8Shell Identity service. Manages user identities, authenticates users via SSH public key or password, issues JWTs, and provides on-demand Kubernetes service-account tokens via the TokenRequest API.

## Concepts

### Identity providers

Identity is built around pluggable providers. A provider is the source of truth for a user record.

| Type | Description |
|---|---|
| **Local** (`file`) | Users loaded from YAML files on disk. No onboarding. Good for development and testing. |
| **Remote** (`idp`)  | gRPC-connected external provider (e.g. GitHub). Supports device-flow and web-flow onboarding. |

### JWT token lifecycle

On login the service issues a signed JWT for the authenticated user. Tokens are issued on demand — there is no background refresh loop and no token state is stored.

### Kubernetes service-account tokens

The identity service acts as a credential helper for k8shell workspace components that need to authenticate to Kubernetes. When a credential with source `kubernetes` is resolved, the service issues a fresh, short-lived bound service-account token on demand via the Kubernetes TokenRequest API. No token is stored — every request results in a new token issued directly from the cluster. The token TTL is controlled by `kubernetes.saToken.ttl` in the service configuration.

### gRPC API

The service defines two gRPC interfaces defined in a separate common repository at `pkg/api/identity/v1`:

- `IdentityService` (`identity.proto`) — user lookup, authentication, onboarding, credential management. Consumed by other k8shell services.
- `IdentityProviderService` (`idp.proto`) — implemented by remote identity providers. Identity connects to them as a client. No other service accesses this interface directly. 

## Repository layout

```
internal/
  db/          # Postgres access (users, external credentials)
  providers/
    file/      # File-backed identity provider
  server/      # gRPC server, JWT issuance, Kubernetes SA token issuance
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
