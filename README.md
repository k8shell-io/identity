# identity

[![Build](https://github.com/k8shell-io/identity/actions/workflows/build.yaml/badge.svg)](https://github.com/k8shell-io/identity/actions/workflows/build.yaml)

The k8Shell Identity service. Manages user identities, authenticates users via SSH public key or password, issues JWTs, manages per-user external credentials, and provides on-demand Kubernetes service-account tokens via the TokenRequest API.

## Concepts

### Identity providers

Identity is built around pluggable providers. A provider is the source of truth for a user record.

| Type | Description |
|---|---|
| **Local** (`file`) | Users loaded from YAML files on disk. No onboarding. Good for development and testing. |
| **Remote** (`idp`)  | gRPC-connected external provider (e.g. GitHub, GitLab). Supports device-flow and web-flow onboarding. |

Users are cached in Postgres and refreshed from the provider when the cached record expires. Remote providers unavailable at startup are retried every 30 seconds in the background.

### Organizations

Every user belongs to exactly one organization (tenant). Organizations referenced by incoming users can be created automatically via the `organizations.autoCreate` config list (use `["*"]` to allow all).

### JWT token lifecycle

On login the service issues a signed JWT for the authenticated user. Tokens are issued on demand — there is no background refresh loop and no token state is stored in the database.

### Personal Access Tokens (PATs)

Users can hold long-lived Personal Access Tokens with scope restrictions. PATs use the `k8sh_` prefix and are stored as `sha256(raw)` only — the raw value is returned once at creation. API gateways call `ResolveAccessToken` on every `k8sh_` request; the service verifies the token, updates `last_used_at`, and exchanges it for a short-lived JWT. PAT scopes and maximum expiry can be constrained by the `token:create` authz policy. PATs can also be provisioned automatically during web-flow onboarding.

### User credentials

The service stores per-user credentials for external services. Resolution is controlled by `credential_source`:

| `credential_source` | `service_name` | How the secret is resolved |
|---|---|---|
| `stored` | `registry`, `git` | Secret returned as-is from the database |
| `kubernetes` | `kubernetes` | Fresh bound SA token issued via TokenRequest API on every call |
| `<idp-name>` | `git` | Live `GetUserGitToken` RPC to the named provider |

Dynamic git credentials are provisioned automatically at the end of device-flow and web-flow onboarding.

### Kubernetes service-account tokens

When a credential with `credential_source: kubernetes` is resolved, the service issues a fresh, short-lived bound service-account token on demand via the Kubernetes TokenRequest API. No token is stored — every request results in a new token issued directly from the cluster. The TTL is controlled by `kubernetes.saToken.ttl` in the service configuration.

### Authorization policies

The service integrates with an external authz service (gRPC) to enforce OPA/Rego policies at key lifecycle points:

- **`user:onboard`** — evaluated before a new user is persisted. Can deny onboarding or attach obligations (sudo, roles). Blueprint access is derived from whichever roles are granted, not a direct obligation.
- **`user:auth`** — evaluated on each authentication attempt.
- **`token:create`** — evaluated before issuing a PAT. Can restrict scopes or maximum expiry.

The authz client is optional; all policy checks are no-ops when `authz` is not configured.

### gRPC API

The service exposes two gRPC interfaces defined in the separate `github.com/k8shell-io/common` module:

- `IdentityService` (`identity.proto`) — user lookup, authentication, onboarding, credential management, PAT lifecycle. Consumed by other k8shell services.
- `IdentityProviderService` (`idp.proto`) — implemented by remote identity providers. Identity connects to them as a client. No other service accesses this interface directly.

## Repository layout

```
internal/
  db/          # Postgres access (users, credentials, access tokens)
  providers/
    file/      # File-backed identity provider
  server/      # gRPC server, JWT issuance, credential resolution, policy evaluation
db/migrations/ # SQL migrations (golang-migrate)
backend/       # Docker Compose for local Postgres
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
| `release` | `distroless/static-debian12:nonroot` | Production (no shell, runs as non-root) |

Both stages use the same statically compiled binary (`CGO_ENABLED=0`, `-ldflags="-s -w"`).

## Running in Kubernetes

Deployment configuration and Helm charts for identity and the other k8shell services are maintained in the [k8shell-io/charts](https://github.com/k8shell-io/charts) repository.

## License

AGPL-3.0-or-later. See [LICENSE](LICENSE).
