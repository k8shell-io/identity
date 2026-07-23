# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Build
make build                    # compiles to bin/identity

# Test
make test                     # unit tests with coverage (outputs reports/)
make test-static              # golangci-lint + gosec
make test-self                # static + build + smoke tests (what CI runs)
go test ./internal/...        # run tests for a specific package
go test -run TestFoo ./...    # run a single test by name

# Local dev
docker compose -f backend/compose.yaml up -d   # start Postgres
migrate -path db/migrations -database "postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable" up
./bin/identity --config config/config.yaml --logtext

# Docker image
make image                    # alpine (dev)
RUNTIME=distroless make image # production hardened
```

The `reports/` directory is created by `make install-test-deps` (called automatically by `make test`). Tests output JUnit XML there.

## Architecture

### Service overview

`identity` is the k8Shell Identity service — a gRPC server that manages user identities, authenticates via SSH public key or password, issues JWTs, and vends on-demand Kubernetes service-account tokens. It is part of the broader k8shell platform; API proto definitions live in the separate `github.com/k8shell-io/common` module.

### Request flow

```
gRPC client → IdentityService (identity.go)
                 ↓
             Server (server.go)       — orchestrates all subsystems
             ├── identity providers   — source of truth for user records
             ├── DB (internal/db/)    — Postgres persistence
             ├── JWT issuer/verifier  — token lifecycle
             ├── authz client         — policy evaluation (OPA/Rego via gRPC)
             ├── NATS client          — messaging/caching (optional)
             └── k8s client           — TokenRequest API for SA tokens
```

### Identity providers

Providers implement `identity.IdpClient` (from `common`). Two kinds exist:

- **`file`** (`internal/providers/file/`) — loads users from YAML files on disk. No onboarding. Used for local dev and testing. Provider name constant: `file.FILE_PROVIDER_NAME`.
- **`idp`** (remote) — gRPC client connecting to an external identity provider (e.g. GitHub, GitLab). Supports device-flow and web-flow OAuth onboarding.

Providers are stored in `Server.IdentityProviders` (name → client). Remote providers unavailable at startup are queued in `pendingProviderCfgs` and retried every 30 s in a background goroutine. Provider access is guarded by `Server.providerMu` (RWMutex). `orderedProviders()` always returns them in deterministic (name-sorted) order for consistent fallback behavior during user refresh.

### User lifecycle

Users are lazy-loaded: on first `GetUserByUsername`, if not in DB (or expired/invalid), `refreshUser` queries providers in order and upserts the record. On-boarding policy (`applyOnboardPolicy`) is evaluated against the authz service before a new user is persisted — it can grant/deny and attach obligations (sudo, roles, blueprints).

Without a DB (`db.enabled: false`), the server falls back to `getLocalUsers()` (file provider only) — all user lookups and token operations that require the DB return `codes.Unavailable`.

### Credentials

Three credential types stored in `identity.user_credentials`:

| `credential_source` | `service_name` | Resolution |
|---|---|---|
| `stored` | `registry`, `git` | Secret returned as-is from DB |
| `kubernetes` | `kubernetes` | Fresh SA token issued via TokenRequest API on every call |
| `<idp-name>` | `git` | Live `GetUserGitToken` RPC to the named provider |

Dynamic git credentials are provisioned at the end of `CompleteUserWebFlow` / `CompleteUserDeviceFlow`.

### Personal Access Tokens (PATs)

PATs (`k8sh_` prefix) are stored as `sha256(raw)` only — the raw token is returned once at creation and never stored. `ResolveAccessToken` is called by API gateways on every `k8sh_` request; it updates `last_used_at` and exchanges the PAT for a short-lived JWT. Scopes and expiry can be constrained by the `token:create` authz policy.

### Configuration

Loaded from YAML by `server.LoadConfig`. Secrets can be injected via:
- Environment variables: `${ENV_VAR}`
- File references: `!file /path/to/file`

See `config/config.yaml` for the full reference. Key sections: `grpc`, `db`, `jwtIssuer`, `localProviders`, `remoteProviders`, `kubernetes.saToken`, `authz`, `nats`.

### gRPC proto definitions

Defined in `github.com/k8shell-io/common`:
- `IdentityService` (`identity.proto`) — consumed by other k8shell services
- `IdentityProviderService` (`idp.proto`) — implemented by remote providers; identity connects as a client

If a `go.work` file is present and links `common` to a local filesystem path (e.g. `/opt/shared/common`), that checkout is a separate git repository from `identity`. Any proto/Go changes needed in `common` (new RPCs, messages, etc.) should be made directly in that local checkout and regenerated there with `make proto` — do not vendor or hand-copy generated code into `identity`. Do not `git commit` or push changes inside that `common` checkout unless the user explicitly asks — it's a shared module consumed by other services, and publishing a new version is the user's call, not something to do as a side effect of an `identity` change.

### Database schema

Schema lives in `db/migrations/` (golang-migrate). Tables: `identity.organizations`, `identity.users`, `identity.user_credentials`, `identity.access_tokens`. The `identity.users` record caches provider data and expires at `expires_at`; `is_valid=false` disables login without deletion.

### CI

CI (`build.yaml`) runs `make test-self` on PRs (non-draft) and pushes. Pushes to `v*` tags additionally build and push a distroless image to `registry.k8shell.io`. PR builds produce alpine images tagged `pr-<N>-<sha>`.
