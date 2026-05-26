# syntax=docker/dockerfile:1
# Copyright 2025 the k8Shell authors.
# SPDX-License-Identifier: AGPL-3.0-or-later

# -- Build stage ---------------------------------------------------------------
# Compiles a fully static binary. CGO_ENABLED=0 ensures the binary runs on
# Alpine or distroless final images without requiring glibc.
# VERSION and COMMIT_ID are injected at build time by the `make image` target
# and baked into the binary via -ldflags -X.
FROM registry.k8shell.io/docker/library/golang:1.24.5 AS build-debug

ARG VERSION
ARG COMMIT_ID

LABEL VERSION=$VERSION
LABEL COMMIT_ID=$COMMIT_ID

WORKDIR /go/src/identity

# Copy dependency manifests first so Docker can cache the vendor layer
# independently of source changes.
COPY go.mod go.sum ./
COPY vendor ./vendor

COPY main.go ./
COPY internal ./internal
COPY db ./db

ENV GOFLAGS="-mod=vendor"

RUN CGO_ENABLED=0 go build -gcflags="all=-N -l" \
    -ldflags="-X main.VERSION=$VERSION -X main.COMMIT=$COMMIT_ID" \
    -o /go/bin/identity main.go

# -- Build stage (release) -----------------------------------------------------
# Stripped production binary: debug symbols and DWARF removed via -s -w.
# No -gcflags so the compiler applies full optimisations.
FROM registry.k8shell.io/docker/library/golang:1.24.5 AS build-release

ARG VERSION
ARG COMMIT_ID

WORKDIR /go/src/identity

COPY go.mod go.sum ./
COPY vendor ./vendor

COPY main.go ./
COPY internal ./internal
COPY db ./db

ENV GOFLAGS="-mod=vendor"

RUN CGO_ENABLED=0 go build \
    -ldflags="-s -w -X main.VERSION=$VERSION -X main.COMMIT=$COMMIT_ID" \
    -o /go/bin/identity main.go

# -- Runtime stage (Alpine) ----------------------------------------------------
# Default runtime: minimal Alpine image with a shell and basic tools, useful
# for debugging. The db/ directory is included so the service can run database
# migrations on startup without a separate init container.
# Build with: docker build -f docker/identity/Dockerfile .
FROM registry.k8shell.io/docker/library/alpine:3.21.3 AS alpine

RUN mkdir /app
COPY --from=build-debug /go/bin/identity /app/identity
COPY --from=build-debug /go/src/identity/db /app/db
WORKDIR /app
# While-loop entrypoint: restarts the service if it exits without terminating the
# container. Args passed via Kubernetes `args:` become $@ and are forwarded on
# every restart, so the same args field works for both alpine and distroless.
ENTRYPOINT ["sh", "-c", "while true; do /app/identity \"$@\"; done", "--"]

# -- Runtime stage (distroless) ------------------------------------------------
# Hardened production runtime:
#   - No shell, no package manager, no package metadata — minimal attack surface.
#   - :nonroot variant runs as uid 65532 (nonroot) rather than root.
#   - Binary is already stripped of debug symbols via -ldflags="-s -w".
#   - Fully static binary (CGO_ENABLED=0) — no libc dependency.
# Build with: RUNTIME=distroless make image
FROM gcr.io/distroless/static-debian12:nonroot AS distroless

COPY --from=build-release --chown=nonroot:nonroot /go/bin/identity /app/identity
COPY --from=build-release --chown=nonroot:nonroot /go/src/identity/db /app/db

USER nonroot:nonroot
WORKDIR /app
ENTRYPOINT ["/app/identity"]

