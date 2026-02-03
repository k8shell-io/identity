FROM registry.k8shell.io/docker/library/golang:1.24.5 AS build

ARG VERSION
ARG COMMIT_ID

LABEL VERSION=$VERSION
LABEL COMMIT_ID=$COMMIT_ID

WORKDIR /go/src/identity
COPY go.mod go.sum ./
COPY vendor ./vendor
COPY main.go ./
COPY internal ./internal
COPY pkg ./pkg
COPY db ./db

ENV GOFLAGS="-mod=vendor"

RUN CGO_ENABLED=0 go build -ldflags="-s -w -X main.VERSION=$VERSION -X main.COMMIT=$COMMIT_ID" \
    -o /go/bin/identity main.go

FROM registry.k8shell.io/docker/library/alpine:3.21.3

RUN mkdir /app
COPY --from=build /go/bin/identity /app/identity
COPY --from=build /go/src/identity/db /app/db
WORKDIR /app