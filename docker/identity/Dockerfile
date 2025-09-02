FROM golang:1.24.5 AS build

ARG VERSION
ARG COMMIT_ID

LABEL VERSION=$VERSION
LABEL COMMIT_ID=$COMMIT_ID

WORKDIR /go/src/identity
COPY files .

# need to use 1.16.4 due to regression bug in 1.16.5
# https://github.com/swaggo/swag/issues/2042
RUN go install github.com/swaggo/swag/cmd/swag@v1.16.4
#RUN /go/bin/swag init --generalInfo internal/server/restapi.go --output docs
RUN /go/bin/swag init --parseDependency --parseInternal
ENV GOFLAGS="-mod=vendor"

RUN CGO_ENABLED=0 go build -ldflags="-s -w -X main.VERSION=$VERSION -X main.COMMIT=$COMMIT_ID" \
    -o /go/bin/identity main.go

FROM gcr.io/distroless/static-debian12

WORKDIR /app
COPY --from=build /go/bin/identity /app/identity
COPY --from=build /go/src/identity/docs /app/docs
COPY --from=build /go/src/identity/db /app/db

USER nonroot:nonroot
ENTRYPOINT ["/app/identity"]