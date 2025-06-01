FROM golang:1.24.3 AS build

ARG VERSION
ARG COMMIT_ID

LABEL VERSION=$VERSION
LABEL COMMIT_ID=$COMMIT_ID

WORKDIR /go/src/identity
COPY files .

RUN go mod download
RUN go install github.com/swaggo/swag/cmd/swag@latest
RUN /go/bin/swag init --generalInfo pkg/server/restapi.go --output docs

RUN CGO_ENABLED=0 go build -ldflags="-s -w -X main.IDENTITY_VERSION=$VERSION -X main.K8SHELLD_COMMIT=$COMMIT_ID" \
    -o /go/bin/identity main.go

FROM alpine:3.21.3

RUN mkdir /app
COPY --from=build /go/bin/identity /app
COPY --from=build /go/src/identity/docs /app/docs