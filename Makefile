# Variables
GOOS_LIST := linux 
GOARCH_LIST := amd64 arm64
REPO=registry.k8shell.io

# Default target
all: build

# Initialize Go module
init:
	@echo "Initializing Go module..."
	go mod tidy

image:
	@echo "Idp usermap docker image"
	@rm -fr docker/identity/files
	@mkdir -p docker/identity/files
	@echo "Downloading vendor modules..."
	@go mod vendor -o docker/identity/files/vendor
	@echo "Building image..."
	@version=$$(git describe --tags --match 'v*' | sed 's/-g.*//') && \
	cp -r go.mod go.sum pkg internal db main.go docker/identity/files && \
	cd docker/identity && docker build --build-arg VERSION=$$version \
		--build-arg COMMIT_ID=$$(git rev-parse --short HEAD) -t $(REPO)/$$(cat ./BUILD):$$version .

COMMON_DIR := $(shell go list -m -f '{{.Dir}}' github.com/k8shell-io/common)

proto-setup:
	mkdir -p .proto_deps
	@rm -f .proto_deps/common
	ln -s $(COMMON_DIR) .proto_deps/common

protoc:
	@echo "Generating Go code from proto files..."
	rm -rf pkg/api/typespb
	protoc -I . -I .proto_deps \
	  --go_out=. --go_opt=module=github.com/k8shell-io/identity \
	  --go-grpc_out=. --go-grpc_opt=module=github.com/k8shell-io/identity \
	  pkg/api/types.proto
	rm -rf pkg/api/identitypb
	protoc -I . -I .proto_deps \
	  --go_out=. --go_opt=module=github.com/k8shell-io/identity \
	  --go-grpc_out=. --go-grpc_opt=module=github.com/k8shell-io/identity \
	  pkg/api/identity.proto
	rm -rf pkg/api/idppb
	protoc -I . -I .proto_deps \
	  --go_out=. --go_opt=module=github.com/k8shell-io/identity \
	  --go-grpc_out=. --go-grpc_opt=module=github.com/k8shell-io/identity \
	  pkg/api/idp.proto