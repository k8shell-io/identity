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

vendor:  ##@ Vendor Go modules
         ##@ Downloads and vendors all Go module dependencies into the vendor/ directory
		 ##@ Used in CI/CD workflow before preparing Docker context
	@echo "Vendoring Go modules..."
	@go mod vendor
	@echo "Vendoring complete!"

prepare-docker: ##@ Prepare Docker build context
                ##@ Copies vendored dependencies and source files to docker/identity/files/
                ##@ Used in CI/CD workflow before building container image
	@echo "Preparing Docker build context..."
	@rm -rf docker/identity/files
	@mkdir -p docker/identity/files
	@cp -r vendor docker/identity/files/
	@cp -r go.mod go.sum internal pkg db docker/identity/files/
	@echo "Docker context prepared!"

image:  ##@ Build Docker image
        ##@ Builds identity container image with version tagging
        ##@ Accepts VERSION, COMMIT_ID, IMAGE_TAG from environment or auto-detects from git
        ##@ Can be used locally or in CI/CD workflow
image: vendor prepare-docker
	@echo "Building identity docker image..."
	@if ! command -v git >/dev/null 2>&1; then echo "Git not found. Please install Git."; exit 1; fi
	@VERSION=$${VERSION:-$$(git describe --tags --match 'v*' | sed 's/-g.*//')} && \
	COMMIT_ID=$${COMMIT_ID:-$$(git rev-parse --short HEAD)} && \
	IMAGE_TAG=$${IMAGE_TAG:-$$VERSION} && \
	echo -n "k8shell-test/identity:$$IMAGE_TAG" > docker/identity/BUILD && \
	cd docker/identity && docker build --build-arg VERSION=$$VERSION \
		--build-arg COMMIT_ID=$$COMMIT_ID -t $(REPO)/$$(cat ./BUILD) .

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