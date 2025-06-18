# Variables
GOOS_LIST := linux 
GOARCH_LIST := amd64 arm64
REPO=fitcr.ksi.in.fit.cvut.cz

# Default target
all: build

# Initialize Go module
init:
	@echo "Initializing Go module..."
	go mod tidy

image:
	@echo "Identity docker image"
	@rm -fr docker/files
	@mkdir -p docker/files
	@echo "Downloading vendor modules..."
	@go mod vendor -o docker/files/vendor
	@echo "Building image..."
	@version=$$(git describe --tags --match '*' | cut -d'-' -f1-2) && \
	echo -n "k8shell-base/identity:$$version" > docker/BUILD && \
	cp -r go.mod go.sum pkg internal db main.go docker/files && \
	cd docker && docker build --build-arg VERSION=$$version \
		--build-arg COMMIT_ID=$$(git rev-parse --short HEAD) -t $(REPO)/$$(cat ./BUILD) .

push:
	$(MAKE) image
	@echo "Pushing identity docker image to repository..."
	cd docker && docker push $(REPO)/$$(cat ./BUILD)

