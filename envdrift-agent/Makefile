.PHONY: build build-all clean test install

# Version info
VERSION ?= dev
LDFLAGS := -ldflags "-X github.com/jainal09/envdrift-agent/internal/cmd.Version=$(VERSION)"

# Build for current platform
build:
	go build $(LDFLAGS) -o bin/envdrift-agent ./cmd/envdrift-agent

# Cross-compile for all platforms
build-all: clean
	GOOS=linux   GOARCH=amd64 go build $(LDFLAGS) -o dist/envdrift-agent-linux-amd64 ./cmd/envdrift-agent
	GOOS=linux   GOARCH=arm64 go build $(LDFLAGS) -o dist/envdrift-agent-linux-arm64 ./cmd/envdrift-agent
	GOOS=darwin  GOARCH=amd64 go build $(LDFLAGS) -o dist/envdrift-agent-darwin-amd64 ./cmd/envdrift-agent
	GOOS=darwin  GOARCH=arm64 go build $(LDFLAGS) -o dist/envdrift-agent-darwin-arm64 ./cmd/envdrift-agent
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o dist/envdrift-agent-windows-amd64.exe ./cmd/envdrift-agent

# Clean build artifacts
clean:
	rm -rf bin/ dist/

# Run tests
test:
	go test -v ./...

# Install locally
install: build
	cp bin/envdrift-agent /usr/local/bin/

# Run linter
lint:
	golangci-lint run

# Development: run the agent
run:
	go run ./cmd/envdrift-agent start
