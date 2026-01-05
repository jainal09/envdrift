# Contributing to EnvDrift Agent

Thank you for your interest in contributing to EnvDrift Agent!

## Development Setup

### Prerequisites

- Go 1.22+
- Make
- (Optional) golangci-lint for linting

### Getting Started

```bash
# Clone the repository
git clone https://github.com/jainal09/envdrift.git
cd envdrift/envdrift-agent

# Install dependencies
go mod download

# Build
make build

# Run tests
make test
```

## Making Changes

### Running Tests

```bash
# All tests
make test

# With verbose output
go test -v ./...

# With race detection
go test -race ./...

# Specific package
go test -v ./internal/config/...
```

### Linting

```bash
# Install golangci-lint
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

# Run linter
make lint
```

### Building

```bash
# Build for current platform
make build

# Cross-compile all platforms
make build-all
```

## Code Style

- Follow standard Go conventions
- Run `gofmt` before committing
- Add tests for new functionality
- Keep functions focused and small

## Pull Request Process

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests (`make test`)
5. Run linter (`make lint`)
6. Commit your changes (`git commit -m 'Add amazing feature'`)
7. Push to your fork (`git push origin feature/amazing-feature`)
8. Open a Pull Request

## Testing on Different Platforms

The CI automatically tests on:

- Ubuntu (Linux)
- macOS
- Windows

If you're adding platform-specific code, please test locally on that platform if possible.

## Need Help?

Open an issue or start a discussion!
