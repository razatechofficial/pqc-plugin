.PHONY: build clean test install

# Build the plugin for the current platform
build:
	@echo "Building post-quantum Vault plugin..."
	@go build -o vault-plugin-pqc ./main.go

# Build for Linux
build-linux:
	@echo "Building post-quantum Vault plugin for Linux..."
	@GOOS=linux GOARCH=amd64 go build -o vault-plugin-pqc-linux ./main.go

# Build for macOS
build-darwin:
	@echo "Building post-quantum Vault plugin for macOS..."
	@GOOS=darwin GOARCH=amd64 go build -o vault-plugin-pqc-darwin ./main.go

# Build for all platforms
build-all: build-linux build-darwin
	@echo "Built plugins for all platforms"

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	@rm -f vault-plugin-pqc vault-plugin-pqc-*

# Run tests
test:
	@echo "Running tests..."
	@go test ./...

# Install dependencies
deps:
	@echo "Installing dependencies..."
	@go mod download
	@go mod tidy

# Calculate SHA256 checksum (required for Vault plugin registration)
sha256:
	@echo "Calculating SHA256 checksum..."
	@shasum -a 256 vault-plugin-pqc || echo "Please build the plugin first with 'make build'"

