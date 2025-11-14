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

# Run unit and integration tests
test:
	@echo "Running unit and integration tests..."
	@go test ./backend -v

# Run tests with coverage
test-coverage:
	@echo "Running tests with coverage..."
	@go test ./backend -cover -coverprofile=coverage.out
	@go tool cover -func=coverage.out | tail -1

# Run end-to-end tests with actual Vault instance
test-e2e:
	@echo "Running end-to-end tests..."
	@./scripts/test-plugin.sh

# Run manual interactive tests
test-manual:
	@echo "Running manual interactive tests..."
	@./scripts/test-plugin-manual.sh

# Install dependencies
deps:
	@echo "Installing dependencies..."
	@go mod download
	@go mod tidy

# Calculate SHA256 checksum (required for Vault plugin registration)
sha256:
	@echo "Calculating SHA256 checksum..."
	@shasum -a 256 vault-plugin-pqc || echo "Please build the plugin first with 'make build'"

# Docker commands
docker-build:
	@echo "Building plugin with Docker..."
	@./scripts/docker-build.sh

docker-deploy:
	@echo "Deploying plugin to VPS..."
	@./scripts/docker-deploy.sh

docker-up:
	@echo "Starting Vault with Docker Compose..."
	@docker-compose up -d

docker-down:
	@echo "Stopping Docker Compose services..."
	@docker-compose down

docker-logs:
	@echo "Viewing Vault logs..."
	@docker-compose logs -f vault

# Remote Vault connection
connect-remote:
	@echo "Connecting to remote Vault..."
	@./scripts/connect-remote-vault.sh

connect-remote-ssh:
	@echo "Connecting to remote Vault via SSH..."
	@./scripts/remote-vault-ssh.sh

test-remote:
	@echo "Testing with remote Vault..."
	@./scripts/test-remote-vault.sh

# Execute single command on remote Vault
remote-cmd:
	@echo "Executing command on remote Vault..."
	@./scripts/remote-vault-command.sh "$(CMD)"

# Quick connect to server
connect-server:
	@echo "Connecting to server..."
	@./scripts/connect-to-server.sh

# PQC Verification (for banking compliance)
verify-pqc:
	@echo "Verifying Post-Quantum Cryptography (size verification)..."
	@./scripts/verify-pqc-sizes.sh

# Banking sector compliance test
test-banking:
	@echo "Running banking sector compliance test..."
	@./scripts/banking-test.sh

