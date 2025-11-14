# Multi-stage build for Post-Quantum Cryptography Vault Plugin

# Stage 1: Build the plugin
FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git make

# Set working directory
WORKDIR /build

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the plugin
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -installsuffix cgo -o vault-plugin-pqc ./main.go

# Stage 2: Create minimal runtime image
FROM alpine:latest

# Install ca-certificates for HTTPS
RUN apk --no-cache add ca-certificates

# Create plugin directory
RUN mkdir -p /vault/plugins

# Copy plugin binary from builder
COPY --from=builder /build/vault-plugin-pqc /vault/plugins/vault-plugin-pqc

# Make plugin executable
RUN chmod +x /vault/plugins/vault-plugin-pqc

# Set working directory
WORKDIR /vault

# Default command (can be overridden)
CMD ["/vault/plugins/vault-plugin-pqc"]




