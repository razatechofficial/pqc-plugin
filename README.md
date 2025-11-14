# Post-Quantum Cryptography Vault Plugin

A HashiCorp Vault plugin that provides post-quantum cryptographic capabilities for the Community Edition, including encryption, decryption, signing, and verification using NIST-standardized post-quantum algorithms.

## Features

- **Post-Quantum Encryption**: Support for CRYSTALS-Kyber (Kyber512, Kyber768, Kyber1024)
- **Post-Quantum Signing**: Support for CRYSTALS-Dilithium (Dilithium2, Dilithium3, Dilithium5)
- **Key Management**: Create, read, update, and delete post-quantum keys
- **Transit-like Operations**: Encrypt, decrypt, sign, and verify operations similar to Vault's Transit Secrets Engine
- **Docker Support**: Full Dockerization for easy deployment to VPS

## Supported Algorithms

### Encryption (Key Encapsulation Mechanism)

- `kyber512` - NIST Level 1 security
- `kyber768` - NIST Level 3 security (recommended)
- `kyber1024` - NIST Level 5 security

### Signing (Digital Signatures)

- `dilithium2` - NIST Level 2 security
- `dilithium3` - NIST Level 3 security (recommended)
- `dilithium5` - NIST Level 5 security

## Quick Start

### Option 1: Docker Deployment (Recommended for VPS)

```bash
# Build the plugin with Docker
make docker-build

# Deploy to your VPS
export REMOTE_HOST=your-vps-ip
export REMOTE_USER=vault
make docker-deploy
```

See [DOCKER.md](DOCKER.md) for detailed Docker deployment instructions.

### Option 2: Local Build

```bash
# Install dependencies
make deps

# Build the plugin
make build

# Register and enable (see Installation section)
```

## Prerequisites

- Go 1.21 or later (for local development)
- Docker (for Docker builds)
- HashiCorp Vault (Community or Enterprise Edition)
- Access to your Vault instance with appropriate permissions

## Building the Plugin

### Local Build

1. **Install dependencies:**

```bash
make deps
```

2. **Build for your platform:**

```bash
# For current platform
make build

# For specific platforms
make build-linux    # Linux
make build-darwin   # macOS

# For all platforms
make build-all
```

### Docker Build

```bash
# Build plugin binary using Docker
make docker-build

# The binary will be in ./build-output/vault-plugin-pqc
```

## Installation and Registration

### 1. Place the Plugin Binary

Copy the plugin binary to Vault's plugin directory. The default location is typically:

- Linux: `/etc/vault.d/plugins/` or `$VAULT_PLUGIN_DIR`
- macOS: `$VAULT_PLUGIN_DIR`

You can also specify a custom plugin directory in your Vault configuration:

```hcl
plugin_directory = "/path/to/vault/plugins"
```

### 2. Calculate SHA256 Checksum

```bash
# On Linux/macOS
shasum -a 256 vault-plugin-pqc

# Or use the Makefile
make sha256
```

### 3. Register the Plugin

Set your Vault environment variables. You can either:

**Option A: Use a .env file (recommended)**

```bash
# Copy the example file and update with your credentials
cp .env.example .env
# Edit .env with your actual Vault token
```

**Option B: Export environment variables directly**

```bash
export VAULT_ADDR=https://kms.averox.com
export VAULT_TOKEN=your-vault-token-here
```

Register the plugin with Vault:

```bash
# Replace <SHA256_CHECKSUM> with the actual checksum from step 2
vault write sys/plugins/catalog/secret/pqc-plugin \
  sha256="<SHA256_CHECKSUM>" \
  command="vault-plugin-pqc"
```

### 4. Enable the Plugin

Enable the plugin at a mount path:

```bash
# Enable at the default path
vault secrets enable -path=pqc pqc-plugin

# Or enable at a custom path (e.g., to complement your transit mount)
vault secrets enable -path=pqc-transit pqc-plugin
```

## Usage Examples

### Create an Encryption Key

```bash
# Create a Kyber768 encryption key
vault write pqc/keys/my-encryption-key \
  algorithm=kyber768 \
  key_type=encryption
```

### Create a Signing Key

```bash
# Create a Dilithium3 signing key
vault write pqc/keys/my-signing-key \
  algorithm=dilithium3 \
  key_type=signing
```

### List Keys

```bash
vault list pqc/keys
```

### Read Key Information

```bash
vault read pqc/keys/my-encryption-key
```

### Encrypt Data

```bash
# First, base64 encode your plaintext
PLAINTEXT=$(echo -n "Hello, Post-Quantum World!" | base64)

# Encrypt using the key
vault write pqc/encrypt/my-encryption-key \
  plaintext="$PLAINTEXT"
```

### Decrypt Data

```bash
# Use the ciphertext from the encryption operation
vault write pqc/decrypt/my-encryption-key \
  ciphertext="<CIPHERTEXT_FROM_ENCRYPT_OPERATION>"
```

### Sign Data

```bash
# Base64 encode the data to sign
DATA=$(echo -n "Important document content" | base64)

# Sign the data
vault write pqc/sign/my-signing-key \
  input="$DATA"
```

### Verify Signature

```bash
# Verify the signature
vault write pqc/verify/my-signing-key \
  input="$DATA" \
  signature="<SIGNATURE_FROM_SIGN_OPERATION>"
```

## Testing

### Unit and Integration Tests

```bash
# Run all tests
make test

# Run with coverage
make test-coverage
```

### End-to-End Tests

```bash
# Run automated E2E tests with actual Vault
make test-e2e

# Run manual interactive tests
make test-manual
```

### PQC Verification (Banking Compliance)

Verify that Post-Quantum Cryptography is actually being used by checking key, ciphertext, and signature sizes:

```bash
# Verify PQC is being used (checks sizes match PQC specifications)
make verify-pqc
```

This verification script proves you're using PQC by checking:
- **Key Size**: Kyber768 keys should be ~1184 bytes (vs RSA-2048: ~256 bytes)
- **Ciphertext Size**: Kyber768 ciphertexts should be > 1000 bytes (vs AES: ~32 bytes)
- **Signature Size**: Dilithium3 signatures should be ~3293 bytes (vs ECDSA: ~64 bytes)

If all three tests show ✓✓✓ VERIFIED, you are definitely using Post-Quantum Cryptography!

### Banking Sector Compliance Tests

Run comprehensive banking sector compliance tests:

```bash
# Run banking sector compliance test suite
make test-banking
```

## Docker Deployment

For deploying to a VPS where Vault is running, see the comprehensive [DOCKER.md](DOCKER.md) guide.

Quick commands:

```bash
# Build plugin with Docker
make docker-build

# Deploy to VPS
export REMOTE_HOST=your-vps-ip
make docker-deploy

# Or use Docker Compose for local testing
make docker-up
```

## API Endpoints

### Key Management

- `GET /v1/pqc/keys` - List all keys
- `GET /v1/pqc/keys/:name` - Read key information
- `POST /v1/pqc/keys/:name` - Create a new key
- `PUT /v1/pqc/keys/:name` - Update a key
- `DELETE /v1/pqc/keys/:name` - Delete a key

### Encryption Operations

- `POST /v1/pqc/encrypt/:name` - Encrypt data

### Decryption Operations

- `POST /v1/pqc/decrypt/:name` - Decrypt data

### Signing Operations

- `POST /v1/pqc/sign/:name` - Sign data

### Verification Operations

- `POST /v1/pqc/verify/:name` - Verify signature

## Integration with Existing Transit Mount

If you have an existing transit mount at `transit`, you can use this plugin alongside it:

```bash
# Your existing transit mount
vault write transit/encrypt/my-key plaintext="..."

# Post-quantum operations
vault write pqc/encrypt/my-pq-key plaintext="..."
```

This allows you to:

- Use traditional algorithms via the transit mount
- Use post-quantum algorithms via the pqc mount
- Gradually migrate to post-quantum cryptography

## Security Considerations

1. **Key Storage**: Private keys are stored encrypted in Vault's storage backend using seal wrapping (if configured).
2. **Algorithm Selection**:
   - For encryption, Kyber768 is recommended for most use cases (NIST Level 3)
   - For signing, Dilithium3 is recommended for most use cases (NIST Level 3)
3. **Hybrid Cryptography**: Consider using hybrid approaches (combining classical and post-quantum algorithms) during the transition period.
4. **Key Rotation**: Implement regular key rotation policies for your post-quantum keys.

## Troubleshooting

### Plugin Not Found

If Vault cannot find the plugin:

1. Verify the plugin binary is in the correct directory
2. Check that the `command` in the catalog matches the binary name
3. Ensure the plugin has execute permissions: `chmod +x vault-plugin-pqc`

### Permission Denied

Ensure your Vault token has the necessary permissions:

- `sys/plugins/catalog` - to register plugins
- `sys/mounts` - to enable secrets engines
- `pqc/*` - to use the plugin operations

### Build Errors

If you encounter build errors:

1. Ensure Go 1.21+ is installed: `go version`
2. Update dependencies: `go mod tidy`
3. Check that all required packages are available

### Docker Issues

See [DOCKER.md](DOCKER.md) for Docker-specific troubleshooting.

## Development

### Project Structure

```
pqc-plugin/
├── main.go              # Plugin entry point
├── backend/
│   ├── backend.go       # Backend implementation
│   ├── paths.go         # API path handlers
│   ├── pqc.go           # Post-quantum crypto operations
│   └── *_test.go        # Test files
├── scripts/             # Utility scripts
├── docker-compose.yml   # Docker Compose configuration
├── Dockerfile           # Docker build file
├── go.mod               # Go module definition
├── Makefile             # Build automation
└── README.md            # This file
```

### Testing

```bash
# Run tests
make test

# Run with verbose output
go test -v ./...

# Run E2E tests
make test-e2e
```

## License

This plugin is provided as-is for extending HashiCorp Vault Community Edition with post-quantum cryptographic capabilities.

## References

- [HashiCorp Vault Plugin Development](https://developer.hashicorp.com/vault/docs/internals/plugins)
- [NIST Post-Quantum Cryptography Standards](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [Cloudflare CIRCL Library](https://github.com/cloudflare/circl)
- [CRYSTALS-Kyber](https://pq-crystals.org/kyber/)
- [CRYSTALS-Dilithium](https://pq-crystals.org/dilithium/)
