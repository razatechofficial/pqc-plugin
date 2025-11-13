# Quick Start Guide

This guide will help you quickly set up and use the Post-Quantum Cryptography Vault Plugin.

## Prerequisites

- Go 1.21+ installed
- HashiCorp Vault CLI installed
- Access to your Vault instance at `https://kms.averox.com`

## Step 1: Build the Plugin

```bash
# Install dependencies
make deps

# Build the plugin
make build
```

This creates the `vault-plugin-pqc` binary in the current directory.

## Step 2: Copy Plugin to Vault Server

Copy the plugin binary to your Vault server's plugin directory. The location depends on your Vault configuration, but common locations are:

- `/etc/vault.d/plugins/` (Linux)
- `/usr/local/lib/vault/plugins/` (macOS)
- Or the directory specified in your Vault config's `plugin_directory` setting

```bash
# Example for Linux
sudo cp vault-plugin-pqc /etc/vault.d/plugins/
sudo chmod +x /etc/vault.d/plugins/vault-plugin-pqc
```

## Step 3: Register the Plugin

### Option A: Using the Registration Script

```bash
# Set your Vault credentials using .env file (recommended)
cp .env.example .env
# Edit .env with your actual Vault token

# Or export environment variables directly
export VAULT_ADDR=https://kms.averox.com
export VAULT_TOKEN=your-vault-token-here

# Run the registration script
./scripts/register-plugin.sh /path/to/vault-plugin-pqc
```

### Option B: Manual Registration

```bash
# Set your Vault credentials using .env file (recommended)
cp .env.example .env
# Edit .env with your actual Vault token

# Or export environment variables directly
export VAULT_ADDR=https://kms.averox.com
export VAULT_TOKEN=your-vault-token-here

# Calculate SHA256 checksum
SHA256=$(shasum -a 256 vault-plugin-pqc | awk '{print $1}')

# Register the plugin
vault write sys/plugins/catalog/secret/pqc-plugin \
  sha256="$SHA256" \
  command="vault-plugin-pqc"

# Enable the plugin
vault secrets enable -path=pqc pqc-plugin
```

## Step 4: Verify Installation

```bash
# List secrets engines
vault secrets list

# You should see 'pqc/' in the list
```

## Step 5: Create Your First Key

### Create an Encryption Key

```bash
vault write pqc/keys/my-encryption-key \
  algorithm=kyber768 \
  key_type=encryption
```

### Create a Signing Key

```bash
vault write pqc/keys/my-signing-key \
  algorithm=dilithium3 \
  key_type=signing
```

## Step 6: Use the Keys

### Encrypt Data

```bash
# Prepare your data (base64 encoded)
PLAINTEXT=$(echo -n "Hello, Post-Quantum World!" | base64)

# Encrypt
vault write pqc/encrypt/my-encryption-key plaintext="$PLAINTEXT"
```

### Decrypt Data

```bash
# Use the ciphertext from the encryption response
vault write pqc/decrypt/my-encryption-key \
  ciphertext="<CIPHERTEXT_FROM_ABOVE>"
```

### Sign Data

```bash
# Prepare your data
DATA=$(echo -n "Important document" | base64)

# Sign
vault write pqc/sign/my-signing-key input="$DATA"
```

### Verify Signature

```bash
# Verify the signature
vault write pqc/verify/my-signing-key \
  input="$DATA" \
  signature="<SIGNATURE_FROM_ABOVE>"
```

## Available Algorithms

### Encryption (KEM)
- `kyber512` - NIST Level 1
- `kyber768` - NIST Level 3 (recommended)
- `kyber1024` - NIST Level 5

### Signing
- `dilithium2` - NIST Level 2
- `dilithium3` - NIST Level 3 (recommended)
- `dilithium5` - NIST Level 5

## Troubleshooting

### Plugin Not Found

If Vault can't find the plugin:
1. Check that the binary is in the correct plugin directory
2. Verify the `command` name matches the binary name
3. Ensure the binary has execute permissions: `chmod +x vault-plugin-pqc`

### Permission Errors

Ensure your Vault token has:
- `sys/plugins/catalog` - to register plugins
- `sys/mounts` - to enable secrets engines
- `pqc/*` - to use the plugin

### Build Errors

If you encounter build errors:
```bash
# Clean and rebuild
make clean
make deps
make build
```

## Next Steps

- Review the full [README.md](README.md) for detailed documentation
- Explore the API endpoints
- Set up key rotation policies
- Consider hybrid cryptography approaches

## Integration with Existing Transit Mount

If you have an existing `transit` mount, you can use both:

```bash
# Traditional encryption
vault write transit/encrypt/my-key plaintext="..."

# Post-quantum encryption
vault write pqc/encrypt/my-pq-key plaintext="..."
```

This allows gradual migration to post-quantum cryptography.

