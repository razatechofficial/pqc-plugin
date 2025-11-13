# Architecture and Design

## Overview

This Post-Quantum Cryptography (PQC) Vault Plugin extends HashiCorp Vault Community Edition with post-quantum cryptographic capabilities without modifying Vault's core code. It implements a custom secrets engine that provides encryption, decryption, signing, and verification using NIST-standardized post-quantum algorithms.

## How It Works

### Plugin Architecture

Vault uses a plugin system that allows external binaries to extend functionality. The plugin:

1. **Implements Vault's Plugin Interface**: Uses the `logical.Backend` interface from Vault's SDK
2. **Runs as Separate Process**: Vault spawns the plugin as a separate process and communicates via gRPC
3. **Mounts as Secrets Engine**: The plugin appears as a secrets engine at a mount path (e.g., `/v1/pqc/`)

### Key Components

```
┌─────────────────────────────────────────┐
│         HashiCorp Vault                 │
│  ┌───────────────────────────────────┐  │
│  │   Plugin Manager                  │  │
│  │   - Registers plugins             │  │
│  │   - Manages plugin lifecycle     │  │
│  └──────────────┬────────────────────┘  │
│                 │ gRPC                  │
│  ┌──────────────▼────────────────────┐  │
│  │   Post-Quantum Plugin             │  │
│  │   (vault-plugin-pqc)              │  │
│  │                                    │  │
│  │  ┌──────────────────────────────┐ │  │
│  │  │  Backend (backend.go)        │ │  │
│  │  │  - Routes requests           │ │  │
│  │  │  - Manages lifecycle         │ │  │
│  │  └──────────┬───────────────────┘ │  │
│  │             │                      │  │
│  │  ┌──────────▼───────────────────┐ │  │
│  │  │  Path Handlers (paths.go)    │ │  │
│  │  │  - /keys/*                   │ │  │
│  │  │  - /encrypt/:name            │ │  │
│  │  │  - /decrypt/:name            │ │  │
│  │  │  - /sign/:name               │ │  │
│  │  │  - /verify/:name             │ │  │
│  │  └──────────┬───────────────────┘ │  │
│  │             │                      │  │
│  │  ┌──────────▼───────────────────┐ │  │
│  │  │  PQC Operations (pqc.go)     │ │  │
│  │  │  - Key generation            │ │  │
│  │  │  - Encryption/Decryption     │ │  │
│  │  │  - Signing/Verification      │ │  │
│  │  └──────────────────────────────┘ │  │
│  └────────────────────────────────────┘  │
└──────────────────────────────────────────┘
         │
         │ Uses
         ▼
┌─────────────────────────────────────────┐
│   Cloudflare CIRCL Library              │
│   - CRYSTALS-Kyber (KEM)                │
│   - CRYSTALS-Dilithium (Signatures)     │
└─────────────────────────────────────────┘
```

## Data Flow

### Key Generation

```
Client Request → Vault → Plugin → CIRCL Library
                                    ↓
                              Generate Key Pair
                                    ↓
                              Store in Vault
                                    ↓
                              Return Public Key
```

### Encryption Flow

```
1. Client sends plaintext + key name
2. Plugin retrieves key from Vault storage
3. Plugin uses CIRCL Kyber to:
   - Encapsulate shared secret (KEM)
   - Encrypt plaintext with shared secret
4. Returns ciphertext to client
```

### Decryption Flow

```
1. Client sends ciphertext + key name
2. Plugin retrieves key from Vault storage
3. Plugin uses CIRCL Kyber to:
   - Decapsulate shared secret
   - Decrypt ciphertext
4. Returns plaintext to client
```

## Security Considerations

### Key Storage

- **Private keys** are stored in Vault's encrypted storage backend
- Keys can be seal-wrapped (if configured) for additional protection
- Keys are never exposed in API responses (only public keys)

### Algorithm Selection

The plugin supports multiple security levels:

- **Level 1-2**: Suitable for testing and low-security applications
- **Level 3**: Recommended for most production use (Kyber768, Dilithium3)
- **Level 5**: Highest security, larger key sizes (Kyber1024, Dilithium5)

### Encryption Implementation

**Current Implementation**: Uses XOR with shared secret (simplified for demonstration)

**Production Recommendation**: Use a proper AEAD cipher like AES-GCM with the shared secret:

```go
// Pseudo-code for production
sharedSecret := kem.Encapsulate(publicKey)
cipher := aes.NewGCM(deriveKey(sharedSecret))
ciphertext := cipher.Seal(nonce, nonce, plaintext, nil)
```

## Integration Points

### With Existing Transit Mount

The plugin can coexist with Vault's built-in transit mount:

```
/v1/transit/encrypt/my-key     → Traditional algorithms
/v1/pqc/encrypt/my-pq-key      → Post-quantum algorithms
```

This allows:
- Gradual migration to post-quantum cryptography
- Hybrid approaches (encrypt with both)
- Backward compatibility

### With Vault Policies

Standard Vault policies apply:

```hcl
# Allow all PQC operations
path "pqc/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

# Allow only encryption/decryption
path "pqc/encrypt/*" {
  capabilities = ["update"]
}
path "pqc/decrypt/*" {
  capabilities = ["update"]
}
```

## Storage Schema

Keys are stored in Vault's storage backend with the following structure:

```
keys/
  └── <key-name>/
      └── {
            "name": "my-key",
            "algorithm": "kyber768",
            "key_type": "encryption",
            "public_key": <base64-encoded>,
            "private_key": <base64-encoded>,
            "version": 1
          }
```

## Limitations and Future Enhancements

### Current Limitations

1. **Encryption**: Uses simplified XOR (should use AEAD in production)
2. **Key Rotation**: Manual process (no automatic rotation)
3. **Key Versioning**: Basic version tracking
4. **Context Binding**: No additional authenticated data (AAD) support

### Potential Enhancements

1. **Hybrid Cryptography**: Combine classical + post-quantum algorithms
2. **Key Rotation**: Automatic key rotation policies
3. **Key Derivation**: Support for key derivation functions
4. **Batch Operations**: Encrypt/decrypt multiple items
5. **Key Import/Export**: Import keys from external sources
6. **Performance Optimization**: Caching and connection pooling

## Testing Strategy

### Unit Tests

- Test key generation for each algorithm
- Test encryption/decryption round-trips
- Test signing/verification
- Test error handling

### Integration Tests

- Test with actual Vault instance
- Test plugin registration and mounting
- Test API endpoints
- Test with different Vault policies

### Security Tests

- Verify keys are never exposed
- Test with invalid inputs
- Test key size validation
- Test algorithm parameter validation

## Deployment Considerations

### Plugin Binary

- Must be compiled for the same OS/architecture as Vault
- Must be placed in Vault's plugin directory
- Must have execute permissions
- SHA256 checksum must match registration

### Vault Configuration

- Plugin directory must be configured
- Sufficient permissions for plugin execution
- Network access if using remote storage

### Monitoring

- Monitor plugin process health
- Log cryptographic operations (without sensitive data)
- Track key usage and rotation
- Monitor performance metrics

## References

- [Vault Plugin Development](https://developer.hashicorp.com/vault/docs/internals/plugins)
- [NIST PQC Standards](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [Cloudflare CIRCL](https://github.com/cloudflare/circl)
- [CRYSTALS-Kyber](https://pq-crystals.org/kyber/)
- [CRYSTALS-Dilithium](https://pq-crystals.org/dilithium/)

