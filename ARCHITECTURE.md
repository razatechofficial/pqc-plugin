# PQC Plugin Architecture & Execution Flow

## Overview

This document explains where the Post-Quantum Cryptography code runs and how everything connects together.

## Code Location

### 1. **Source Code (Your Local Machine)**
The PQC implementation code is in these files:

```
pqc-plugin/
├── main.go                    # Plugin entry point - starts the plugin server
├── backend/
│   ├── backend.go            # Vault backend interface implementation
│   ├── paths.go              # API route handlers (keys/, encrypt/, decrypt/, sign/, verify/)
│   └── pqc.go                # ⭐ ACTUAL PQC CRYPTO CODE HERE ⭐
│                              #   - generateEncryptionKey() - Kyber key generation
│                              #   - encryptData() - Kyber encryption
│                              #   - decryptData() - Kyber decryption
│                              #   - generateSigningKey() - Dilithium key generation
│                              #   - signData() - Dilithium signing
│                              #   - verifySignature() - Dilithium verification
```

**Key File: `backend/pqc.go`** - This is where the actual post-quantum cryptographic operations happen using the Cloudflare CIRCL library.

### 2. **Compiled Binary (Remote Vault Server)**
When you build the plugin, it creates a binary:

```
vault-plugin-pqc  (Linux binary)
```

This binary is deployed to your remote Vault server at:
```
/etc/vault.d/plugins/vault-plugin-pqc
```

## Execution Flow

Here's the complete flow when you run the banking test:

```
┌─────────────────────────────────────────────────────────────────┐
│ 1. YOUR LOCAL MACHINE                                           │
│    ┌──────────────────────────────────────────────────────┐    │
│    │  scripts/banking-test.sh                             │    │
│    │  (Runs on your Mac)                                  │    │
│    │                                                       │    │
│    │  vault_cmd() → SSH to remote server                  │    │
│    └──────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
                            │
                            │ SSH Connection
                            │ (104.237.11.39)
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│ 2. REMOTE VAULT SERVER (104.237.11.39)                         │
│    ┌──────────────────────────────────────────────────────┐    │
│    │  Vault CLI Command                                   │    │
│    │  vault write pqc/keys/my-key ...                     │    │
│    └──────────────────────────────────────────────────────┘    │
│                            │                                    │
│                            │ HTTP/API Request                   │
│                            ▼                                    │
│    ┌──────────────────────────────────────────────────────┐    │
│    │  HashiCorp Vault Server                              │    │
│    │  (Running on port 8200)                              │    │
│    │                                                       │    │
│    │  1. Receives API request                             │    │
│    │  2. Routes to "pqc" mount                            │    │
│    │  3. Loads plugin: vault-plugin-pqc                   │    │
│    └──────────────────────────────────────────────────────┘    │
│                            │                                    │
│                            │ Plugin IPC (gRPC)                  │
│                            ▼                                    │
│    ┌──────────────────────────────────────────────────────┐    │
│    │  vault-plugin-pqc Binary                             │    │
│    │  (Located at /etc/vault.d/plugins/vault-plugin-pqc)  │    │
│    │                                                       │    │
│    │  This binary contains:                               │    │
│    │  • main.go code                                      │    │
│    │  • backend/backend.go                                │    │
│    │  • backend/paths.go                                  │    │
│    │  • backend/pqc.go ⭐ (PQC crypto code)               │    │
│    │  • Cloudflare CIRCL library (compiled in)            │    │
│    └──────────────────────────────────────────────────────┘    │
│                            │                                    │
│                            │ Function Call                      │
│                            ▼                                    │
│    ┌──────────────────────────────────────────────────────┐    │
│    │  backend/pqc.go Functions                            │    │
│    │                                                       │    │
│    │  generateEncryptionKey()                             │    │
│    │    → kyber768.Scheme().GenerateKeyPair()             │    │
│    │                                                       │    │
│    │  encryptData()                                       │    │
│    │    → scheme.Encapsulate()                            │    │
│    │                                                       │    │
│    │  signData()                                          │    │
│    │    → dilithium.Mode().Sign()                         │    │
│    └──────────────────────────────────────────────────────┘    │
│                            │                                    │
│                            │ Library Call                       │
│                            ▼                                    │
│    ┌──────────────────────────────────────────────────────┐    │
│    │  Cloudflare CIRCL Library                            │    │
│    │  (Compiled into the binary)                          │    │
│    │                                                       │    │
│    │  • kyber512, kyber768, kyber1024                     │    │
│    │  • dilithium2, dilithium3, dilithium5                │    │
│    │                                                       │    │
│    │  ⭐ ACTUAL POST-QUANTUM ALGORITHMS ⭐                │    │
│    └──────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
```

## Step-by-Step Example

When you run:
```bash
make test-banking
```

Here's what happens:

### Step 1: Test Script Runs Locally
```bash
# scripts/banking-test.sh runs on your Mac
vault_cmd "vault write pqc/keys/customer-key algorithm=kyber768 key_type=encryption"
```

### Step 2: SSH to Remote Server
```bash
# The script SSHs to 104.237.11.39 and runs:
# Note: VAULT_TOKEN must be set as an environment variable before running the script
export VAULT_ADDR=https://kms.averox.com
export VAULT_TOKEN=${VAULT_TOKEN}  # Token is read from environment
vault write pqc/keys/customer-key algorithm=kyber768 key_type=encryption
```

### Step 3: Vault Receives Request
- Vault server receives the HTTP request
- Routes it to the `pqc` mount path
- Identifies that `pqc` is handled by the `pqc-plugin` plugin

### Step 4: Vault Loads Plugin
- Vault looks up the plugin in its catalog
- Finds: `command="vault-plugin-pqc"` in `/etc/vault.d/plugins/`
- Spawns the plugin binary as a subprocess
- Establishes gRPC communication channel

### Step 5: Plugin Processes Request
The `vault-plugin-pqc` binary:
1. Receives the request via gRPC
2. Routes to `backend/paths.go` → `pathKeyCreate()`
3. Calls `backend/pqc.go` → `generateEncryptionKey("kyber768")`
4. Executes:
   ```go
   scheme := kyber768.Scheme()
   publicKey, privateKey, err := scheme.GenerateKeyPair()
   ```
5. Returns the key pair to Vault
6. Vault stores the keys in its storage backend

### Step 6: Response Returns
- Plugin → Vault → Vault CLI → SSH → Your test script
- Test script receives: "Success! Data written to: pqc/keys/customer-key"

## Where is the Code Actually Running?

**Answer: The PQC code runs on the remote Vault server (104.237.11.39) inside the `vault-plugin-pqc` binary process.**

The binary is a compiled Go program that includes:
- All your source code (`main.go`, `backend/*.go`)
- The Cloudflare CIRCL library (compiled in)
- All dependencies (Vault SDK, etc.)

## Verification

You can verify the plugin is running on the remote server:

```bash
# SSH to the server
ssh root@104.237.11.39

# Check if plugin binary exists
ls -lh /etc/vault.d/plugins/vault-plugin-pqc

# Check if Vault has loaded the plugin
vault read sys/plugins/catalog/secret/pqc-plugin

# Check running processes (plugin runs as subprocess of Vault)
ps aux | grep vault-plugin-pqc
```

## Key Points

1. **Source Code**: Lives in `backend/pqc.go` on your local machine
2. **Compiled Binary**: `vault-plugin-pqc` deployed to remote server
3. **Execution**: Binary runs on remote server as Vault subprocess
4. **Test Script**: Only sends commands via SSH, doesn't execute crypto locally
5. **PQC Algorithms**: Actually run on remote server using Cloudflare CIRCL library

## Why This Architecture?

- **Security**: Private keys never leave the Vault server
- **Performance**: Crypto operations happen close to Vault storage
- **Isolation**: Plugin runs in separate process from Vault core
- **Scalability**: Vault can manage multiple plugin instances

## Summary

```
Your Test Script (Local)
    ↓ SSH
Remote Vault CLI
    ↓ HTTP API
Vault Server (Remote)
    ↓ gRPC/Plugin Protocol
vault-plugin-pqc Binary (Remote)
    ↓ Function Calls
backend/pqc.go Code (in binary)
    ↓ Library Calls
Cloudflare CIRCL PQC Library (in binary)
    ↓
⭐ POST-QUANTUM CRYPTOGRAPHY HAPPENS HERE ⭐
```

The actual PQC cryptographic operations happen **on the remote Vault server** inside the `vault-plugin-pqc` binary process, which contains your compiled Go code and the Cloudflare CIRCL post-quantum cryptography library.
