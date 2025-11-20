#!/bin/bash

# Quick PQC Test Commands for Remote Server
# Run these commands directly on the Vault server via SSH

VAULT_ADDR="${VAULT_ADDR:-https://kms.averox.com}"
if [ -z "$VAULT_TOKEN" ]; then
    echo "Error: VAULT_TOKEN environment variable is not set"
    echo "Please set it with: export VAULT_TOKEN=your_token_here"
    exit 1
fi
MOUNT_PATH="pqc"

export VAULT_ADDR
export VAULT_TOKEN

echo "════════════════════════════════════════════════════════════════"
echo "  PQC Plugin Test Commands"
echo "════════════════════════════════════════════════════════════════"
echo ""

# 1. Check plugin is registered
echo "1. Check plugin registration:"
echo "   vault read sys/plugins/catalog/secret/pqc-plugin"
echo ""

# 2. Check mount is enabled
echo "2. Check mount is enabled:"
echo "   vault secrets list | grep pqc"
echo ""

# 3. Create encryption key
echo "3. Create Kyber768 encryption key:"
echo "   vault write $MOUNT_PATH/keys/test-enc-key algorithm=kyber768 key_type=encryption"
echo ""

# 4. Read key info
echo "4. Read key information:"
echo "   vault read $MOUNT_PATH/keys/test-enc-key"
echo ""

# 5. Encrypt data
echo "5. Encrypt data:"
echo "   PLAINTEXT=\$(echo -n 'Hello PQC World!' | base64)"
echo "   vault write $MOUNT_PATH/encrypt/test-enc-key plaintext=\"\$PLAINTEXT\""
echo ""

# 6. Decrypt data
echo "6. Decrypt data (use ciphertext from step 5):"
echo "   vault write $MOUNT_PATH/decrypt/test-enc-key ciphertext=\"<CIPHERTEXT>\""
echo ""

# 7. Create signing key
echo "7. Create Dilithium3 signing key:"
echo "   vault write $MOUNT_PATH/keys/test-sig-key algorithm=dilithium3 key_type=signing"
echo ""

# 8. Sign data
echo "8. Sign data:"
echo "   DATA=\$(echo -n 'Important document' | base64)"
echo "   vault write $MOUNT_PATH/sign/test-sig-key input=\"\$DATA\""
echo ""

# 9. Verify signature
echo "9. Verify signature (use signature from step 8):"
echo "   vault write $MOUNT_PATH/verify/test-sig-key input=\"\$DATA\" signature=\"<SIGNATURE>\""
echo ""

# 10. List all keys
echo "10. List all keys:"
echo "    vault list $MOUNT_PATH/keys"
echo ""

echo "════════════════════════════════════════════════════════════════"
echo "  Quick Test Sequence (Copy & Paste All)"
echo "════════════════════════════════════════════════════════════════"
echo ""
echo "export VAULT_ADDR=$VAULT_ADDR"
echo "export VAULT_TOKEN=$VAULT_TOKEN"
echo ""
echo "# Test 1: Create encryption key"
echo "vault write $MOUNT_PATH/keys/test-key algorithm=kyber768 key_type=encryption"
echo ""
echo "# Test 2: Read key (check public key size ~1184 bytes)"
echo "vault read $MOUNT_PATH/keys/test-key -format=json | grep -o '\"public_key\":\"[^\"]*\"' | head -1"
echo ""
echo "# Test 3: Encrypt"
echo "PLAINTEXT=\$(echo -n 'Test message' | base64)"
echo "vault write $MOUNT_PATH/encrypt/test-key plaintext=\"\$PLAINTEXT\" -format=json"
echo ""
echo "# Test 4: Decrypt (replace CIPHERTEXT with output from Test 3)"
echo "vault write $MOUNT_PATH/decrypt/test-key ciphertext=\"<CIPHERTEXT>\" -format=json"
echo ""
echo "# Test 5: Create signing key"
echo "vault write $MOUNT_PATH/keys/test-sig algorithm=dilithium3 key_type=signing"
echo ""
echo "# Test 6: Sign"
echo "DATA=\$(echo -n 'Sign this' | base64)"
echo "vault write $MOUNT_PATH/sign/test-sig input=\"\$DATA\" -format=json"
echo ""
echo "# Test 7: Verify (replace SIGNATURE with output from Test 6)"
echo "vault write $MOUNT_PATH/verify/test-sig input=\"\$DATA\" signature=\"<SIGNATURE>\" -format=json"
echo ""

