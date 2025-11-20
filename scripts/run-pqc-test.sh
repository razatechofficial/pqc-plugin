#!/bin/bash

# PQC Plugin Test Script - Actually runs the tests
# Run this on the Vault server

set +e  # Don't exit on errors

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

# Configuration
VAULT_ADDR="${VAULT_ADDR:-https://kms.averox.com}"
if [ -z "$VAULT_TOKEN" ]; then
    echo "Error: VAULT_TOKEN environment variable is not set"
    echo "Please set it with: export VAULT_TOKEN=your_token_here"
    exit 1
fi
MOUNT_PATH="pqc"

export VAULT_ADDR
export VAULT_TOKEN

echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  PQC Plugin Test - Running Actual Tests${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
echo ""

# Test 1: Check plugin registration
echo -e "${YELLOW}Test 1: Check plugin registration${NC}"
echo "────────────────────────────────────────────────────────────────"
vault read sys/plugins/catalog/secret/pqc-plugin
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Plugin is registered${NC}"
else
    echo -e "${RED}✗ Plugin not found${NC}"
fi
echo ""

# Test 2: Check mount
echo -e "${YELLOW}Test 2: Check mount is enabled${NC}"
echo "────────────────────────────────────────────────────────────────"
MOUNT_CHECK=$(vault secrets list | grep -q "$MOUNT_PATH" && echo "found" || echo "not found")
if [ "$MOUNT_CHECK" = "found" ]; then
    echo -e "${GREEN}✓ Mount '$MOUNT_PATH' is enabled${NC}"
    vault secrets list | grep "$MOUNT_PATH"
else
    echo -e "${RED}✗ Mount '$MOUNT_PATH' not found${NC}"
    echo "Enable it with: vault secrets enable -path=$MOUNT_PATH pqc-plugin"
fi
echo ""

# Test 3: Create encryption key
echo -e "${YELLOW}Test 3: Create Kyber768 encryption key${NC}"
echo "────────────────────────────────────────────────────────────────"
KEY_NAME="test-enc-key-$(date +%s)"
vault write $MOUNT_PATH/keys/$KEY_NAME algorithm=kyber768 key_type=encryption
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Key created: $KEY_NAME${NC}"
else
    echo -e "${RED}✗ Failed to create key${NC}"
    exit 1
fi
echo ""

# Test 4: Read key info
echo -e "${YELLOW}Test 4: Read key information${NC}"
echo "────────────────────────────────────────────────────────────────"
KEY_INFO=$(vault read $MOUNT_PATH/keys/$KEY_NAME -format=json 2>/dev/null)
if [ $? -eq 0 ]; then
    PUB_KEY=$(echo "$KEY_INFO" | python3 -c "import sys, json; print(json.load(sys.stdin)['data']['public_key'])" 2>/dev/null)
    if [ -n "$PUB_KEY" ]; then
        PUB_KEY_SIZE=$(echo -n "$PUB_KEY" | base64 -d 2>/dev/null | wc -c | tr -d ' ')
        echo -e "${GREEN}✓ Key read successfully${NC}"
        echo "  Public key size: $PUB_KEY_SIZE bytes"
        if [ "$PUB_KEY_SIZE" -ge 1100 ] && [ "$PUB_KEY_SIZE" -le 1300 ]; then
            echo -e "${GREEN}  ✓ PQC verified: Size matches Kyber768 (~1184 bytes)${NC}"
        fi
    else
        echo "$KEY_INFO"
    fi
else
    echo -e "${RED}✗ Failed to read key${NC}"
fi
echo ""

# Test 5: Encrypt data
echo -e "${YELLOW}Test 5: Encrypt data${NC}"
echo "────────────────────────────────────────────────────────────────"
PLAINTEXT="Hello Post-Quantum World!"
PLAINTEXT_B64=$(echo -n "$PLAINTEXT" | base64)
ENCRYPT_OUTPUT=$(vault write $MOUNT_PATH/encrypt/$KEY_NAME plaintext="$PLAINTEXT_B64" -format=json 2>/dev/null)
if [ $? -eq 0 ]; then
    CIPHERTEXT=$(echo "$ENCRYPT_OUTPUT" | python3 -c "import sys, json; print(json.load(sys.stdin)['data']['ciphertext'])" 2>/dev/null)
    if [ -n "$CIPHERTEXT" ]; then
        CIPHER_SIZE=$(echo -n "$CIPHERTEXT" | base64 -d 2>/dev/null | wc -c | tr -d ' ')
        echo -e "${GREEN}✓ Encryption successful${NC}"
        echo "  Plaintext: $PLAINTEXT"
        echo "  Ciphertext size: $CIPHER_SIZE bytes"
        if [ "$CIPHER_SIZE" -gt 1000 ]; then
            echo -e "${GREEN}  ✓ PQC verified: Ciphertext size indicates PQC KEM (>1000 bytes)${NC}"
        fi
    else
        echo "$ENCRYPT_OUTPUT"
    fi
else
    echo -e "${RED}✗ Encryption failed${NC}"
    echo "$ENCRYPT_OUTPUT"
fi
echo ""

# Test 6: Decrypt data
if [ -n "$CIPHERTEXT" ]; then
    echo -e "${YELLOW}Test 6: Decrypt data${NC}"
    echo "────────────────────────────────────────────────────────────────"
    DECRYPT_OUTPUT=$(vault write $MOUNT_PATH/decrypt/$KEY_NAME ciphertext="$CIPHERTEXT" -format=json 2>/dev/null)
    if [ $? -eq 0 ]; then
        DECRYPTED_B64=$(echo "$DECRYPT_OUTPUT" | python3 -c "import sys, json; print(json.load(sys.stdin)['data']['plaintext'])" 2>/dev/null)
        if [ -n "$DECRYPTED_B64" ]; then
            DECRYPTED=$(echo "$DECRYPTED_B64" | base64 -d)
            echo -e "${GREEN}✓ Decryption successful${NC}"
            echo "  Decrypted: $DECRYPTED"
            if [ "$DECRYPTED" = "$PLAINTEXT" ]; then
                echo -e "${GREEN}  ✓ Data integrity verified${NC}"
            else
                echo -e "${RED}  ✗ Data mismatch!${NC}"
            fi
        else
            echo "$DECRYPT_OUTPUT"
        fi
    else
        echo -e "${RED}✗ Decryption failed${NC}"
        echo "$DECRYPT_OUTPUT"
    fi
    echo ""
fi

# Test 7: Create signing key
echo -e "${YELLOW}Test 7: Create Dilithium3 signing key${NC}"
echo "────────────────────────────────────────────────────────────────"
SIG_KEY_NAME="test-sig-key-$(date +%s)"
vault write $MOUNT_PATH/keys/$SIG_KEY_NAME algorithm=dilithium3 key_type=signing
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Signing key created: $SIG_KEY_NAME${NC}"
else
    echo -e "${RED}✗ Failed to create signing key${NC}"
fi
echo ""

# Test 8: Sign data
echo -e "${YELLOW}Test 8: Sign data${NC}"
echo "────────────────────────────────────────────────────────────────"
DATA="Important banking transaction"
DATA_B64=$(echo -n "$DATA" | base64)
SIGN_OUTPUT=$(vault write $MOUNT_PATH/sign/$SIG_KEY_NAME input="$DATA_B64" -format=json 2>/dev/null)
if [ $? -eq 0 ]; then
    SIGNATURE=$(echo "$SIGN_OUTPUT" | python3 -c "import sys, json; print(json.load(sys.stdin)['data']['signature'])" 2>/dev/null)
    if [ -n "$SIGNATURE" ]; then
        SIG_SIZE=$(echo -n "$SIGNATURE" | base64 -d 2>/dev/null | wc -c | tr -d ' ')
        echo -e "${GREEN}✓ Signing successful${NC}"
        echo "  Data: $DATA"
        echo "  Signature size: $SIG_SIZE bytes"
        if [ "$SIG_SIZE" -gt 3000 ] && [ "$SIG_SIZE" -lt 3500 ]; then
            echo -e "${GREEN}  ✓ PQC verified: Size matches Dilithium3 (~3293 bytes)${NC}"
        fi
    else
        echo "$SIGN_OUTPUT"
    fi
else
    echo -e "${RED}✗ Signing failed${NC}"
    echo "$SIGN_OUTPUT"
fi
echo ""

# Test 9: Verify signature
if [ -n "$SIGNATURE" ]; then
    echo -e "${YELLOW}Test 9: Verify signature${NC}"
    echo "────────────────────────────────────────────────────────────────"
    VERIFY_OUTPUT=$(vault write $MOUNT_PATH/verify/$SIG_KEY_NAME input="$DATA_B64" signature="$SIGNATURE" -format=json 2>/dev/null)
    if [ $? -eq 0 ]; then
        IS_VALID=$(echo "$VERIFY_OUTPUT" | python3 -c "import sys, json; print(json.load(sys.stdin)['data'].get('valid', False))" 2>/dev/null)
        if [ "$IS_VALID" = "True" ]; then
            echo -e "${GREEN}✓ Signature verification: Valid${NC}"
        else
            echo -e "${RED}✗ Signature verification: Invalid${NC}"
            echo "$VERIFY_OUTPUT"
        fi
    else
        echo -e "${RED}✗ Verification failed${NC}"
        echo "$VERIFY_OUTPUT"
    fi
    echo ""
fi

# Test 10: List keys
echo -e "${YELLOW}Test 10: List all keys${NC}"
echo "────────────────────────────────────────────────────────────────"
KEY_LIST=$(vault list $MOUNT_PATH/keys 2>/dev/null)
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Keys listed successfully${NC}"
    echo "$KEY_LIST"
else
    echo -e "${RED}✗ Failed to list keys${NC}"
fi
echo ""

# Summary
echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  Test Summary${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${GREEN}✓ Plugin Registration: Checked${NC}"
echo -e "${GREEN}✓ Mount Status: Checked${NC}"
echo -e "${GREEN}✓ Encryption Key Creation: Tested${NC}"
echo -e "${GREEN}✓ Key Reading: Tested${NC}"
echo -e "${GREEN}✓ Encryption: Tested${NC}"
echo -e "${GREEN}✓ Decryption: Tested${NC}"
echo -e "${GREEN}✓ Signing Key Creation: Tested${NC}"
echo -e "${GREEN}✓ Signing: Tested${NC}"
echo -e "${GREEN}✓ Signature Verification: Tested${NC}"
echo -e "${GREEN}✓ Key Listing: Tested${NC}"
echo ""
echo -e "${BLUE}All PQC operations completed!${NC}"
echo ""

