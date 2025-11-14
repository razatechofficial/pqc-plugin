#!/bin/bash

# Manual test script - Interactive testing of the plugin
# Use this for step-by-step manual verification

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

VAULT_ADDR="${VAULT_ADDR:-https://kms.averox.com}"
VAULT_TOKEN="${VAULT_TOKEN:-hvs.Si4gMDMP1a6MwYqpIGiGJCic}"
MOUNT_PATH="pqc"

export VAULT_ADDR
export VAULT_TOKEN

echo -e "${BLUE}Post-Quantum Cryptography Vault Plugin - Manual Test${NC}\n"

# Test 1: Create Encryption Key
echo -e "${YELLOW}Step 1: Create an encryption key${NC}"
echo "Command: vault write $MOUNT_PATH/keys/my-test-key algorithm=kyber768 key_type=encryption"
read -p "Press Enter to execute..."
vault write $MOUNT_PATH/keys/my-test-key algorithm=kyber768 key_type=encryption
echo ""

# Test 2: Read Key
echo -e "${YELLOW}Step 2: Read the key information${NC}"
echo "Command: vault read $MOUNT_PATH/keys/my-test-key"
read -p "Press Enter to execute..."
vault read $MOUNT_PATH/keys/my-test-key
echo ""

# Test 3: Encrypt
echo -e "${YELLOW}Step 3: Encrypt some data${NC}"
PLAINTEXT=$(echo -n "Hello, Post-Quantum World!" | base64)
echo "Plaintext (base64): $PLAINTEXT"
echo "Command: vault write $MOUNT_PATH/encrypt/my-test-key plaintext=\"$PLAINTEXT\""
read -p "Press Enter to execute..."
CIPHERTEXT_OUTPUT=$(vault write $MOUNT_PATH/encrypt/my-test-key plaintext="$PLAINTEXT" -format=json)
CIPHERTEXT=$(echo "$CIPHERTEXT_OUTPUT" | jq -r '.data.ciphertext')
echo "Ciphertext: $CIPHERTEXT"
echo ""

# Test 4: Decrypt
echo -e "${YELLOW}Step 4: Decrypt the data${NC}"
echo "Command: vault write $MOUNT_PATH/decrypt/my-test-key ciphertext=\"$CIPHERTEXT\""
read -p "Press Enter to execute..."
vault write $MOUNT_PATH/decrypt/my-test-key ciphertext="$CIPHERTEXT"
echo ""

# Test 5: Create Signing Key
echo -e "${YELLOW}Step 5: Create a signing key${NC}"
echo "Command: vault write $MOUNT_PATH/keys/my-sign-key algorithm=dilithium3 key_type=signing"
read -p "Press Enter to execute..."
vault write $MOUNT_PATH/keys/my-sign-key algorithm=dilithium3 key_type=signing
echo ""

# Test 6: Sign
echo -e "${YELLOW}Step 6: Sign some data${NC}"
MESSAGE=$(echo -n "Important document" | base64)
echo "Message (base64): $MESSAGE"
echo "Command: vault write $MOUNT_PATH/sign/my-sign-key input=\"$MESSAGE\""
read -p "Press Enter to execute..."
SIGNATURE_OUTPUT=$(vault write $MOUNT_PATH/sign/my-sign-key input="$MESSAGE" -format=json)
SIGNATURE=$(echo "$SIGNATURE_OUTPUT" | jq -r '.data.signature')
echo "Signature: $SIGNATURE"
echo ""

# Test 7: Verify
echo -e "${YELLOW}Step 7: Verify the signature${NC}"
echo "Command: vault write $MOUNT_PATH/verify/my-sign-key input=\"$MESSAGE\" signature=\"$SIGNATURE\""
read -p "Press Enter to execute..."
vault write $MOUNT_PATH/verify/my-sign-key input="$MESSAGE" signature="$SIGNATURE"
echo ""

# Test 8: List Keys
echo -e "${YELLOW}Step 8: List all keys${NC}"
echo "Command: vault list $MOUNT_PATH/keys"
read -p "Press Enter to execute..."
vault list $MOUNT_PATH/keys
echo ""

echo -e "${GREEN}Manual testing complete!${NC}"




