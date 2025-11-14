#!/bin/bash

# Quick PQC Verification - Simple manual test
# Run this to verify PQC is actually being used

set -e

VAULT_ADDR="${VAULT_ADDR:-https://kms.averox.com}"
VAULT_TOKEN="${VAULT_TOKEN:-hvs.Si4gMDMP1a6MwYqpIGiGJCic}"
MOUNT_PATH="pqc"
REMOTE_HOST="${REMOTE_HOST:-104.237.11.39}"
REMOTE_USER="${REMOTE_USER:-root}"
REMOTE_PASSWORD="${REMOTE_PASSWORD:-MaidlyAbregeRubricNeakes}"

export VAULT_ADDR
export VAULT_TOKEN

run_remote() {
    if command -v sshpass &> /dev/null && [ -n "$REMOTE_PASSWORD" ]; then
        sshpass -p "$REMOTE_PASSWORD" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $REMOTE_USER@$REMOTE_HOST "$@"
    else
        ssh -o StrictHostKeyChecking=no $REMOTE_USER@$REMOTE_HOST "$@"
    fi
}

vault_cmd() {
    export_cmd="export VAULT_ADDR=$VAULT_ADDR && export VAULT_TOKEN=$VAULT_TOKEN && $1"
    run_remote "$export_cmd"
}

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Quick PQC Verification Test"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Test 1: Check Key Size
echo "Test 1: Verifying Key Size (PQC vs Classical)"
echo "────────────────────────────────────────────────────────────────"

KEY_NAME="verify-$(date +%s)"
vault_cmd "vault write $MOUNT_PATH/keys/$KEY_NAME algorithm=kyber768 key_type=encryption" > /dev/null 2>&1

KEY_INFO=$(vault_cmd "vault read $MOUNT_PATH/keys/$KEY_NAME -format=json" 2>&1)
PUB_KEY=$(echo "$KEY_INFO" | grep -o '"public_key":"[^"]*"' | cut -d'"' -f4)

if [ -n "$PUB_KEY" ]; then
    # Decode and measure
    PUB_KEY_BYTES=$(echo -n "$PUB_KEY" | base64 -d 2>/dev/null | wc -c || echo "0")
    echo "Public Key Size: $PUB_KEY_BYTES bytes"
    
    if [ "$PUB_KEY_BYTES" -ge 1100 ] && [ "$PUB_KEY_BYTES" -le 1300 ]; then
        echo "✓ VERIFIED: Key size matches Kyber768 specification (~1184 bytes)"
        echo "  Classical RSA-2048 would be ~256 bytes (4.6x smaller)"
    else
        echo "⚠ Warning: Key size doesn't match expected PQC size"
    fi
fi

# Test 2: Check Ciphertext Size
echo ""
echo "Test 2: Verifying Ciphertext Size (PQC KEM vs Classical)"
echo "────────────────────────────────────────────────────────────────"

PLAINTEXT="Small test message"
PLAINTEXT_B64=$(echo -n "$PLAINTEXT" | base64)

ENCRYPT_OUT=$(vault_cmd "vault write $MOUNT_PATH/encrypt/$KEY_NAME plaintext=\"$PLAINTEXT_B64\" -format=json" 2>&1)
CIPHERTEXT=$(echo "$ENCRYPT_OUT" | grep -o '"ciphertext":"[^"]*"' | cut -d'"' -f4)

if [ -n "$CIPHERTEXT" ]; then
    CIPHER_BYTES=$(echo -n "$CIPHERTEXT" | base64 -d 2>/dev/null | wc -c || echo "0")
    echo "Ciphertext Size: $CIPHER_BYTES bytes (for message: '$PLAINTEXT')"
    
    if [ "$CIPHER_BYTES" -gt 1000 ]; then
        echo "✓ VERIFIED: Ciphertext size indicates PQC KEM usage"
        echo "  Classical AES-256 would be ~32 bytes for this message"
        echo "  PQC Kyber768 KEM produces ~1088+ bytes"
    else
        echo "✗ FAILED: Ciphertext too small - may be using classical crypto"
    fi
fi

# Test 3: Check Signature Size
echo ""
echo "Test 3: Verifying Signature Size (PQC vs Classical)"
echo "────────────────────────────────────────────────────────────────"

SIGN_KEY="verify-sig-$(date +%s)"
vault_cmd "vault write $MOUNT_PATH/keys/$SIGN_KEY algorithm=dilithium3 key_type=signing" > /dev/null 2>&1

MESSAGE="Banking transaction test"
MESSAGE_B64=$(echo -n "$MESSAGE" | base64)

SIGN_OUT=$(vault_cmd "vault write $MOUNT_PATH/sign/$SIGN_KEY input=\"$MESSAGE_B64\" -format=json" 2>&1)
SIGNATURE=$(echo "$SIGN_OUT" | grep -o '"signature":"[^"]*"' | cut -d'"' -f4)

if [ -n "$SIGNATURE" ]; then
    SIG_BYTES=$(echo -n "$SIGNATURE" | base64 -d 2>/dev/null | wc -c || echo "0")
    echo "Signature Size: $SIG_BYTES bytes"
    
    if [ "$SIG_BYTES" -gt 3000 ] && [ "$SIG_BYTES" -lt 3500 ]; then
        echo "✓ VERIFIED: Signature size matches Dilithium3 specification (~3293 bytes)"
        echo "  Classical ECDSA P-256 would be ~64 bytes (51x smaller)"
        echo "  Classical RSA-2048 would be ~256 bytes (13x smaller)"
    else
        echo "⚠ Warning: Signature size doesn't match expected PQC size"
    fi
fi

# Summary
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Verification Summary"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "To verify PQC is being used, check:"
echo ""
echo "1. Key Sizes:"
echo "   • PQC Kyber768: ~1184 bytes"
echo "   • Classical RSA-2048: ~256 bytes"
echo "   → If key is ~1184 bytes, you're using PQC ✓"
echo ""
echo "2. Ciphertext Sizes:"
echo "   • PQC Kyber768: > 1000 bytes"
echo "   • Classical AES: < 100 bytes"
echo "   → If ciphertext > 1000 bytes, you're using PQC ✓"
echo ""
echo "3. Signature Sizes:"
echo "   • PQC Dilithium3: ~3293 bytes"
echo "   • Classical ECDSA: ~64 bytes"
echo "   → If signature > 3000 bytes, you're using PQC ✓"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

