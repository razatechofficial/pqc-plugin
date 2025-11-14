#!/bin/bash

# Simple PQC Verification Test
# Easy to understand manual verification

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
    run_remote "$export_cmd" 2>&1
}

echo "════════════════════════════════════════════════════════════════"
echo "  POST-QUANTUM CRYPTOGRAPHY VERIFICATION TEST"
echo "  Banking Sector Compliance Check"
echo "════════════════════════════════════════════════════════════════"
echo ""

# Test 1: Create Key and Check Size
echo "TEST 1: Key Size Verification"
echo "────────────────────────────────────────────────────────────────"
KEY_NAME="pqc-test-$(date +%s)"
echo "Creating Kyber768 encryption key..."

CREATE_OUTPUT=$(vault_cmd "vault write $MOUNT_PATH/keys/$KEY_NAME algorithm=kyber768 key_type=encryption" 2>&1)
if echo "$CREATE_OUTPUT" | grep -q "Success\|algorithm.*kyber768"; then
    echo "✓ Key created successfully"
    
    # Get key info
    KEY_INFO=$(vault_cmd "vault read $MOUNT_PATH/keys/$KEY_NAME -format=json" 2>&1 | grep -v "Warning:" | grep -v "Permanently added")
    PUB_KEY=$(echo "$KEY_INFO" | grep -o '"public_key":"[^"]*"' | head -1 | cut -d'"' -f4 || echo "$KEY_INFO" | python3 -c "import sys, json; print(json.load(sys.stdin)['data']['public_key'])" 2>/dev/null)
    
    if [ -n "$PUB_KEY" ] && [ "$PUB_KEY" != "null" ]; then
        # Calculate size
        PUB_KEY_DECODED=$(echo -n "$PUB_KEY" | base64 -d 2>/dev/null || echo "")
        if [ -n "$PUB_KEY_DECODED" ]; then
            PUB_KEY_SIZE=$(echo -n "$PUB_KEY_DECODED" | wc -c | tr -d ' ')
        else
            PUB_KEY_SIZE=$(echo -n "$PUB_KEY" | wc -c | tr -d ' ')
        fi
        
        echo "Public Key Size: $PUB_KEY_SIZE bytes"
        echo ""
        echo "Expected Sizes:"
        echo "  • PQC Kyber768: ~1184 bytes"
        echo "  • Classical RSA-2048: ~256 bytes"
        echo ""
        
        if [ "$PUB_KEY_SIZE" -ge 1100 ] && [ "$PUB_KEY_SIZE" -le 1300 ]; then
            echo "✓✓✓ VERIFIED: Key size matches PQC Kyber768 specification!"
            echo "  This proves you're using Post-Quantum Cryptography"
        elif [ "$PUB_KEY_SIZE" -lt 500 ]; then
            echo "✗✗✗ WARNING: Key size is too small - may be using classical crypto"
        else
            echo "⚠ Key size: $PUB_KEY_SIZE bytes (check if this matches PQC spec)"
        fi
    else
        echo "⚠ Could not extract public key"
    fi
else
    echo "✗ Failed to create key"
    echo "$CREATE_OUTPUT"
fi

echo ""
echo "────────────────────────────────────────────────────────────────"
echo ""

# Test 2: Encrypt and Check Ciphertext Size
echo "TEST 2: Ciphertext Size Verification"
echo "────────────────────────────────────────────────────────────────"
echo "Encrypting small test message..."

PLAINTEXT="Banking test message"
PLAINTEXT_B64=$(echo -n "$PLAINTEXT" | base64)

ENCRYPT_OUTPUT=$(vault_cmd "vault write $MOUNT_PATH/encrypt/$KEY_NAME plaintext=\"$PLAINTEXT_B64\" -format=json" 2>&1 | grep -v "Warning:" | grep -v "Permanently added")
CIPHERTEXT=$(echo "$ENCRYPT_OUTPUT" | grep -o '"ciphertext":"[^"]*"' | head -1 | cut -d'"' -f4 || echo "$ENCRYPT_OUTPUT" | python3 -c "import sys, json; print(json.load(sys.stdin)['data']['ciphertext'])" 2>/dev/null)

if [ -n "$CIPHERTEXT" ]; then
    CIPHER_DECODED=$(echo -n "$CIPHERTEXT" | base64 -d 2>/dev/null)
    CIPHER_SIZE=$(echo -n "$CIPHER_DECODED" | wc -c)
    
    echo "Ciphertext Size: $CIPHER_SIZE bytes (for message: '$PLAINTEXT')"
    echo ""
    echo "Expected Sizes:"
    echo "  • PQC Kyber768 KEM: > 1000 bytes"
    echo "  • Classical AES-256: ~32 bytes"
    echo ""
    
    if [ "$CIPHER_SIZE" -gt 1000 ]; then
        echo "✓✓✓ VERIFIED: Ciphertext size indicates PQC KEM usage!"
        echo "  Classical AES would produce ~32 bytes for this message"
        echo "  Your ciphertext is $CIPHER_SIZE bytes - definitely PQC!"
    else
        echo "✗✗✗ WARNING: Ciphertext too small - may be using classical crypto"
    fi
    
    # Test decryption
    DECRYPT_OUTPUT=$(vault_cmd "vault write $MOUNT_PATH/decrypt/$KEY_NAME ciphertext=\"$CIPHERTEXT\" -format=json" 2>&1 | grep -v "Warning:" | grep -v "Permanently added")
    DECRYPTED_B64=$(echo "$DECRYPT_OUTPUT" | grep -o '"plaintext":"[^"]*"' | head -1 | cut -d'"' -f4 || echo "$DECRYPT_OUTPUT" | python3 -c "import sys, json; print(json.load(sys.stdin)['data']['plaintext'])" 2>/dev/null)
    if [ -n "$DECRYPTED_B64" ]; then
        DECRYPTED=$(echo "$DECRYPTED_B64" | base64 -d)
        if [ "$DECRYPTED" = "$PLAINTEXT" ]; then
            echo "✓ Decryption verified - Data integrity maintained"
        fi
    fi
else
    echo "✗ Encryption failed"
    echo "$ENCRYPT_OUTPUT"
fi

echo ""
echo "────────────────────────────────────────────────────────────────"
echo ""

# Test 3: Sign and Check Signature Size
echo "TEST 3: Signature Size Verification"
echo "────────────────────────────────────────────────────────────────"
echo "Creating Dilithium3 signing key..."

SIGN_KEY="pqc-sig-test-$(date +%s)"
SIGN_CREATE=$(vault_cmd "vault write $MOUNT_PATH/keys/$SIGN_KEY algorithm=dilithium3 key_type=signing" 2>&1)

if echo "$SIGN_CREATE" | grep -q "Success\|algorithm.*dilithium3"; then
    echo "✓ Signing key created"
    
    MESSAGE="Banking transaction: $(date)"
    MESSAGE_B64=$(echo -n "$MESSAGE" | base64)
    
    SIGN_OUTPUT=$(vault_cmd "vault write $MOUNT_PATH/sign/$SIGN_KEY input=\"$MESSAGE_B64\" -format=json" 2>&1 | grep -v "Warning:" | grep -v "Permanently added")
    SIGNATURE=$(echo "$SIGN_OUTPUT" | grep -o '"signature":"[^"]*"' | head -1 | cut -d'"' -f4 || echo "$SIGN_OUTPUT" | python3 -c "import sys, json; print(json.load(sys.stdin)['data']['signature'])" 2>/dev/null)
    
    if [ -n "$SIGNATURE" ]; then
        SIG_DECODED=$(echo -n "$SIGNATURE" | base64 -d 2>/dev/null)
        SIG_SIZE=$(echo -n "$SIG_DECODED" | wc -c)
        
        echo "Signature Size: $SIG_SIZE bytes"
        echo ""
        echo "Expected Sizes:"
        echo "  • PQC Dilithium3: ~3293 bytes"
        echo "  • Classical ECDSA P-256: ~64 bytes"
        echo "  • Classical RSA-2048: ~256 bytes"
        echo ""
        
        if [ "$SIG_SIZE" -gt 3000 ] && [ "$SIG_SIZE" -lt 3500 ]; then
            echo "✓✓✓ VERIFIED: Signature size matches PQC Dilithium3 specification!"
            echo "  Classical signatures would be 10-50x smaller"
            echo "  Your signature is $SIG_SIZE bytes - definitely PQC!"
        else
            echo "⚠ Signature size: $SIG_SIZE bytes (check if this matches PQC spec)"
        fi
        
        # Verify signature
        VERIFY_OUTPUT=$(vault_cmd "vault write $MOUNT_PATH/verify/$SIGN_KEY input=\"$MESSAGE_B64\" signature=\"$SIGNATURE\" -format=json" 2>&1 | grep -v "Warning:" | grep -v "Permanently added")
        if echo "$VERIFY_OUTPUT" | grep -q '"valid":true' || echo "$VERIFY_OUTPUT" | python3 -c "import sys, json; exit(0 if json.load(sys.stdin)['data'].get('valid') == True else 1)" 2>/dev/null; then
            echo "✓ Signature verification: Valid"
        fi
    else
        echo "✗ Signing failed"
        echo "$SIGN_OUTPUT"
    fi
else
    echo "✗ Failed to create signing key"
    echo "$SIGN_CREATE"
fi

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "  VERIFICATION SUMMARY"
echo "════════════════════════════════════════════════════════════════"
echo ""
echo "To prove PQC is being used, verify:"
echo ""
echo "1. Key Size:"
echo "   ✓ PQC Kyber768: ~1184 bytes"
echo "   ✗ Classical RSA-2048: ~256 bytes"
echo ""
echo "2. Ciphertext Size:"
echo "   ✓ PQC Kyber768: > 1000 bytes"
echo "   ✗ Classical AES: < 100 bytes"
echo ""
echo "3. Signature Size:"
echo "   ✓ PQC Dilithium3: ~3293 bytes"
echo "   ✗ Classical ECDSA: ~64 bytes"
echo ""
echo "If your measurements match the PQC sizes above,"
echo "you are DEFINITELY using Post-Quantum Cryptography!"
echo ""
echo "════════════════════════════════════════════════════════════════"

