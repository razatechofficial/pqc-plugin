#!/bin/bash

# Verify PQC is actually being used by checking key/ciphertext/signature sizes
# This script proves you're using Post-Quantum Cryptography

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

vault_cmd_json() {
    export_cmd="export VAULT_ADDR=$VAULT_ADDR && export VAULT_TOKEN=$VAULT_TOKEN && $1"
    run_remote "$export_cmd" 2>/dev/null | grep -v "Warning:" | grep -v "Permanently added" | python3 -c "import sys, json; print(json.dumps(json.load(sys.stdin)))" 2>/dev/null || run_remote "$export_cmd" 2>/dev/null | grep -v "Warning:" | grep -v "Permanently added"
}

echo "════════════════════════════════════════════════════════════════"
echo "  POST-QUANTUM CRYPTOGRAPHY SIZE VERIFICATION"
echo "  Proving PQC is Actually Being Used"
echo "════════════════════════════════════════════════════════════════"
echo ""

# Test 1: Key Size
echo "TEST 1: Encryption Key Size (Kyber768)"
echo "────────────────────────────────────────────────────────────────"
KEY_NAME="pqc-verify-$(date +%s)"
echo "Creating Kyber768 key..."

CREATE_OUTPUT=$(run_remote "export VAULT_ADDR=$VAULT_ADDR && export VAULT_TOKEN=$VAULT_TOKEN && vault write $MOUNT_PATH/keys/$KEY_NAME algorithm=kyber768 key_type=encryption" 2>/dev/null)

if echo "$CREATE_OUTPUT" | grep -q "Success\|algorithm"; then
    echo "✓ Key created"
    
    KEY_JSON=$(vault_cmd_json "vault read $MOUNT_PATH/keys/$KEY_NAME -format=json")
    PUB_KEY=$(echo "$KEY_JSON" | python3 -c "import sys, json; print(json.load(sys.stdin)['data']['public_key'])" 2>/dev/null)
    
    if [ -n "$PUB_KEY" ] && [ "$PUB_KEY" != "null" ]; then
        PUB_KEY_BYTES=$(echo -n "$PUB_KEY" | base64 -d 2>/dev/null | wc -c | tr -d ' ')
        echo "Public Key Size: $PUB_KEY_BYTES bytes"
        
        if [ "$PUB_KEY_BYTES" -ge 1100 ] && [ "$PUB_KEY_BYTES" -le 1300 ]; then
            echo "✓✓✓ VERIFIED: Key size ($PUB_KEY_BYTES bytes) matches PQC Kyber768!"
        else
            echo "⚠ Key size: $PUB_KEY_BYTES bytes (expected ~1184 for Kyber768)"
        fi
    fi
fi

echo ""
echo "────────────────────────────────────────────────────────────────"
echo ""

# Test 2: Ciphertext Size
echo "TEST 2: Ciphertext Size (Kyber768 KEM)"
echo "────────────────────────────────────────────────────────────────"
PLAINTEXT="Test message"
PLAINTEXT_B64=$(echo -n "$PLAINTEXT" | base64)

ENCRYPT_JSON=$(vault_cmd_json "vault write $MOUNT_PATH/encrypt/$KEY_NAME plaintext=\"$PLAINTEXT_B64\" -format=json")
CIPHERTEXT=$(echo "$ENCRYPT_JSON" | python3 -c "import sys, json; print(json.load(sys.stdin)['data']['ciphertext'])" 2>/dev/null)

if [ -n "$CIPHERTEXT" ] && [ "$CIPHERTEXT" != "null" ]; then
    CIPHER_BYTES=$(echo -n "$CIPHERTEXT" | base64 -d 2>/dev/null | wc -c | tr -d ' ')
    echo "Ciphertext Size: $CIPHER_BYTES bytes (for message: '$PLAINTEXT')"
    
    if [ "$CIPHER_BYTES" -gt 1000 ]; then
        echo "✓✓✓ VERIFIED: Ciphertext size ($CIPHER_BYTES bytes) indicates PQC KEM!"
        echo "  Classical AES would be ~32 bytes for this message"
    else
        echo "⚠ Ciphertext size: $CIPHER_BYTES bytes (expected > 1000 for PQC)"
    fi
    
    # Verify decryption
    DECRYPT_JSON=$(vault_cmd_json "vault write $MOUNT_PATH/decrypt/$KEY_NAME ciphertext=\"$CIPHERTEXT\" -format=json")
    DECRYPTED_B64=$(echo "$DECRYPT_JSON" | python3 -c "import sys, json; print(json.load(sys.stdin)['data']['plaintext'])" 2>/dev/null)
    if [ -n "$DECRYPTED_B64" ]; then
        DECRYPTED=$(echo "$DECRYPTED_B64" | base64 -d)
        if [ "$DECRYPTED" = "$PLAINTEXT" ]; then
            echo "✓ Decryption verified - Data integrity maintained"
        fi
    fi
fi

echo ""
echo "────────────────────────────────────────────────────────────────"
echo ""

# Test 3: Signature Size
echo "TEST 3: Signature Size (Dilithium3)"
echo "────────────────────────────────────────────────────────────────"
SIGN_KEY="pqc-sig-verify-$(date +%s)"
SIGN_CREATE=$(run_remote "export VAULT_ADDR=$VAULT_ADDR && export VAULT_TOKEN=$VAULT_TOKEN && vault write $MOUNT_PATH/keys/$SIGN_KEY algorithm=dilithium3 key_type=signing" 2>/dev/null)

if echo "$SIGN_CREATE" | grep -q "Success\|algorithm"; then
    echo "✓ Signing key created"
    
    MESSAGE="Banking transaction test"
    MESSAGE_B64=$(echo -n "$MESSAGE" | base64)
    
    SIGN_JSON=$(vault_cmd_json "vault write $MOUNT_PATH/sign/$SIGN_KEY input=\"$MESSAGE_B64\" -format=json")
    SIGNATURE=$(echo "$SIGN_JSON" | python3 -c "import sys, json; print(json.load(sys.stdin)['data']['signature'])" 2>/dev/null)
    
    if [ -n "$SIGNATURE" ] && [ "$SIGNATURE" != "null" ]; then
        SIG_BYTES=$(echo -n "$SIGNATURE" | base64 -d 2>/dev/null | wc -c | tr -d ' ')
        echo "Signature Size: $SIG_BYTES bytes"
        
        if [ "$SIG_BYTES" -gt 3000 ] && [ "$SIG_BYTES" -lt 3500 ]; then
            echo "✓✓✓ VERIFIED: Signature size ($SIG_BYTES bytes) matches PQC Dilithium3!"
            echo "  Classical ECDSA would be ~64 bytes (50x smaller!)"
        else
            echo "⚠ Signature size: $SIG_BYTES bytes (expected ~3293 for Dilithium3)"
        fi
        
        # Verify signature
        VERIFY_JSON=$(vault_cmd_json "vault write $MOUNT_PATH/verify/$SIGN_KEY input=\"$MESSAGE_B64\" signature=\"$SIGNATURE\" -format=json")
        IS_VALID=$(echo "$VERIFY_JSON" | python3 -c "import sys, json; print(json.load(sys.stdin)['data'].get('valid', False))" 2>/dev/null)
        if [ "$IS_VALID" = "True" ]; then
            echo "✓ Signature verification: Valid"
        fi
    fi
fi

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "  VERIFICATION COMPLETE"
echo "════════════════════════════════════════════════════════════════"
echo ""
echo "If all three tests show ✓✓✓ VERIFIED, you are definitely"
echo "using Post-Quantum Cryptography (PQC) algorithms!"
echo ""
echo "Key Indicators:"
echo "  • Kyber768 keys: ~1184 bytes (vs RSA-2048: ~256 bytes)"
echo "  • Kyber768 ciphertexts: > 1000 bytes (vs AES: ~32 bytes)"
echo "  • Dilithium3 signatures: ~3293 bytes (vs ECDSA: ~64 bytes)"
echo ""
echo "════════════════════════════════════════════════════════════════"

