#!/bin/bash

# End-to-end test script for remote Vault at kms.averox.com
# This script tests the plugin with your actual remote Vault instance

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration - Remote Vault
VAULT_ADDR="${VAULT_ADDR:-https://kms.averox.com}"
VAULT_TOKEN="${VAULT_TOKEN:-hvs.Si4gMDMP1a6MwYqpIGiGJCic}"
MOUNT_PATH="pqc"
PLUGIN_NAME="pqc-plugin"

export VAULT_ADDR
export VAULT_TOKEN

# Test counters
TESTS_PASSED=0
TESTS_FAILED=0

print_test() {
    echo -e "\n${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}Test: $1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
    ((TESTS_PASSED++))
}

print_failure() {
    echo -e "${RED}✗ $1${NC}"
    ((TESTS_FAILED++))
}

print_info() {
    echo -e "${YELLOW}ℹ $1${NC}"
}

# Check connection
check_connection() {
    print_test "Checking Remote Vault Connection"
    
    if ! command -v vault &> /dev/null; then
        print_failure "Vault CLI not found"
        exit 1
    fi
    
    if vault status &> /dev/null; then
        print_success "Connected to $VAULT_ADDR"
        vault status | head -5
    else
        print_failure "Cannot connect to $VAULT_ADDR"
        print_info "Check VAULT_ADDR and VAULT_TOKEN"
        exit 1
    fi
}

# Test plugin registration
test_plugin_registered() {
    print_test "Test Plugin Registration"
    
    if vault read sys/plugins/catalog/secret/$PLUGIN_NAME &> /dev/null; then
        print_success "Plugin is registered"
        PLUGIN_INFO=$(vault read sys/plugins/catalog/secret/$PLUGIN_NAME -format=json)
        echo "$PLUGIN_INFO" | jq -r '.data | "  Command: \(.command)\n  SHA256: \(.sha256)"'
    else
        print_failure "Plugin is not registered"
        print_info "Run: ./scripts/register-plugin.sh"
        exit 1
    fi
}

# Test plugin enabled
test_plugin_enabled() {
    print_test "Test Plugin Mount"
    
    if vault secrets list | grep -q "^$MOUNT_PATH/"; then
        print_success "Plugin is enabled at: $MOUNT_PATH"
    else
        print_failure "Plugin is not enabled"
        print_info "Enabling plugin..."
        if vault secrets enable -path=$MOUNT_PATH $PLUGIN_NAME 2>/dev/null; then
            print_success "Plugin enabled"
        else
            print_failure "Failed to enable plugin"
            exit 1
        fi
    fi
}

# Test create encryption key
test_create_encryption_key() {
    print_test "Create Encryption Key (Kyber768)"
    
    KEY_NAME="test-enc-$(date +%s)"
    
    OUTPUT=$(vault write $MOUNT_PATH/keys/$KEY_NAME \
        algorithm=kyber768 \
        key_type=encryption 2>&1)
    
    if [ $? -eq 0 ]; then
        print_success "Key created: $KEY_NAME"
        echo "$KEY_NAME" > /tmp/pqc_remote_enc_key.txt
    else
        print_failure "Failed to create key"
        echo "$OUTPUT"
        return 1
    fi
}

# Test create signing key
test_create_signing_key() {
    print_test "Create Signing Key (Dilithium3)"
    
    KEY_NAME="test-sig-$(date +%s)"
    
    OUTPUT=$(vault write $MOUNT_PATH/keys/$KEY_NAME \
        algorithm=dilithium3 \
        key_type=signing 2>&1)
    
    if [ $? -eq 0 ]; then
        print_success "Key created: $KEY_NAME"
        echo "$KEY_NAME" > /tmp/pqc_remote_sig_key.txt
    else
        print_failure "Failed to create key"
        echo "$OUTPUT"
        return 1
    fi
}

# Test encrypt/decrypt
test_encrypt_decrypt() {
    print_test "Test Encryption/Decryption"
    
    if [ ! -f /tmp/pqc_remote_enc_key.txt ]; then
        print_failure "No encryption key found"
        return 1
    fi
    
    KEY_NAME=$(cat /tmp/pqc_remote_enc_key.txt)
    PLAINTEXT="Hello from Remote Vault! $(date)"
    PLAINTEXT_B64=$(echo -n "$PLAINTEXT" | base64)
    
    # Encrypt
    ENCRYPT_OUTPUT=$(vault write $MOUNT_PATH/encrypt/$KEY_NAME \
        plaintext="$PLAINTEXT_B64" -format=json 2>&1)
    
    if [ $? -eq 0 ]; then
        CIPHERTEXT=$(echo "$ENCRYPT_OUTPUT" | jq -r '.data.ciphertext')
        print_success "Encryption successful"
        
        # Decrypt
        DECRYPT_OUTPUT=$(vault write $MOUNT_PATH/decrypt/$KEY_NAME \
            ciphertext="$CIPHERTEXT" -format=json 2>&1)
        
        if [ $? -eq 0 ]; then
            DECRYPTED_B64=$(echo "$DECRYPT_OUTPUT" | jq -r '.data.plaintext')
            DECRYPTED=$(echo "$DECRYPTED_B64" | base64 -d)
            
            if echo "$DECRYPTED" | grep -q "$PLAINTEXT"; then
                print_success "Decryption successful - data matches"
            else
                print_failure "Decrypted data doesn't match"
            fi
        else
            print_failure "Decryption failed"
            echo "$DECRYPT_OUTPUT"
        fi
    else
        print_failure "Encryption failed"
        echo "$ENCRYPT_OUTPUT"
    fi
}

# Test sign/verify
test_sign_verify() {
    print_test "Test Signing/Verification"
    
    if [ ! -f /tmp/pqc_remote_sig_key.txt ]; then
        print_failure "No signing key found"
        return 1
    fi
    
    KEY_NAME=$(cat /tmp/pqc_remote_sig_key.txt)
    MESSAGE="Important document: $(date)"
    MESSAGE_B64=$(echo -n "$MESSAGE" | base64)
    
    # Sign
    SIGN_OUTPUT=$(vault write $MOUNT_PATH/sign/$KEY_NAME \
        input="$MESSAGE_B64" -format=json 2>&1)
    
    if [ $? -eq 0 ]; then
        SIGNATURE=$(echo "$SIGN_OUTPUT" | jq -r '.data.signature')
        print_success "Signing successful"
        
        # Verify
        VERIFY_OUTPUT=$(vault write $MOUNT_PATH/verify/$KEY_NAME \
            input="$MESSAGE_B64" \
            signature="$SIGNATURE" -format=json 2>&1)
        
        if [ $? -eq 0 ]; then
            VALID=$(echo "$VERIFY_OUTPUT" | jq -r '.data.valid')
            if [ "$VALID" = "true" ]; then
                print_success "Verification successful - signature valid"
            else
                print_failure "Signature verification failed"
            fi
        else
            print_failure "Verification request failed"
            echo "$VERIFY_OUTPUT"
        fi
    else
        print_failure "Signing failed"
        echo "$SIGN_OUTPUT"
    fi
}

# Test list keys
test_list_keys() {
    print_test "List Keys"
    
    OUTPUT=$(vault list $MOUNT_PATH/keys 2>&1)
    
    if [ $? -eq 0 ]; then
        KEY_COUNT=$(echo "$OUTPUT" | grep -v "Keys" | grep -v "^$" | wc -l | tr -d ' ')
        print_success "Listed $KEY_COUNT keys"
    else
        print_failure "Failed to list keys"
        echo "$OUTPUT"
    fi
}

# Cleanup
cleanup() {
    print_test "Cleanup"
    rm -f /tmp/pqc_remote_*.txt
    print_success "Cleanup completed"
}

# Main
main() {
    echo -e "${GREEN}"
    echo "╔════════════════════════════════════════════════════════╗"
    echo "║  Remote Vault Plugin E2E Tests                        ║"
    echo "║  Endpoint: $VAULT_ADDR"
    echo "╚════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    check_connection
    test_plugin_registered
    test_plugin_enabled
    test_create_encryption_key
    test_create_signing_key
    test_list_keys
    test_encrypt_decrypt
    test_sign_verify
    cleanup
    
    # Summary
    echo -e "\n${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}Test Summary${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}Tests Passed: $TESTS_PASSED${NC}"
    echo -e "${RED}Tests Failed: $TESTS_FAILED${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
    
    if [ $TESTS_FAILED -eq 0 ]; then
        echo -e "${GREEN}All tests passed! ✓${NC}\n"
        exit 0
    else
        echo -e "${RED}Some tests failed.${NC}\n"
        exit 1
    fi
}

trap cleanup EXIT
main

