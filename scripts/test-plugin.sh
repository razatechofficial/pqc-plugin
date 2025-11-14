#!/bin/bash

# End-to-end test script for Post-Quantum Cryptography Vault Plugin
# This script tests the actual plugin functionality with a real Vault instance

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
VAULT_ADDR="${VAULT_ADDR:-https://kms.averox.com}"
VAULT_TOKEN="${VAULT_TOKEN:-hvs.Si4gMDMP1a6MwYqpIGiGJCic}"
PLUGIN_NAME="pqc-plugin"
MOUNT_PATH="pqc"
PLUGIN_BINARY="./vault-plugin-pqc"

# Test counters
TESTS_PASSED=0
TESTS_FAILED=0

# Function to print test header
print_test() {
    echo -e "\n${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}Test: $1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

# Function to print success
print_success() {
    echo -e "${GREEN}✓ $1${NC}"
    ((TESTS_PASSED++))
}

# Function to print failure
print_failure() {
    echo -e "${RED}✗ $1${NC}"
    ((TESTS_FAILED++))
}

# Function to print info
print_info() {
    echo -e "${YELLOW}ℹ $1${NC}"
}

# Check prerequisites
check_prerequisites() {
    print_test "Checking Prerequisites"
    
    if ! command -v vault &> /dev/null; then
        print_failure "Vault CLI not found. Please install HashiCorp Vault CLI."
        exit 1
    fi
    print_success "Vault CLI found"
    
    if [ ! -f "$PLUGIN_BINARY" ]; then
        print_failure "Plugin binary not found at $PLUGIN_BINARY"
        print_info "Building plugin..."
        make build
        if [ ! -f "$PLUGIN_BINARY" ]; then
            print_failure "Failed to build plugin"
            exit 1
        fi
    fi
    print_success "Plugin binary found"
    
    # Set Vault environment
    export VAULT_ADDR
    export VAULT_TOKEN
    
    # Test Vault connection
    if ! vault status &> /dev/null; then
        print_failure "Cannot connect to Vault at $VAULT_ADDR"
        exit 1
    fi
    print_success "Vault connection successful"
}

# Test 1: Check if plugin is registered
test_plugin_registered() {
    print_test "Test 1: Check Plugin Registration"
    
    if vault read sys/plugins/catalog/secret/$PLUGIN_NAME &> /dev/null; then
        print_success "Plugin is registered"
    else
        print_failure "Plugin is not registered"
        print_info "Please register the plugin first using: ./scripts/register-plugin.sh"
        exit 1
    fi
}

# Test 2: Check if plugin is enabled
test_plugin_enabled() {
    print_test "Test 2: Check Plugin Mount"
    
    if vault secrets list | grep -q "^$MOUNT_PATH/"; then
        print_success "Plugin is enabled at path: $MOUNT_PATH"
    else
        print_failure "Plugin is not enabled"
        print_info "Enabling plugin..."
        vault secrets enable -path=$MOUNT_PATH $PLUGIN_NAME
        print_success "Plugin enabled"
    fi
}

# Test 3: Create encryption key
test_create_encryption_key() {
    print_test "Test 3: Create Encryption Key (Kyber768)"
    
    KEY_NAME="test-enc-key-$(date +%s)"
    
    OUTPUT=$(vault write $MOUNT_PATH/keys/$KEY_NAME \
        algorithm=kyber768 \
        key_type=encryption 2>&1)
    
    if [ $? -eq 0 ]; then
        print_success "Encryption key created: $KEY_NAME"
        echo "$OUTPUT" | grep -q "public_key" && print_success "Public key returned"
        echo "$OUTPUT" | grep -q "algorithm.*kyber768" && print_success "Correct algorithm set"
        echo "$KEY_NAME" > /tmp/pqc_test_enc_key.txt
    else
        print_failure "Failed to create encryption key"
        echo "$OUTPUT"
        return 1
    fi
}

# Test 4: Create signing key
test_create_signing_key() {
    print_test "Test 4: Create Signing Key (Dilithium3)"
    
    KEY_NAME="test-sig-key-$(date +%s)"
    
    OUTPUT=$(vault write $MOUNT_PATH/keys/$KEY_NAME \
        algorithm=dilithium3 \
        key_type=signing 2>&1)
    
    if [ $? -eq 0 ]; then
        print_success "Signing key created: $KEY_NAME"
        echo "$OUTPUT" | grep -q "public_key" && print_success "Public key returned"
        echo "$OUTPUT" | grep -q "algorithm.*dilithium3" && print_success "Correct algorithm set"
        echo "$KEY_NAME" > /tmp/pqc_test_sig_key.txt
    else
        print_failure "Failed to create signing key"
        echo "$OUTPUT"
        return 1
    fi
}

# Test 5: List keys
test_list_keys() {
    print_test "Test 5: List Keys"
    
    OUTPUT=$(vault list $MOUNT_PATH/keys 2>&1)
    
    if [ $? -eq 0 ]; then
        KEY_COUNT=$(echo "$OUTPUT" | grep -v "Keys" | grep -v "^$" | wc -l | tr -d ' ')
        print_success "Listed $KEY_COUNT keys"
        if [ "$KEY_COUNT" -gt 0 ]; then
            print_info "Keys found:"
            echo "$OUTPUT" | grep -v "Keys" | grep -v "^$" | head -5
        fi
    else
        print_failure "Failed to list keys"
        echo "$OUTPUT"
        return 1
    fi
}

# Test 6: Read key information
test_read_key() {
    print_test "Test 6: Read Key Information"
    
    if [ ! -f /tmp/pqc_test_enc_key.txt ]; then
        print_failure "No test key found"
        return 1
    fi
    
    KEY_NAME=$(cat /tmp/pqc_test_enc_key.txt)
    
    OUTPUT=$(vault read $MOUNT_PATH/keys/$KEY_NAME 2>&1)
    
    if [ $? -eq 0 ]; then
        print_success "Key information retrieved"
        echo "$OUTPUT" | grep -q "public_key" && print_success "Public key present"
        echo "$OUTPUT" | grep -q "algorithm" && print_success "Algorithm present"
        echo "$OUTPUT" | grep -q "key_type" && print_success "Key type present"
        ! echo "$OUTPUT" | grep -q "private_key" && print_success "Private key not exposed"
    else
        print_failure "Failed to read key"
        echo "$OUTPUT"
        return 1
    fi
}

# Test 7: Encrypt data
test_encrypt() {
    print_test "Test 7: Encrypt Data"
    
    if [ ! -f /tmp/pqc_test_enc_key.txt ]; then
        print_failure "No encryption key found"
        return 1
    fi
    
    KEY_NAME=$(cat /tmp/pqc_test_enc_key.txt)
    PLAINTEXT="Hello, Post-Quantum World! $(date)"
    PLAINTEXT_B64=$(echo -n "$PLAINTEXT" | base64)
    
    OUTPUT=$(vault write $MOUNT_PATH/encrypt/$KEY_NAME \
        plaintext="$PLAINTEXT_B64" 2>&1)
    
    if [ $? -eq 0 ]; then
        print_success "Data encrypted successfully"
        CIPHERTEXT=$(echo "$OUTPUT" | grep "ciphertext" | awk '{print $2}')
        if [ -n "$CIPHERTEXT" ]; then
            echo "$CIPHERTEXT" > /tmp/pqc_test_ciphertext.txt
            print_success "Ciphertext saved"
        fi
    else
        print_failure "Encryption failed"
        echo "$OUTPUT"
        return 1
    fi
}

# Test 8: Decrypt data
test_decrypt() {
    print_test "Test 8: Decrypt Data"
    
    if [ ! -f /tmp/pqc_test_enc_key.txt ] || [ ! -f /tmp/pqc_test_ciphertext.txt ]; then
        print_failure "Missing key or ciphertext"
        return 1
    fi
    
    KEY_NAME=$(cat /tmp/pqc_test_enc_key.txt)
    CIPHERTEXT=$(cat /tmp/pqc_test_ciphertext.txt)
    ORIGINAL_PLAINTEXT="Hello, Post-Quantum World!"
    
    OUTPUT=$(vault write $MOUNT_PATH/decrypt/$KEY_NAME \
        ciphertext="$CIPHERTEXT" 2>&1)
    
    if [ $? -eq 0 ]; then
        print_success "Data decrypted successfully"
        DECRYPTED_B64=$(echo "$OUTPUT" | grep "plaintext" | awk '{print $2}')
        if [ -n "$DECRYPTED_B64" ]; then
            DECRYPTED=$(echo "$DECRYPTED_B64" | base64 -d)
            if echo "$DECRYPTED" | grep -q "$ORIGINAL_PLAINTEXT"; then
                print_success "Decrypted text matches original"
            else
                print_failure "Decrypted text doesn't match"
                print_info "Original: $ORIGINAL_PLAINTEXT"
                print_info "Decrypted: $DECRYPTED"
            fi
        fi
    else
        print_failure "Decryption failed"
        echo "$OUTPUT"
        return 1
    fi
}

# Test 9: Sign data
test_sign() {
    print_test "Test 9: Sign Data"
    
    if [ ! -f /tmp/pqc_test_sig_key.txt ]; then
        print_failure "No signing key found"
        return 1
    fi
    
    KEY_NAME=$(cat /tmp/pqc_test_sig_key.txt)
    MESSAGE="Important document: $(date)"
    MESSAGE_B64=$(echo -n "$MESSAGE" | base64)
    echo "$MESSAGE_B64" > /tmp/pqc_test_message.txt
    
    OUTPUT=$(vault write $MOUNT_PATH/sign/$KEY_NAME \
        input="$MESSAGE_B64" 2>&1)
    
    if [ $? -eq 0 ]; then
        print_success "Data signed successfully"
        SIGNATURE=$(echo "$OUTPUT" | grep "signature" | awk '{print $2}')
        if [ -n "$SIGNATURE" ]; then
            echo "$SIGNATURE" > /tmp/pqc_test_signature.txt
            print_success "Signature saved"
        fi
    else
        print_failure "Signing failed"
        echo "$OUTPUT"
        return 1
    fi
}

# Test 10: Verify signature
test_verify() {
    print_test "Test 10: Verify Signature"
    
    if [ ! -f /tmp/pqc_test_sig_key.txt ] || [ ! -f /tmp/pqc_test_message.txt ] || [ ! -f /tmp/pqc_test_signature.txt ]; then
        print_failure "Missing key, message, or signature"
        return 1
    fi
    
    KEY_NAME=$(cat /tmp/pqc_test_sig_key.txt)
    MESSAGE_B64=$(cat /tmp/pqc_test_message.txt)
    SIGNATURE=$(cat /tmp/pqc_test_signature.txt)
    
    OUTPUT=$(vault write $MOUNT_PATH/verify/$KEY_NAME \
        input="$MESSAGE_B64" \
        signature="$SIGNATURE" 2>&1)
    
    if [ $? -eq 0 ]; then
        VALID=$(echo "$OUTPUT" | grep "valid" | awk '{print $2}')
        if [ "$VALID" = "true" ]; then
            print_success "Signature verified successfully"
        else
            print_failure "Signature verification failed"
            echo "$OUTPUT"
            return 1
        fi
    else
        print_failure "Verification request failed"
        echo "$OUTPUT"
        return 1
    fi
}

# Test 11: Verify with wrong message
test_verify_wrong_message() {
    print_test "Test 11: Verify Signature with Wrong Message"
    
    if [ ! -f /tmp/pqc_test_sig_key.txt ] || [ ! -f /tmp/pqc_test_signature.txt ]; then
        print_failure "Missing key or signature"
        return 1
    fi
    
    KEY_NAME=$(cat /tmp/pqc_test_sig_key.txt)
    WRONG_MESSAGE_B64=$(echo -n "Wrong message" | base64)
    SIGNATURE=$(cat /tmp/pqc_test_signature.txt)
    
    OUTPUT=$(vault write $MOUNT_PATH/verify/$KEY_NAME \
        input="$WRONG_MESSAGE_B64" \
        signature="$SIGNATURE" 2>&1)
    
    if [ $? -eq 0 ]; then
        VALID=$(echo "$OUTPUT" | grep "valid" | awk '{print $2}')
        if [ "$VALID" = "false" ]; then
            print_success "Correctly rejected invalid signature"
        else
            print_failure "Should have rejected invalid signature"
            return 1
        fi
    else
        print_failure "Verification request failed"
        echo "$OUTPUT"
        return 1
    fi
}

# Test 12: Test all algorithms
test_all_algorithms() {
    print_test "Test 12: Test All Algorithms"
    
    ALGORITHMS=("kyber512" "kyber768" "kyber1024" "dilithium2" "dilithium3" "dilithium5")
    
    for ALG in "${ALGORITHMS[@]}"; do
        if [[ "$ALG" == kyber* ]]; then
            KEY_TYPE="encryption"
        else
            KEY_TYPE="signing"
        fi
        
        KEY_NAME="test-${ALG}-$(date +%s)"
        
        OUTPUT=$(vault write $MOUNT_PATH/keys/$KEY_NAME \
            algorithm=$ALG \
            key_type=$KEY_TYPE 2>&1)
        
        if [ $? -eq 0 ]; then
            print_success "Algorithm $ALG works"
        else
            print_failure "Algorithm $ALG failed"
            echo "$OUTPUT"
        fi
    done
}

# Test 13: Error handling - wrong key type
test_error_handling() {
    print_test "Test 13: Error Handling"
    
    # Try to encrypt with signing key
    if [ -f /tmp/pqc_test_sig_key.txt ]; then
        KEY_NAME=$(cat /tmp/pqc_test_sig_key.txt)
        PLAINTEXT_B64=$(echo -n "test" | base64)
        
        OUTPUT=$(vault write $MOUNT_PATH/encrypt/$KEY_NAME \
            plaintext="$PLAINTEXT_B64" 2>&1)
        
        if [ $? -ne 0 ]; then
            print_success "Correctly rejected encryption with signing key"
        else
            print_failure "Should have rejected encryption with signing key"
        fi
    fi
    
    # Try to sign with encryption key
    if [ -f /tmp/pqc_test_enc_key.txt ]; then
        KEY_NAME=$(cat /tmp/pqc_test_enc_key.txt)
        MESSAGE_B64=$(echo -n "test" | base64)
        
        OUTPUT=$(vault write $MOUNT_PATH/sign/$KEY_NAME \
            input="$MESSAGE_B64" 2>&1)
        
        if [ $? -ne 0 ]; then
            print_success "Correctly rejected signing with encryption key"
        else
            print_failure "Should have rejected signing with encryption key"
        fi
    fi
}

# Cleanup function
cleanup() {
    print_test "Cleanup"
    
    # Clean up test keys (optional - comment out if you want to keep them)
    # if [ -f /tmp/pqc_test_enc_key.txt ]; then
    #     KEY_NAME=$(cat /tmp/pqc_test_enc_key.txt)
    #     vault delete $MOUNT_PATH/keys/$KEY_NAME &> /dev/null
    #     print_info "Cleaned up encryption key: $KEY_NAME"
    # fi
    
    # Remove temp files
    rm -f /tmp/pqc_test_*.txt
    print_success "Cleanup completed"
}

# Main execution
main() {
    echo -e "${GREEN}"
    echo "╔════════════════════════════════════════════════════════╗"
    echo "║  Post-Quantum Cryptography Vault Plugin E2E Tests     ║"
    echo "╚════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    check_prerequisites
    test_plugin_registered
    test_plugin_enabled
    test_create_encryption_key
    test_create_signing_key
    test_list_keys
    test_read_key
    test_encrypt
    test_decrypt
    test_sign
    test_verify
    test_verify_wrong_message
    test_all_algorithms
    test_error_handling
    cleanup
    
    # Print summary
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
        echo -e "${RED}Some tests failed. Please review the output above.${NC}\n"
        exit 1
    fi
}

# Trap to ensure cleanup on exit
trap cleanup EXIT

# Run main function
main




