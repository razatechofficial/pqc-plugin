#!/bin/bash

# Script to connect and test with remote HashiCorp Vault
# Vault endpoint: https://kms.averox.com

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

# Configuration
VAULT_ADDR="${VAULT_ADDR:-https://kms.averox.com}"
VAULT_TOKEN="${VAULT_TOKEN:-hvs.Si4gMDMP1a6MwYqpIGiGJCic}"
MOUNT_PATH="pqc"
PLUGIN_NAME="pqc-plugin"

export VAULT_ADDR
export VAULT_TOKEN

echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}  Connect to Remote HashiCorp Vault${NC}"
echo -e "${BLUE}  Endpoint: $VAULT_ADDR${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"

# Check if vault CLI is installed
if ! command -v vault &> /dev/null; then
    echo -e "${RED}✗ Vault CLI not found. Please install HashiCorp Vault CLI.${NC}"
    exit 1
fi

# Test connection
echo -e "${YELLOW}Testing connection to Vault...${NC}"
if vault status &> /dev/null; then
    echo -e "${GREEN}✓ Successfully connected to Vault${NC}\n"
    
    # Show Vault status
    echo -e "${BLUE}Vault Status:${NC}"
    vault status
    echo ""
else
    echo -e "${RED}✗ Failed to connect to Vault${NC}"
    echo -e "${YELLOW}Please check:${NC}"
    echo "  1. VAULT_ADDR is correct: $VAULT_ADDR"
    echo "  2. VAULT_TOKEN is valid"
    echo "  3. Network connectivity to $VAULT_ADDR"
    echo "  4. TLS certificate is valid"
    exit 1
fi

# Check if plugin is registered
echo -e "${YELLOW}Checking if plugin is registered...${NC}"
if vault read sys/plugins/catalog/secret/$PLUGIN_NAME &> /dev/null; then
    echo -e "${GREEN}✓ Plugin is registered${NC}"
    vault read sys/plugins/catalog/secret/$PLUGIN_NAME
    echo ""
else
    echo -e "${YELLOW}⚠ Plugin is not registered${NC}"
    echo -e "${YELLOW}You need to register the plugin first.${NC}"
    echo ""
    read -p "Do you want to register the plugin now? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${YELLOW}Registering plugin...${NC}"
        
        # Check if plugin binary exists locally
        if [ -f "./vault-plugin-pqc" ]; then
            SHA256=$(shasum -a 256 ./vault-plugin-pqc | awk '{print $1}')
            echo "SHA256: $SHA256"
            
            vault write sys/plugins/catalog/secret/$PLUGIN_NAME \
                sha256="$SHA256" \
                command="vault-plugin-pqc"
            
            echo -e "${GREEN}✓ Plugin registered${NC}"
        else
            echo -e "${RED}✗ Plugin binary not found locally${NC}"
            echo "Please build the plugin first: make build"
            echo "Or provide the SHA256 checksum manually"
            read -p "Enter SHA256 checksum: " SHA256
            vault write sys/plugins/catalog/secret/$PLUGIN_NAME \
                sha256="$SHA256" \
                command="vault-plugin-pqc"
        fi
        echo ""
    fi
fi

# Check if plugin is enabled
echo -e "${YELLOW}Checking if plugin is enabled...${NC}"
if vault secrets list | grep -q "^$MOUNT_PATH/"; then
    echo -e "${GREEN}✓ Plugin is enabled at path: $MOUNT_PATH${NC}"
    echo ""
else
    echo -e "${YELLOW}⚠ Plugin is not enabled${NC}"
    echo -e "${YELLOW}You need to enable the plugin.${NC}"
    echo ""
    read -p "Do you want to enable the plugin now? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${YELLOW}Enabling plugin...${NC}"
        vault secrets enable -path=$MOUNT_PATH $PLUGIN_NAME
        echo -e "${GREEN}✓ Plugin enabled${NC}"
        echo ""
    fi
fi

# List all secrets engines
echo -e "${BLUE}Available Secrets Engines:${NC}"
vault secrets list
echo ""

# Test plugin functionality
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}  Quick Plugin Test${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"

# Check if mount exists
if vault secrets list | grep -q "^$MOUNT_PATH/"; then
    echo -e "${GREEN}Plugin is ready to use!${NC}\n"
    
    # List existing keys
    echo -e "${YELLOW}Existing keys:${NC}"
    if vault list $MOUNT_PATH/keys 2>/dev/null | grep -v "Keys" | grep -v "^$"; then
        vault list $MOUNT_PATH/keys
    else
        echo "  (no keys found)"
    fi
    echo ""
    
    # Offer to run a test
    read -p "Do you want to run a quick test? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${YELLOW}Creating test key...${NC}"
        TEST_KEY="test-key-$(date +%s)"
        
        vault write $MOUNT_PATH/keys/$TEST_KEY \
            algorithm=kyber768 \
            key_type=encryption
        
        echo -e "${GREEN}✓ Test key created: $TEST_KEY${NC}"
        echo ""
        
        echo -e "${YELLOW}Testing encryption...${NC}"
        PLAINTEXT=$(echo -n "Hello from remote Vault!" | base64)
        ENCRYPT_OUTPUT=$(vault write $MOUNT_PATH/encrypt/$TEST_KEY plaintext="$PLAINTEXT" -format=json)
        CIPHERTEXT=$(echo "$ENCRYPT_OUTPUT" | jq -r '.data.ciphertext')
        echo -e "${GREEN}✓ Encryption successful${NC}"
        echo ""
        
        echo -e "${YELLOW}Testing decryption...${NC}"
        DECRYPT_OUTPUT=$(vault write $MOUNT_PATH/decrypt/$TEST_KEY ciphertext="$CIPHERTEXT" -format=json)
        DECRYPTED=$(echo "$DECRYPT_OUTPUT" | jq -r '.data.plaintext' | base64 -d)
        echo -e "${GREEN}✓ Decryption successful${NC}"
        echo "  Decrypted: $DECRYPTED"
        echo ""
        
        echo -e "${GREEN}✓ All tests passed!${NC}"
    fi
else
    echo -e "${YELLOW}Plugin is not enabled. Please enable it first.${NC}"
fi

echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}Connection test complete!${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"

