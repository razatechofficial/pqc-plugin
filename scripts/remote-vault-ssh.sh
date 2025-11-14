#!/bin/bash

# Script to run Vault commands on remote server via SSH
# This allows you to use Vault CLI on the remote server without installing it locally

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

# Configuration
REMOTE_HOST="${REMOTE_HOST:-104.237.11.39}"
REMOTE_USER="${REMOTE_USER:-root}"
REMOTE_PASSWORD="${REMOTE_PASSWORD:-MaidlyAbregeRubricNeakes}"
VAULT_ADDR="${VAULT_ADDR:-https://kms.averox.com}"
VAULT_TOKEN="${VAULT_TOKEN:-hvs.Si4gMDMP1a6MwYqpIGiGJCic}"
MOUNT_PATH="pqc"
PLUGIN_NAME="pqc-plugin"

echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}  Remote Vault Operations via SSH${NC}"
echo -e "${BLUE}  Server: $REMOTE_USER@$REMOTE_HOST${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"

# Function to run command on remote server
run_remote() {
    if command -v sshpass &> /dev/null && [ -n "$REMOTE_PASSWORD" ]; then
        sshpass -p "$REMOTE_PASSWORD" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $REMOTE_USER@$REMOTE_HOST "$@"
    else
        ssh -o StrictHostKeyChecking=no $REMOTE_USER@$REMOTE_HOST "$@"
    fi
}

# Test SSH connection
echo -e "${YELLOW}Testing SSH connection...${NC}"
if run_remote "echo 'SSH connection successful'" &> /dev/null; then
    echo -e "${GREEN}✓ SSH connection successful${NC}\n"
else
    echo -e "${RED}✗ SSH connection failed${NC}"
    echo -e "${YELLOW}Please check:${NC}"
    echo "  1. SSH access to $REMOTE_USER@$REMOTE_HOST"
    echo "  2. SSH keys are set up"
    echo "  3. User has access to the server"
    exit 1
fi

# Check if Vault CLI is installed on remote server
echo -e "${YELLOW}Checking Vault CLI on remote server...${NC}"
if run_remote "command -v vault" &> /dev/null; then
    VAULT_VERSION=$(run_remote "vault version" | head -1)
    echo -e "${GREEN}✓ Vault CLI found: $VAULT_VERSION${NC}\n"
else
    echo -e "${RED}✗ Vault CLI not found on remote server${NC}"
    echo -e "${YELLOW}Installing Vault CLI on remote server...${NC}"
    
    # Try to install Vault CLI
    run_remote "curl -fsSL https://apt.releases.hashicorp.com/gpg | sudo apt-key add -" || true
    run_remote "sudo apt-add-repository 'deb https://apt.releases.hashicorp.com $(lsb_release -cs) main'" || true
    run_remote "sudo apt-get update && sudo apt-get install -y vault" || {
        echo -e "${RED}Failed to install Vault CLI automatically${NC}"
        echo -e "${YELLOW}Please install Vault CLI manually on the server${NC}"
        exit 1
    }
    echo -e "${GREEN}✓ Vault CLI installed${NC}\n"
fi

# Set Vault environment on remote
export_cmd="export VAULT_ADDR=$VAULT_ADDR && export VAULT_TOKEN=$VAULT_TOKEN"

# Test Vault connection
echo -e "${YELLOW}Testing Vault connection on remote server...${NC}"
if run_remote "$export_cmd && vault status" &> /dev/null; then
    echo -e "${GREEN}✓ Vault connection successful${NC}\n"
    run_remote "$export_cmd && vault status" | head -5
    echo ""
else
    echo -e "${RED}✗ Cannot connect to Vault${NC}"
    echo -e "${YELLOW}Please check VAULT_ADDR and VAULT_TOKEN${NC}"
    exit 1
fi

# Check plugin registration
echo -e "${YELLOW}Checking plugin registration...${NC}"
if run_remote "$export_cmd && vault read sys/plugins/catalog/secret/$PLUGIN_NAME" &> /dev/null; then
    echo -e "${GREEN}✓ Plugin is registered${NC}"
    run_remote "$export_cmd && vault read sys/plugins/catalog/secret/$PLUGIN_NAME"
    echo ""
else
    echo -e "${YELLOW}⚠ Plugin is not registered${NC}"
    echo ""
    read -p "Do you want to register the plugin? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        # Get SHA256 from local binary or remote
        if [ -f "./vault-plugin-pqc" ]; then
            SHA256=$(shasum -a 256 ./vault-plugin-pqc | awk '{print $1}')
        else
            # Try to get from remote
            SHA256=$(run_remote "shasum -a 256 /etc/vault.d/plugins/vault-plugin-pqc 2>/dev/null | awk '{print \$1}'" || echo "")
            if [ -z "$SHA256" ]; then
                read -p "Enter SHA256 checksum: " SHA256
            fi
        fi
        
        echo "Registering plugin with SHA256: $SHA256"
        run_remote "$export_cmd && vault write sys/plugins/catalog/secret/$PLUGIN_NAME sha256=\"$SHA256\" command=\"vault-plugin-pqc\""
        echo -e "${GREEN}✓ Plugin registered${NC}\n"
    fi
fi

# Check if plugin is enabled
echo -e "${YELLOW}Checking if plugin is enabled...${NC}"
if run_remote "$export_cmd && vault secrets list" | grep -q "^$MOUNT_PATH/"; then
    echo -e "${GREEN}✓ Plugin is enabled at: $MOUNT_PATH${NC}\n"
else
    echo -e "${YELLOW}⚠ Plugin is not enabled${NC}"
    echo ""
    read -p "Do you want to enable the plugin? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        run_remote "$export_cmd && vault secrets enable -path=$MOUNT_PATH $PLUGIN_NAME"
        echo -e "${GREEN}✓ Plugin enabled${NC}\n"
    fi
fi

# Show available commands
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}Available Operations${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"

# List keys
echo -e "${YELLOW}Listing keys:${NC}"
run_remote "$export_cmd && vault list $MOUNT_PATH/keys" || echo "  (no keys found)"
echo ""

# Menu
while true; do
    echo -e "${BLUE}What would you like to do?${NC}"
    echo "  1) List keys"
    echo "  2) Create encryption key"
    echo "  3) Create signing key"
    echo "  4) Encrypt data"
    echo "  5) Decrypt data"
    echo "  6) Sign data"
    echo "  7) Verify signature"
    echo "  8) Read key info"
    echo "  9) Vault status"
    echo "  10) Exit"
    echo ""
    read -p "Enter choice [1-10]: " choice
    
    case $choice in
        1)
            echo ""
            run_remote "$export_cmd && vault list $MOUNT_PATH/keys"
            echo ""
            ;;
        2)
            read -p "Key name: " key_name
            echo ""
            run_remote "$export_cmd && vault write $MOUNT_PATH/keys/$key_name algorithm=kyber768 key_type=encryption"
            echo ""
            ;;
        3)
            read -p "Key name: " key_name
            echo ""
            run_remote "$export_cmd && vault write $MOUNT_PATH/keys/$key_name algorithm=dilithium3 key_type=signing"
            echo ""
            ;;
        4)
            read -p "Key name: " key_name
            read -p "Plaintext: " plaintext
            plaintext_b64=$(echo -n "$plaintext" | base64)
            echo ""
            run_remote "$export_cmd && vault write $MOUNT_PATH/encrypt/$key_name plaintext=\"$plaintext_b64\""
            echo ""
            ;;
        5)
            read -p "Key name: " key_name
            read -p "Ciphertext: " ciphertext
            echo ""
            run_remote "$export_cmd && vault write $MOUNT_PATH/decrypt/$key_name ciphertext=\"$ciphertext\""
            echo ""
            ;;
        6)
            read -p "Key name: " key_name
            read -p "Data to sign: " data
            data_b64=$(echo -n "$data" | base64)
            echo ""
            run_remote "$export_cmd && vault write $MOUNT_PATH/sign/$key_name input=\"$data_b64\""
            echo ""
            ;;
        7)
            read -p "Key name: " key_name
            read -p "Data: " data
            read -p "Signature: " signature
            data_b64=$(echo -n "$data" | base64)
            echo ""
            run_remote "$export_cmd && vault write $MOUNT_PATH/verify/$key_name input=\"$data_b64\" signature=\"$signature\""
            echo ""
            ;;
        8)
            read -p "Key name: " key_name
            echo ""
            run_remote "$export_cmd && vault read $MOUNT_PATH/keys/$key_name"
            echo ""
            ;;
        9)
            echo ""
            run_remote "$export_cmd && vault status"
            echo ""
            ;;
        10)
            echo -e "${GREEN}Goodbye!${NC}"
            exit 0
            ;;
        *)
            echo -e "${RED}Invalid choice${NC}\n"
            ;;
    esac
done

