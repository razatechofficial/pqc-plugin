#!/bin/bash

# Script to build, deploy, and register the PQC plugin on remote Vault server
# Usage: ./scripts/register-remote-plugin.sh

set +e  # Don't exit on error, we'll handle errors explicitly

# Load environment variables from .env file if it exists
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
if [ -f "$PROJECT_ROOT/.env" ]; then
    set -a
    source "$PROJECT_ROOT/.env"
    set +a
fi

# Configuration
REMOTE_HOST="${REMOTE_HOST:-104.237.11.39}"
REMOTE_USER="${REMOTE_USER:-root}"
REMOTE_PASSWORD="${REMOTE_PASSWORD:-MaidlyAbregeRubricNeakes}"
VAULT_ADDR="${VAULT_ADDR:-https://kms.averox.com}"
if [ -z "$VAULT_TOKEN" ]; then
    echo "Error: VAULT_TOKEN environment variable is not set"
    echo "Please set it with: export VAULT_TOKEN=your_token_here"
    exit 1
fi
PLUGIN_NAME="vault-plugin-pqc"
PLUGIN_DIR="/etc/vault.d/plugins"
MOUNT_PATH="pqc"
CATALOG_NAME="pqc-plugin"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

# Helper function to run commands on remote server
run_remote() {
    if command -v sshpass &> /dev/null && [ -n "$REMOTE_PASSWORD" ]; then
        sshpass -p "$REMOTE_PASSWORD" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $REMOTE_USER@$REMOTE_HOST "$@"
    else
        ssh -o StrictHostKeyChecking=no $REMOTE_USER@$REMOTE_HOST "$@"
    fi
}

# Helper function to copy files to remote server
copy_remote() {
    local src="$1"
    local dst="$2"
    if command -v sshpass &> /dev/null && [ -n "$REMOTE_PASSWORD" ]; then
        sshpass -p "$REMOTE_PASSWORD" scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "$src" "$REMOTE_USER@$REMOTE_HOST:$dst"
    else
        scp -o StrictHostKeyChecking=no "$src" "$REMOTE_USER@$REMOTE_HOST:$dst"
    fi
}

# Helper function to run Vault commands on remote server
vault_cmd() {
    local cmd="$1"
    export_cmd="export VAULT_ADDR=$VAULT_ADDR && export VAULT_TOKEN=$VAULT_TOKEN && $cmd"
    run_remote "$export_cmd" 2>&1
}

echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}Post-Quantum Vault Plugin - Remote Registration${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "${YELLOW}Remote Server:${NC} $REMOTE_USER@$REMOTE_HOST"
echo -e "${YELLOW}Vault Address:${NC} $VAULT_ADDR"
echo -e "${YELLOW}Plugin Name:${NC} $CATALOG_NAME"
echo ""

# Step 1: Build the plugin for Linux
echo -e "${BLUE}[1/6] Building plugin for Linux...${NC}"
cd "$PROJECT_ROOT"
if ! make build-linux; then
    echo -e "${RED}✗ Failed to build plugin${NC}"
    exit 1
fi

if [ ! -f "./vault-plugin-pqc-linux" ]; then
    echo -e "${RED}✗ Plugin binary not found after build${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Plugin built successfully${NC}"
echo ""

# Step 2: Deploy plugin to remote server
echo -e "${BLUE}[2/6] Deploying plugin to remote server...${NC}"
run_remote "sudo mkdir -p $PLUGIN_DIR" || true
copy_remote "./vault-plugin-pqc-linux" "/tmp/$PLUGIN_NAME"

if [ $? -ne 0 ]; then
    echo -e "${RED}✗ Failed to copy plugin to remote server${NC}"
    exit 1
fi

# Move to plugin directory and set permissions
run_remote "sudo mv /tmp/$PLUGIN_NAME $PLUGIN_DIR/$PLUGIN_NAME && sudo chmod +x $PLUGIN_DIR/$PLUGIN_NAME && sudo chown vault:vault $PLUGIN_DIR/$PLUGIN_NAME 2>/dev/null || sudo chown root:root $PLUGIN_DIR/$PLUGIN_NAME"

if [ $? -ne 0 ]; then
    echo -e "${RED}✗ Failed to set plugin permissions${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Plugin deployed to $PLUGIN_DIR/$PLUGIN_NAME${NC}"
echo ""

# Step 3: Calculate SHA256 on remote server
echo -e "${BLUE}[3/6] Calculating SHA256 checksum on remote server...${NC}"
SHA256=$(run_remote "shasum -a 256 $PLUGIN_DIR/$PLUGIN_NAME 2>/dev/null | awk '{print \$1}' || sha256sum $PLUGIN_DIR/$PLUGIN_NAME 2>/dev/null | awk '{print \$1}'")

if [ -z "$SHA256" ]; then
    echo -e "${RED}✗ Failed to calculate SHA256${NC}"
    exit 1
fi

echo -e "${GREEN}✓ SHA256:${NC} $SHA256"
echo ""

# Step 4: Check if plugin is already registered
echo -e "${BLUE}[4/6] Checking plugin registration status...${NC}"
REGISTERED=$(vault_cmd "vault read sys/plugins/catalog/secret/$CATALOG_NAME" 2>&1 | grep -q "No value found" && echo "no" || echo "yes")

if [ "$REGISTERED" = "yes" ]; then
    echo -e "${YELLOW}⚠ Plugin is already registered${NC}"
    read -p "Do you want to re-register with new SHA256? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${YELLOW}Skipping registration...${NC}"
        SKIP_REGISTER=true
    fi
fi

# Step 5: Register the plugin
if [ "$SKIP_REGISTER" != "true" ]; then
    echo -e "${BLUE}[5/6] Registering plugin with Vault...${NC}"
    REGISTER_OUTPUT=$(vault_cmd "vault write sys/plugins/catalog/secret/$CATALOG_NAME sha256=\"$SHA256\" command=\"$PLUGIN_NAME\"")
    
    if echo "$REGISTER_OUTPUT" | grep -q "Error"; then
        echo -e "${RED}✗ Failed to register plugin:${NC}"
        echo "$REGISTER_OUTPUT"
        exit 1
    fi
    
    echo -e "${GREEN}✓ Plugin registered successfully${NC}"
    echo ""
else
    echo -e "${YELLOW}[5/6] Skipping registration (already registered)${NC}"
    echo ""
fi

# Step 6: Enable the plugin
echo -e "${BLUE}[6/6] Enabling plugin at mount path '$MOUNT_PATH'...${NC}"
ENABLED=$(vault_cmd "vault secrets list" 2>&1 | grep -q "^$MOUNT_PATH/" && echo "yes" || echo "no")

if [ "$ENABLED" = "yes" ]; then
    echo -e "${YELLOW}⚠ Plugin is already enabled at path: $MOUNT_PATH${NC}"
    read -p "Do you want to disable and re-enable? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${YELLOW}Disabling existing mount...${NC}"
        vault_cmd "vault secrets disable $MOUNT_PATH" > /dev/null 2>&1
        sleep 2
    else
        echo -e "${GREEN}✓ Plugin is already enabled${NC}"
        echo ""
        echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${GREEN}Registration Complete!${NC}"
        echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo ""
        echo -e "${GREEN}Plugin is available at:${NC} $VAULT_ADDR/v1/$MOUNT_PATH/"
        echo ""
        echo "Test the plugin:"
        echo "  ./scripts/remote-vault-command.sh 'vault write $MOUNT_PATH/keys/test-key algorithm=kyber768 key_type=encryption'"
        exit 0
    fi
fi

ENABLE_OUTPUT=$(vault_cmd "vault secrets enable -path=$MOUNT_PATH $CATALOG_NAME")

if echo "$ENABLE_OUTPUT" | grep -q "Error"; then
    echo -e "${RED}✗ Failed to enable plugin:${NC}"
    echo "$ENABLE_OUTPUT"
    exit 1
fi

echo -e "${GREEN}✓ Plugin enabled successfully${NC}"
echo ""

# Final summary
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}Registration Complete!${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "${GREEN}Plugin Details:${NC}"
echo "  - Catalog Name: $CATALOG_NAME"
echo "  - Mount Path: $MOUNT_PATH"
echo "  - Binary: $PLUGIN_DIR/$PLUGIN_NAME"
echo "  - SHA256: $SHA256"
echo ""
echo -e "${GREEN}Plugin is available at:${NC} $VAULT_ADDR/v1/$MOUNT_PATH/"
echo ""
echo -e "${YELLOW}Test the plugin:${NC}"
echo "  ./scripts/remote-vault-command.sh 'vault write $MOUNT_PATH/keys/test-key algorithm=kyber768 key_type=encryption'"
echo "  ./scripts/remote-vault-command.sh 'vault list $MOUNT_PATH/keys'"
echo ""

