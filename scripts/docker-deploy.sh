#!/bin/bash

# Script to deploy the plugin to a VPS with existing Vault installation

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

# Configuration
VAULT_PLUGIN_DIR="${VAULT_PLUGIN_DIR:-/etc/vault.d/plugins}"
PLUGIN_NAME="vault-plugin-pqc"
REMOTE_HOST="${REMOTE_HOST:-}"
REMOTE_USER="${REMOTE_USER:-vault}"

echo -e "${BLUE}Deploy Post-Quantum Cryptography Vault Plugin to VPS${NC}\n"

# Check if plugin is built
if [ ! -f "./build-output/$PLUGIN_NAME" ]; then
    echo -e "${RED}Plugin binary not found. Building...${NC}"
    ./scripts/docker-build.sh
fi

# If REMOTE_HOST is set, deploy remotely
if [ -n "$REMOTE_HOST" ]; then
    echo -e "${YELLOW}Deploying to remote host: $REMOTE_HOST${NC}"
    
    # Copy plugin to remote host
    scp ./build-output/$PLUGIN_NAME $REMOTE_USER@$REMOTE_HOST:/tmp/$PLUGIN_NAME
    
    # SSH and move to plugin directory
    ssh $REMOTE_USER@$REMOTE_HOST << EOF
        sudo mkdir -p $VAULT_PLUGIN_DIR
        sudo mv /tmp/$PLUGIN_NAME $VAULT_PLUGIN_DIR/$PLUGIN_NAME
        sudo chmod +x $VAULT_PLUGIN_DIR/$PLUGIN_NAME
        sudo chown vault:vault $VAULT_PLUGIN_DIR/$PLUGIN_NAME
        echo "Plugin deployed to $VAULT_PLUGIN_DIR/$PLUGIN_NAME"
        ls -lh $VAULT_PLUGIN_DIR/$PLUGIN_NAME
EOF
    
    echo -e "${GREEN}✓ Plugin deployed to $REMOTE_HOST${NC}"
    echo -e "${YELLOW}Next steps:${NC}"
    echo "1. SSH to the server: ssh $REMOTE_USER@$REMOTE_HOST"
    echo "2. Calculate SHA256: sudo shasum -a 256 $VAULT_PLUGIN_DIR/$PLUGIN_NAME"
    echo "3. Register plugin with Vault"
    echo "4. Enable the plugin"
else
    echo -e "${YELLOW}Local deployment mode${NC}"
    echo -e "${BLUE}Plugin binary location: ./build-output/$PLUGIN_NAME${NC}"
    echo -e "${YELLOW}To deploy remotely, set REMOTE_HOST:${NC}"
    echo "  export REMOTE_HOST=your-vps-ip"
    echo "  export REMOTE_USER=vault"
    echo "  ./scripts/docker-deploy.sh"
fi




