#!/bin/bash

# Script to register the post-quantum Vault plugin
# Usage: ./scripts/register-plugin.sh [plugin-binary-path]

set -e

# Load environment variables from .env file if it exists
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
if [ -f "$PROJECT_ROOT/.env" ]; then
    set -a
    source "$PROJECT_ROOT/.env"
    set +a
fi

# Configuration
VAULT_ADDR="${VAULT_ADDR:-https://kms.averox.com}"
VAULT_TOKEN="${VAULT_TOKEN:-your-vault-token-here}"
PLUGIN_NAME="pqc-plugin"
PLUGIN_BINARY="${1:-./vault-plugin-pqc}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}Post-Quantum Vault Plugin Registration${NC}"
echo "=========================================="

# Check if plugin binary exists
if [ ! -f "$PLUGIN_BINARY" ]; then
    echo -e "${RED}Error: Plugin binary not found at $PLUGIN_BINARY${NC}"
    echo "Please build the plugin first with 'make build'"
    exit 1
fi

# Check if vault CLI is available
if ! command -v vault &> /dev/null; then
    echo -e "${RED}Error: Vault CLI not found. Please install HashiCorp Vault CLI.${NC}"
    exit 1
fi

# Export Vault environment variables
export VAULT_ADDR
export VAULT_TOKEN

echo -e "${YELLOW}Vault Address:${NC} $VAULT_ADDR"
echo -e "${YELLOW}Plugin Binary:${NC} $PLUGIN_BINARY"

# Calculate SHA256 checksum
echo ""
echo -e "${GREEN}Calculating SHA256 checksum...${NC}"
if [[ "$OSTYPE" == "darwin"* ]]; then
    SHA256=$(shasum -a 256 "$PLUGIN_BINARY" | awk '{print $1}')
else
    SHA256=$(sha256sum "$PLUGIN_BINARY" | awk '{print $1}')
fi

echo -e "${GREEN}SHA256:${NC} $SHA256"

# Get the binary name (without path)
BINARY_NAME=$(basename "$PLUGIN_BINARY")

# Register the plugin
echo ""
echo -e "${GREEN}Registering plugin with Vault...${NC}"
vault write sys/plugins/catalog/secret/$PLUGIN_NAME \
    sha256="$SHA256" \
    command="$BINARY_NAME"

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Plugin registered successfully!${NC}"
else
    echo -e "${RED}✗ Failed to register plugin${NC}"
    exit 1
fi

# Enable the plugin
echo ""
echo -e "${GREEN}Enabling plugin at mount path 'pqc'...${NC}"
vault secrets enable -path=pqc $PLUGIN_NAME

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Plugin enabled successfully!${NC}"
    echo ""
    echo -e "${GREEN}Plugin is now available at:${NC} $VAULT_ADDR/v1/pqc/"
    echo ""
    echo "You can now use the plugin:"
    echo "  vault write pqc/keys/my-key algorithm=kyber768 key_type=encryption"
else
    echo -e "${YELLOW}⚠ Plugin may already be enabled${NC}"
fi

echo ""
echo -e "${GREEN}Registration complete!${NC}"

