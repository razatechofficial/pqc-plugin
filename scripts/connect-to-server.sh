#!/bin/bash

# Quick connection script with server credentials
# Uses SSH with password authentication

set -e

# Server credentials
REMOTE_HOST="${REMOTE_HOST:-104.237.11.39}"
REMOTE_USER="${REMOTE_USER:-root}"
REMOTE_PASSWORD="${REMOTE_PASSWORD:-MaidlyAbregeRubricNeakes}"
VAULT_ADDR="${VAULT_ADDR:-https://kms.averox.com}"
VAULT_TOKEN="${VAULT_TOKEN:-hvs.Si4gMDMP1a6MwYqpIGiGJCic}"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}  Connecting to Vault Server${NC}"
echo -e "${BLUE}  Server: $REMOTE_USER@$REMOTE_HOST${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"

# Check if sshpass is installed (for password auth)
if ! command -v sshpass &> /dev/null; then
    echo -e "${YELLOW}Installing sshpass for password authentication...${NC}"
    if [[ "$OSTYPE" == "darwin"* ]]; then
        brew install hudochenkov/sshpass/sshpass 2>/dev/null || {
            echo -e "${YELLOW}Please install sshpass manually:${NC}"
            echo "  brew install hudochenkov/sshpass/sshpass"
            echo ""
            echo "Or use SSH keys instead of password"
            exit 1
        }
    else
        sudo apt-get install -y sshpass 2>/dev/null || sudo yum install -y sshpass 2>/dev/null || {
            echo "Please install sshpass: sudo apt-get install sshpass"
            exit 1
        }
    fi
fi

# Function to run command on remote with password
run_remote() {
    sshpass -p "$REMOTE_PASSWORD" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $REMOTE_USER@$REMOTE_HOST "$@"
}

# Test connection
echo -e "${YELLOW}Testing SSH connection...${NC}"
if run_remote "echo 'Connection successful'" &> /dev/null; then
    echo -e "${GREEN}✓ SSH connection successful${NC}\n"
else
    echo -e "${YELLOW}SSH connection failed. Trying with interactive password...${NC}"
    echo "Please enter password when prompted:"
    ssh -o StrictHostKeyChecking=no $REMOTE_USER@$REMOTE_HOST "echo 'Connection successful'"
fi

# Check Vault CLI on server
echo -e "${YELLOW}Checking Vault CLI on server...${NC}"
if run_remote "command -v vault" &> /dev/null; then
    VAULT_VERSION=$(run_remote "vault version" | head -1)
    echo -e "${GREEN}✓ Vault CLI found: $VAULT_VERSION${NC}\n"
else
    echo -e "${YELLOW}Vault CLI not found. Installing...${NC}"
    run_remote "curl -fsSL https://apt.releases.hashicorp.com/gpg | sudo apt-key add - && sudo apt-add-repository 'deb https://apt.releases.hashicorp.com \$(lsb_release -cs) main' && sudo apt-get update && sudo apt-get install -y vault" || {
        echo -e "${YELLOW}Automatic installation failed. Please install Vault CLI manually on the server.${NC}"
    }
fi

# Set Vault environment
export_cmd="export VAULT_ADDR=$VAULT_ADDR && export VAULT_TOKEN=$VAULT_TOKEN"

# Test Vault connection
echo -e "${YELLOW}Testing Vault connection...${NC}"
if run_remote "$export_cmd && vault status" &> /dev/null; then
    echo -e "${GREEN}✓ Vault connection successful${NC}\n"
    run_remote "$export_cmd && vault status" | head -8
    echo ""
else
    echo -e "${YELLOW}⚠ Cannot connect to Vault. Check VAULT_ADDR and VAULT_TOKEN${NC}\n"
fi

# Check plugin
echo -e "${YELLOW}Checking plugin status...${NC}"
if run_remote "$export_cmd && vault secrets list" | grep -q "pqc/"; then
    echo -e "${GREEN}✓ Plugin is enabled${NC}\n"
    run_remote "$export_cmd && vault list pqc/keys" 2>/dev/null || echo "  (no keys yet)"
else
    echo -e "${YELLOW}⚠ Plugin is not enabled${NC}\n"
fi

echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}Connection established!${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"

echo -e "${YELLOW}You can now run Vault commands:${NC}"
echo "  ./scripts/remote-vault-command.sh 'vault status'"
echo "  ./scripts/remote-vault-command.sh 'vault list pqc/keys'"
echo ""
echo -e "${YELLOW}Or use interactive menu:${NC}"
echo "  make connect-remote-ssh"
echo ""

