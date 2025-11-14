#!/bin/bash

# Execute a single Vault command on remote server
# Usage: ./scripts/remote-vault-command.sh "vault list pqc/keys"

set -e

# Configuration
REMOTE_HOST="${REMOTE_HOST:-104.237.11.39}"
REMOTE_USER="${REMOTE_USER:-root}"
REMOTE_PASSWORD="${REMOTE_PASSWORD:-MaidlyAbregeRubricNeakes}"
VAULT_ADDR="${VAULT_ADDR:-https://kms.averox.com}"
VAULT_TOKEN="${VAULT_TOKEN:-hvs.Si4gMDMP1a6MwYqpIGiGJCic}"

# Get command from arguments
if [ $# -eq 0 ]; then
    echo "Usage: $0 'vault command'"
    echo "Example: $0 'vault status'"
    echo "Example: $0 'vault list pqc/keys'"
    exit 1
fi

VAULT_CMD="$@"

# Set environment and run command
export_cmd="export VAULT_ADDR=$VAULT_ADDR && export VAULT_TOKEN=$VAULT_TOKEN && $VAULT_CMD"

# Execute on remote server (try with password if sshpass available, otherwise use SSH keys)
if command -v sshpass &> /dev/null && [ -n "$REMOTE_PASSWORD" ]; then
    sshpass -p "$REMOTE_PASSWORD" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $REMOTE_USER@$REMOTE_HOST "$export_cmd"
else
    ssh -o StrictHostKeyChecking=no $REMOTE_USER@$REMOTE_HOST "$export_cmd"
fi

