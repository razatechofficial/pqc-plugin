#!/bin/bash

# Script to build the plugin using Docker

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}Building Post-Quantum Cryptography Vault Plugin with Docker${NC}\n"

# Build the plugin
echo -e "${YELLOW}Building plugin binary...${NC}"
docker build -f Dockerfile.production -t pqc-plugin:latest .

# Create output directory
mkdir -p build-output

# Extract the binary
echo -e "${YELLOW}Extracting plugin binary...${NC}"
docker create --name pqc-plugin-temp pqc-plugin:latest
docker cp pqc-plugin-temp:/vault-plugin-pqc ./build-output/vault-plugin-pqc
docker rm pqc-plugin-temp

# Make it executable
chmod +x ./build-output/vault-plugin-pqc

echo -e "${GREEN}✓ Plugin built successfully!${NC}"
echo -e "${GREEN}Binary location: ./build-output/vault-plugin-pqc${NC}\n"

# Show file info
echo -e "${BLUE}File information:${NC}"
ls -lh ./build-output/vault-plugin-pqc
file ./build-output/vault-plugin-pqc

# Calculate SHA256
echo -e "\n${BLUE}SHA256 checksum:${NC}"
shasum -a 256 ./build-output/vault-plugin-pqc




