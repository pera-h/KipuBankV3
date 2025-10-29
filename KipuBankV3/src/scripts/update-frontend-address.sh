#!/bin/bash

# Update frontend with deployed contract address
# Usage: ./scripts/update-frontend-address.sh <CONTRACT_ADDRESS>

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

if [ -z "$1" ]; then
    echo -e "${RED}❌ Error: Contract address required${NC}"
    echo ""
    echo "Usage: ./scripts/update-frontend-address.sh <CONTRACT_ADDRESS>"
    echo ""
    echo "Example:"
    echo "  ./scripts/update-frontend-address.sh 0x1234567890abcdef..."
    echo ""
    
    # Try to read from deployments
    if [ -f deployments/sepolia.json ]; then
        CONTRACT=$(cat deployments/sepolia.json | grep "kipuBankV3" | cut -d'"' -f4)
        echo -e "${YELLOW}💡 Found deployment:${NC} $CONTRACT"
        echo ""
        read -p "Use this address? (y/n) " -n 1 -r
        echo ""
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            CONTRACT_ADDRESS=$CONTRACT
        else
            exit 1
        fi
    else
        exit 1
    fi
else
    CONTRACT_ADDRESS=$1
fi

echo "╔═══════════════════════════════════════════════════════════╗"
echo "║         Update Frontend Contract Address                  ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

# Validate address format
if [[ ! $CONTRACT_ADDRESS =~ ^0x[a-fA-F0-9]{40}$ ]]; then
    echo -e "${RED}❌ Error: Invalid Ethereum address format${NC}"
    exit 1
fi

FRONTEND_FILE="../KipuBankV3-frontend/packages/nextjs/contracts/deployedContracts.ts"

# Check if frontend file exists
if [ ! -f "$FRONTEND_FILE" ]; then
    echo -e "${RED}❌ Error: Frontend file not found at $FRONTEND_FILE${NC}"
    exit 1
fi

echo -e "${YELLOW}📝 Updating:${NC} $FRONTEND_FILE"
echo -e "${YELLOW}🔗 Address:${NC} $CONTRACT_ADDRESS"
echo ""

# Backup original file
cp "$FRONTEND_FILE" "${FRONTEND_FILE}.backup"
echo -e "${GREEN}✓${NC} Backup created: ${FRONTEND_FILE}.backup"

# Update address
sed -i "s/address: \"0x[0-9a-fA-F]*\"/address: \"$CONTRACT_ADDRESS\"/" "$FRONTEND_FILE"

echo -e "${GREEN}✓${NC} Address updated in deployedContracts.ts"
echo ""

# Also update USDC address in bank page
BANK_PAGE="../KipuBankV3-frontend/packages/nextjs/app/bank/page.tsx"

if [ -f "$BANK_PAGE" ]; then
    # Update USDC address to Sepolia USDC
    USDC_SEPOLIA="0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238"
    sed -i "s/const USDC_ADDRESS = \"0x[0-9a-fA-F]*\"/const USDC_ADDRESS = \"$USDC_SEPOLIA\"/" "$BANK_PAGE"
    echo -e "${GREEN}✓${NC} USDC address updated in bank page"
fi

echo ""
echo -e "${GREEN}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║              ✅ FRONTEND UPDATED!                         ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════════════════╝${NC}"
echo ""

echo -e "${YELLOW}📋 Next steps:${NC}"
echo "1. Restart frontend server:"
echo "   cd ../KipuBankV3-frontend"
echo "   yarn dev"
echo ""
echo "2. Open in browser:"
echo "   http://localhost:3000/bank"
echo ""
echo "3. Connect wallet and test!"
echo ""

echo -e "${GREEN}🎉 Done!${NC}"

