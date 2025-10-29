#!/bin/bash

# Deploy KipuBankV3 to Sepolia Testnet
# Usage: ./scripts/deploy-sepolia.sh

set -e

echo "╔═══════════════════════════════════════════════════════════╗"
echo "║           KipuBankV3 - Sepolia Deployment                ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check if .env exists
if [ ! -f .env ]; then
    echo -e "${RED}❌ Error: .env file not found!${NC}"
    echo ""
    echo -e "${YELLOW}Please create .env file:${NC}"
    echo "1. cp env.example .env"
    echo "2. Edit .env with your credentials"
    echo ""
    exit 1
fi

# Source environment variables
source .env

# Check required variables
if [ -z "$PRIVATE_KEY" ]; then
    echo -e "${RED}❌ Error: PRIVATE_KEY not set in .env${NC}"
    exit 1
fi

if [ -z "$SEPOLIA_RPC_URL" ]; then
    echo -e "${RED}❌ Error: SEPOLIA_RPC_URL not set in .env${NC}"
    exit 1
fi

echo -e "${BLUE}🔍 Pre-flight checks...${NC}"
echo ""

# Get deployer address
DEPLOYER=$(cast wallet address --private-key $PRIVATE_KEY)
echo -e "${GREEN}✓${NC} Deployer: $DEPLOYER"

# Check balance
BALANCE=$(cast balance $DEPLOYER --rpc-url $SEPOLIA_RPC_URL)
BALANCE_ETH=$(cast to-unit $BALANCE ether)
echo -e "${GREEN}✓${NC} Balance: $BALANCE_ETH ETH"

# Check if enough balance
if (( $(echo "$BALANCE_ETH < 0.01" | bc -l) )); then
    echo -e "${YELLOW}⚠️  Warning: Low balance. You might need more Sepolia ETH${NC}"
    echo -e "   Get from faucet: https://sepoliafaucet.com/"
fi

echo ""
echo -e "${YELLOW}📋 Deployment Configuration:${NC}"
echo "   Network: Sepolia Testnet"
echo "   Chain ID: 11155111"
echo "   Bank Cap: 1,000,000 USD"
echo "   Withdrawal Limit: 10,000 USD"
echo ""

# Ask for confirmation
read -p "Ready to deploy? (y/n) " -n 1 -r
echo ""
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${YELLOW}Deployment cancelled.${NC}"
    exit 0
fi

echo ""
echo -e "${BLUE}🚀 Starting deployment...${NC}"
echo ""

# Deploy
if [ -z "$ETHERSCAN_API_KEY" ]; then
    # Deploy without verification
    echo -e "${YELLOW}⚠️  No Etherscan API key found. Deploying without verification.${NC}"
    forge script script/Deploy.s.sol \
        --rpc-url $SEPOLIA_RPC_URL \
        --broadcast \
        --legacy
else
    # Deploy with verification
    echo -e "${GREEN}✓${NC} Etherscan API key found. Deploying with verification..."
    forge script script/Deploy.s.sol \
        --rpc-url $SEPOLIA_RPC_URL \
        --broadcast \
        --verify \
        --etherscan-api-key $ETHERSCAN_API_KEY \
        --legacy
fi

echo ""
echo -e "${GREEN}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║              ✅ DEPLOYMENT COMPLETE!                      ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════════════════╝${NC}"
echo ""

# Read deployment info
if [ -f deployments/sepolia.json ]; then
    CONTRACT_ADDRESS=$(cat deployments/sepolia.json | grep "kipuBankV3" | cut -d'"' -f4)
    echo -e "${GREEN}Contract Address:${NC} $CONTRACT_ADDRESS"
    echo ""
    echo -e "${BLUE}📝 Next Steps:${NC}"
    echo "1. View on Etherscan: https://sepolia.etherscan.io/address/$CONTRACT_ADDRESS"
    echo "2. Update frontend: packages/nextjs/contracts/deployedContracts.ts"
    echo "3. Add price feeds for tokens"
    echo "4. Configure Uniswap pools"
    echo ""
    echo -e "${YELLOW}💡 Quick update frontend command:${NC}"
    echo "   sed -i 's/0x0000000000000000000000000000000000000000/$CONTRACT_ADDRESS/' ../KipuBankV3-frontend/packages/nextjs/contracts/deployedContracts.ts"
    echo ""
fi

echo -e "${GREEN}🎉 Done!${NC}"

