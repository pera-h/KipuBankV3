#!/bin/bash

# Script to update frontend ABI after contract changes
# Usage: ./scripts/update-frontend-abi.sh

set -e

echo "🔧 Updating Frontend ABI..."

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Paths
CONTRACT_DIR="/home/pero/Repos/KipuBankV3"
FRONTEND_DIR="/home/pero/Repos/KipuBankV3-frontend"
ABI_OUTPUT="$FRONTEND_DIR/packages/nextjs/contracts/KipuBankV3_abi.ts"

# Step 1: Build contracts
echo -e "${BLUE}Step 1:${NC} Building contracts..."
cd "$CONTRACT_DIR"
forge build

# Step 2: Extract ABI and convert to TypeScript
echo -e "${BLUE}Step 2:${NC} Extracting ABI..."
python3 -c "
import json
data = json.load(open('out/KipuBankV3.sol/KipuBankV3.json'))
with open('$ABI_OUTPUT', 'w') as f:
    f.write('export const KipuBankV3ABI = ')
    json.dump(data['abi'], f, indent=2)
    f.write(' as const;\n')
"

echo -e "${GREEN}✅ ABI updated successfully!${NC}"
echo -e "📁 Location: $ABI_OUTPUT"
echo ""
echo -e "${BLUE}Next steps:${NC}"
echo "1. Restart your frontend server if running"
echo "2. Hard refresh your browser (Ctrl+Shift+R)"
echo ""
echo "Done! 🎉"

