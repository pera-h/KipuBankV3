Contract Address: 0x76dB0c189AC1771baf49baF2A5578BF9952e8bB7
Sepolia etherscan link: https://sepolia.etherscan.io/address/0x76db0c189ac1771baf49baf2a5578bf9952e8bb7#code
# KipuBankV3

A decentralized banking protocol built on Ethereum that accepts deposits in any Uniswap V4-supported token and automatically converts them to USDC for standardized accounting.

## Overview

KipuBankV3 extends traditional DeFi banking concepts by integrating Uniswap V4's UniversalRouter to enable frictionless deposits from any supported token. The protocol maintains internal accounting in USDC while providing flexibility for users to deposit native ETH, ERC20 tokens, or any arbitrary token available on Uniswap V4 liquidity pools.

### Core Improvements

**Uniswap V4 Integration**

The primary enhancement in V3 is the integration with Uniswap's latest protocol version. This allows the bank to accept deposits in tokens that may not have a configured price feed by automatically swapping them to USDC through the UniversalRouter. The swap process is handled on-chain during the deposit transaction, removing the need for users to manually convert tokens before depositing.

**Unified Accounting Model**

All deposits are ultimately credited in USDC regardless of the input token. This standardization simplifies risk management, reporting, and withdrawal limits. Users can deposit ETH, pre-approved ERC20 tokens, or arbitrary tokens, but their balance is maintained in a single denomination.

**Role-Based Administration**

Access control is implemented using OpenZeppelin's AccessControl pattern with three specialized roles:

- `OPERATIONS_MANAGER_ROLE`: Adjusts bank capacity and withdrawal limits
- `ASSET_MANAGER_ROLE`: Configures supported tokens, price feeds, and liquidity pool parameters
- `FUNDS_RECOVERY_ROLE`: Handles manual balance adjustments for error recovery

This separation allows granular permission delegation while maintaining security.

**Chainlink Oracle Integration**

Token valuations use Chainlink price feeds to calculate USD values for deposit caps and withdrawal limits. Prices are normalized to 8 decimals for consistent calculations across tokens with varying decimal configurations.

## Architecture

### Deposit Flow

1. **Standard Token Deposit**: For tokens with configured price feeds (e.g., ETH, DAI), deposits follow the traditional path where the token is transferred to the contract, valued using its price feed, and credited to the user's balance.

2. **Arbitrary Token Deposit**: For tokens without price feeds, the `depositArbitraryToken` function handles:
   - Transfer of the input token to the contract
   - Approval for UniversalRouter spending
   - Execution of V4_SWAP command through UniversalRouter
   - Slippage protection via `minUsdcOut` parameter
   - USDC crediting to user's balance

3. **Native ETH Deposit**: ETH deposits to the arbitrary token function are first wrapped to WETH, then swapped to USDC via the same mechanism.

### Swap Mechanism

Token swaps use Uniswap V4's PoolKey structure which defines:
- Currency pair (sorted token addresses)
- Fee tier (e.g., 3000 = 0.3%)
- Tick spacing
- Hooks contract (if any)

Pool configurations are stored per token and managed by the `ASSET_MANAGER_ROLE`. The swap path is encoded using V3-compatible path encoding (token0 | fee | token1) which V4's UniversalRouter interprets correctly.

### Risk Controls

**Bank Capacity Limit**: Total value of all deposits is capped at a configurable USD threshold. This prevents unlimited exposure and allows gradual scaling.

**Withdrawal Limits**: Individual withdrawals are restricted to a maximum USD value per transaction. This mitigates rapid capital flight scenarios.

**Reentrancy Protection**: All external calls use OpenZeppelin's ReentrancyGuard to prevent reentrancy attacks.

**Price Feed Validation**: Price feeds must return positive values and are normalized to 8 decimals. Invalid feeds revert transactions.

## Deployment

### Requirements

- Foundry toolkit (forge, cast, anvil)
- Node.js >= v20.18.3 and Yarn for frontend
- Access to Ethereum RPC endpoint (Alchemy, Infura, or self-hosted node)
- Private key with sufficient ETH for gas

### Environment Configuration

Create a `.env` file in the `KipuBankV3` directory:

```
PRIVATE_KEY=0x...
SEPOLIA_RPC_URL=https://eth-sepolia.g.alchemy.com/v2/YOUR_KEY
ETHERSCAN_API_KEY=YOUR_ETHERSCAN_KEY
```

### Contract Deployment

Deploy to Sepolia testnet:

```bash
cd KipuBankV3
forge script script/Deploy.s.sol --rpc-url sepolia --broadcast --verify
```

The deployment script initializes the contract with:
- Bank cap: 1,000,000 USD
- Withdrawal limit: 10,000 USD
- Uniswap V4 UniversalRouter: 0x3f0Ca1a08e12E2B19F25D2b4f4FAa18cC7f3D52d
- PoolManager: 0x8C4BcBE6b9eF47855f97E675296FA3F6fafa5F1A
- USDC (Sepolia): 0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238

### Post-Deployment Configuration

1. **Add Token Price Feeds**

For tokens requiring legacy deposit support (direct deposit without swap):

```bash
cast send $CONTRACT_ADDRESS "addToken(address,address)" \
  $TOKEN_ADDRESS $CHAINLINK_FEED_ADDRESS \
  --private-key $PRIVATE_KEY --rpc-url sepolia
```

2. **Configure Liquidity Pools**

For arbitrary token deposits, configure the token-to-USDC pool:

```bash
# Example: Configure WETH -> USDC pool
cast send $CONTRACT_ADDRESS "addTokenPool(address,(address,address,uint24,int24,address))" \
  $WETH_ADDRESS \
  "($WETH_ADDRESS,$USDC_ADDRESS,3000,60,0x0000000000000000000000000000000000000000)" \
  --private-key $PRIVATE_KEY --rpc-url sepolia
```

The tuple structure represents:
- currency0: First token (sorted)
- currency1: Second token (sorted)
- fee: Fee tier in hundredths of a bip (3000 = 0.3%)
- tickSpacing: Tick spacing for the pool
- hooks: Hooks contract address (0x0 for no hooks)

3. **Frontend Integration**

Update the deployed contract address in the frontend:

```bash
cd ../KipuBankV3-frontend/packages/nextjs
# Edit contracts/deployedContracts.ts with new contract address
```

Run the frontend:

```bash
yarn install
yarn start
```

Access at `http://localhost:3000`

## Interaction Guide

### Depositing Standard Tokens

Call `deposit(address token, uint256 amount)` for tokens with configured price feeds:

```solidity
// Approve first for ERC20
IERC20(tokenAddress).approve(bankAddress, amount);
bank.deposit(tokenAddress, amount);

// For ETH, send value with transaction
bank.deposit(ETH_ADDRESS, amount){value: amount}
```

### Depositing Arbitrary Tokens

Call `depositArbitraryToken(address token, uint256 amount, uint256 minUsdcOut)`:

```solidity
// Approve the bank to spend tokens
IERC20(arbitraryToken).approve(bankAddress, amount);

// Calculate minimum output considering slippage
uint256 minUsdcOut = expectedUsdcAmount * 95 / 100; // 5% slippage tolerance

bank.depositArbitraryToken(arbitraryToken, amount, minUsdcOut);
```

The `minUsdcOut` parameter protects against excessive slippage during the swap.

### Withdrawing Funds

Withdrawals are processed in the originally deposited token:

```solidity
bank.withdraw(tokenAddress, amount);
```

For arbitrary token deposits (which are converted to USDC), withdraw USDC:

```solidity
bank.withdraw(USDC_ADDRESS, amount);
```

### Administrative Functions

**Update Bank Limits** (OPERATIONS_MANAGER_ROLE):

```solidity
bank.setBankCapInUsd(2000000e8); // 2M USD
bank.setWithdrawalLimitInUsd(20000e8); // 20K USD
```

**Add New Token** (ASSET_MANAGER_ROLE):

```solidity
bank.addToken(tokenAddress, priceFeedAddress);
```

**Recover Balances** (FUNDS_RECOVERY_ROLE):

```solidity
bank.recoverBalance(tokenAddress, userAddress, correctedBalance);
```

## Design Decisions and Trade-offs

### Automatic Conversion to USDC

**Decision**: All arbitrary token deposits are converted to USDC immediately upon deposit.

**Rationale**: This eliminates exposure to volatile token prices and simplifies internal accounting. Users always know their balance in a stable asset.

**Trade-off**: Users cannot maintain balances in their original deposited tokens if using the arbitrary deposit function. They must use standard deposits if they want to preserve the token type. Additionally, swap fees and slippage are incurred during conversion.

### Dual Deposit Paths

**Decision**: Maintain two separate deposit functions - `deposit()` for known tokens and `depositArbitraryToken()` for others.

**Rationale**: Standard deposits are more gas-efficient for commonly used tokens that already have price feeds configured. The swap mechanism is only invoked when needed.

**Trade-off**: Increased contract complexity and potential user confusion about which function to use. The benefit is flexibility without forcing all deposits through the swap mechanism.

### On-Chain Price Feeds

**Decision**: Use Chainlink oracles for standard token pricing rather than Uniswap TWAP or other mechanisms.

**Rationale**: Chainlink feeds are manipulation-resistant, widely trusted, and provide consistent pricing across DeFi protocols.

**Trade-off**: Dependency on external oracle network. If a feed fails or becomes stale, deposits/withdrawals for that token will revert. The protocol requires manual configuration of feeds for each new token.

### Role-Based Permissions

**Decision**: Implement granular roles rather than a single admin.

**Rationale**: Allows operational separation where different parties can manage different aspects. For example, a treasury team can manage limits while a technical team manages token configurations.

**Trade-off**: More complex access control setup during deployment. Requires careful key management for multiple roles.

### Pool Configuration Storage

**Decision**: Store PoolKey structures on-chain per token rather than calculating them dynamically.

**Rationale**: Pool parameters (fees, tick spacing, hooks) may vary per token pair and cannot be reliably determined without external data.

**Trade-off**: Administrative overhead to configure pools for each new token. Incorrect configuration can cause transaction failures.

### UniversalRouter Integration

**Decision**: Use Uniswap's UniversalRouter rather than direct PoolManager interaction.

**Rationale**: UniversalRouter provides a stable interface that abstracts V4 complexity and handles multi-step operations (approvals, swaps, settlements).

**Trade-off**: Additional gas overhead from router abstraction. Direct PoolManager interaction would be more gas-efficient but significantly more complex to implement correctly.

### Slippage Protection

**Decision**: Require users to specify minimum output amounts rather than automatic slippage calculation.

**Rationale**: Slippage tolerance varies by use case. Automated calculation would need oracle data and could be gamed.

**Trade-off**: Users must calculate appropriate slippage parameters externally. Incorrect values cause transaction reverts.

### Native ETH Handling

**Decision**: Support native ETH through the special address `0xEeee...EeeE` and automatic WETH wrapping.

**Rationale**: Improves UX by allowing users to deposit ETH directly without manual wrapping.

**Trade-off**: Additional gas cost for WETH wrapping step and increased code complexity to handle the special case.

## Testing

Run the full test suite:

```bash
cd KipuBankV3
forge test
```

Run with verbosity for detailed output:

```bash
forge test -vvv
```

Run specific test files:

```bash
forge test --match-path src/test/unit/KipuBankV3.t.sol
```

Test coverage report:

```bash
forge coverage
```

## Security Considerations

- All external token transfers use SafeERC20 to handle non-standard implementations
- Reentrancy guards protect all state-changing external calls
- Integer overflow protection through Solidity 0.8.x built-in checks
- Price feed validation ensures positive, non-zero prices
- Slippage protection prevents sandwich attacks on swaps
- Role-based access control limits administrative functions

The contract has not been formally audited. Use in production at your own risk.

## License

MIT

