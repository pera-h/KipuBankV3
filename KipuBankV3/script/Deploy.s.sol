// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import "../src/KipuBankV3.sol";

/**
 * @title Deploy Script for KipuBankV3
 * @notice Deploys KipuBankV3 to Sepolia testnet
 * @dev Run with: forge script script/Deploy.s.sol --rpc-url sepolia --broadcast --verify
 */
contract DeployScript is Script {
    // Sepolia addresses - Uniswap V4 Official
    // https://docs.uniswap.org/contracts/v4/deployments#sepolia-11155111
    address constant UNISWAP_V4_UNIVERSAL_ROUTER =
        0x3f0Ca1a08e12E2B19F25D2b4f4FAa18cC7f3D52d; // ✅ Official Uniswap V4
    address constant PERMIT2 = 0x000000000022D473030F116dDEE9F6B43aC78BA3;
    address constant USDC_SEPOLIA = 0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238; // USDC on Sepolia
    address constant POOL_MANAGER = 0x8C4BcBE6b9eF47855f97E675296FA3F6fafa5F1A; // ✅ Official PoolManager

    // Initial configuration
    uint256 constant INITIAL_BANK_CAP = 1_000_000 * 1e8; // 1M USD (8 decimals)
    uint256 constant INITIAL_WITHDRAWAL_LIMIT = 10_000 * 1e8; // 10k USD (8 decimals)

    function run() external {
        // Get deployer private key from environment
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);

        console.log("===========================================");
        console.log("KIPUBANK V3 DEPLOYMENT");
        console.log("===========================================");
        console.log("Deployer:", deployer);
        console.log("Network: Sepolia Testnet");
        console.log("Bank Cap:", INITIAL_BANK_CAP / 1e8, "USD");
        console.log("Withdrawal Limit:", INITIAL_WITHDRAWAL_LIMIT / 1e8, "USD");
        console.log("===========================================");

        // Start broadcasting transactions
        vm.startBroadcast(deployerPrivateKey);

        // Deploy KipuBankV3
        KipuBankV3 bank = new KipuBankV3(
            INITIAL_BANK_CAP,
            INITIAL_WITHDRAWAL_LIMIT,
            UNISWAP_V4_UNIVERSAL_ROUTER,
            PERMIT2,
            USDC_SEPOLIA,
            POOL_MANAGER
        );

        console.log("===========================================");
        console.log("DEPLOYMENT SUCCESSFUL!");
        console.log("===========================================");
        console.log("KipuBankV3 Address:", address(bank));
        console.log("===========================================");
        console.log("");
        console.log("Next steps:");
        console.log("1. Verify contract on Etherscan");
        console.log("2. Update frontend deployedContracts.ts");
        console.log("3. Add price feeds for tokens");
        console.log("4. Configure Uniswap pools");
        console.log("===========================================");

        // Note: Deployment info will be saved manually after deploy
        // vm.writeFile requires fs_permissions in foundry.toml

        vm.stopBroadcast();
    }
}
