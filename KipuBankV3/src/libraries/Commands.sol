// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title Commands
/// @notice Library containing command constants for Uniswap UniversalRouter
library Commands {
    // Uniswap V4 command constants
    uint256 constant V4_SWAP = 0x00;
    uint256 constant WRAP_ETH = 0x0a;
    uint256 constant UNWRAP_WETH = 0x0b;
    uint256 constant PERMIT2_TRANSFER_FROM = 0x0c;
    
    // Add more commands as needed from UniversalRouter documentation
}

