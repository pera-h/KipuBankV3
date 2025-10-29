// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Currency is a user-defined value type that wraps an address
/// @dev This allows for type-safe handling of token addresses
type Currency is address;

/// @notice Interface for hooks in Uniswap V4
/// @dev Hooks can be address(0) for no hooks
interface IHooks {
    // Empty interface for hooks (can be address(0))
}

/// @notice Structure defining a pool's key
/// @dev Used to identify and configure liquidity pools
struct PoolKey {
    /// @notice The first currency of the pool
    Currency currency0;
    /// @notice The second currency of the pool
    Currency currency1;
    /// @notice The fee tier of the pool (e.g., 3000 = 0.3%)
    uint24 fee;
    /// @notice The tick spacing of the pool
    int24 tickSpacing;
    /// @notice The hooks contract for the pool (can be address(0))
    IHooks hooks;
}

/// @title IPoolManager
/// @notice Interface for Uniswap V4 PoolManager
interface IPoolManager {
    // Add relevant functions if needed for direct pool interaction
}

