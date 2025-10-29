// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../interfaces/uniswap/IPoolManager.sol";

/// @title UniswapV4Helper
/// @notice Helper library for encoding Uniswap V4 commands and data structures
library UniswapV4Helper {
    /// @notice Encodes a V4 swap command for UniversalRouter
    /// @param recipient The address that will receive the output tokens
    /// @param amountIn The exact amount of input tokens to swap
    /// @param amountOutMin The minimum amount of output tokens expected
    /// @param path The encoded swap path
    /// @param payerIsUser Whether the payer is the user (true) or the router (false)
    /// @return Encoded swap data
    function encodeV4Swap(
        address recipient,
        uint256 amountIn,
        uint256 amountOutMin,
        bytes memory path,
        bool payerIsUser
    ) internal pure returns (bytes memory) {
        return abi.encode(
            recipient,
            amountIn,
            amountOutMin,
            path,
            payerIsUser
        );
    }

    /// @notice Builds a PoolKey for Uniswap V4 pool identification
    /// @param tokenA The first token address
    /// @param tokenB The second token address
    /// @param fee The pool fee tier (e.g., 3000 = 0.3%)
    /// @param tickSpacing The tick spacing for the pool
    /// @param hooks The hooks contract address (use address(0) for no hooks)
    /// @return poolKey The constructed PoolKey
    function buildPoolKey(
        address tokenA,
        address tokenB,
        uint24 fee,
        int24 tickSpacing,
        address hooks
    ) internal pure returns (PoolKey memory poolKey) {
        // Ensure token order (token0 < token1)
        (address token0, address token1) = tokenA < tokenB 
            ? (tokenA, tokenB) 
            : (tokenB, tokenA);
        
        poolKey = PoolKey({
            currency0: Currency.wrap(token0),
            currency1: Currency.wrap(token1),
            fee: fee,
            tickSpacing: tickSpacing,
            hooks: IHooks(hooks)
        });
    }

    /// @notice Encodes a swap path for a single-hop swap
    /// @param tokenIn The input token address
    /// @param tokenOut The output token address
    /// @param fee The pool fee
    /// @return Encoded path
    function encodeSingleHopPath(
        address tokenIn,
        address tokenOut,
        uint24 fee
    ) internal pure returns (bytes memory) {
        // For Uniswap V3 style path encoding:
        // tokenIn (20 bytes) | fee (3 bytes) | tokenOut (20 bytes)
        return abi.encodePacked(tokenIn, fee, tokenOut);
    }

    /// @notice Encodes a swap path for a multi-hop swap
    /// @param tokens Array of token addresses in the swap path
    /// @param fees Array of fee tiers for each hop
    /// @return Encoded path
    function encodeMultiHopPath(
        address[] memory tokens,
        uint24[] memory fees
    ) internal pure returns (bytes memory) {
        require(tokens.length >= 2, "Invalid path");
        require(fees.length == tokens.length - 1, "Invalid fees");
        
        bytes memory path = abi.encodePacked(tokens[0]);
        
        for (uint256 i = 0; i < fees.length; i++) {
            path = abi.encodePacked(path, fees[i], tokens[i + 1]);
        }
        
        return path;
    }

    /// @notice Unwraps a Currency type to an address
    /// @param currency The Currency to unwrap
    /// @return The underlying token address
    function currencyToAddress(Currency currency) internal pure returns (address) {
        return Currency.unwrap(currency);
    }

    /// @notice Wraps an address into a Currency type
    /// @param token The token address to wrap
    /// @return The wrapped Currency
    function addressToCurrency(address token) internal pure returns (Currency) {
        return Currency.wrap(token);
    }
}

