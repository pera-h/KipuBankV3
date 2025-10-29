// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/// @title MockUniversalRouter
/// @notice Mock UniversalRouter for testing swaps
contract MockUniversalRouter {
    // Exchange rate: 1 input token = this many output tokens (scaled by 1e18)
    uint256 public exchangeRate = 1e18; // Default 1:1
    bool public shouldFail = false;

    /// @notice Set exchange rate for swaps
    /// @param rate The exchange rate (scaled by 1e18)
    function setExchangeRate(uint256 rate) external {
        exchangeRate = rate;
    }

    /// @notice Set whether swaps should fail
    /// @param fail True to make swaps fail
    function setShouldFail(bool fail) external {
        shouldFail = fail;
    }

    /// @notice Mock execute function that simulates token swaps
    /// @param commands Encoded commands (we'll ignore for mock)
    /// @param inputs Array of encoded inputs
    /// @param deadline Deadline for execution
    function execute(
        bytes calldata commands,
        bytes[] calldata inputs,
        uint256 deadline
    ) external payable {
        require(!shouldFail, "Mock: Swap failed");
        require(block.timestamp <= deadline, "Mock: Deadline passed");

        // Decode the first input to get swap parameters
        // Format: (recipient, amountIn, amountOutMin, path, payerIsUser)
        if (inputs.length > 0) {
            (
                address recipient,
                uint256 amountIn,
                uint256 amountOutMin,
                bytes memory path,

            ) = abi.decode(inputs[0], (address, uint256, uint256, bytes, bool));

            // Decode path to get tokenIn and tokenOut
            // Path format: tokenIn (20 bytes) | fee (3 bytes) | tokenOut (20 bytes)
            require(path.length >= 43, "Mock: Invalid path");

            address tokenIn;
            address tokenOut;

            assembly {
                tokenIn := mload(add(path, 20))
                tokenOut := mload(add(path, 43))
            }

            // Calculate output amount based on exchange rate
            uint256 amountOut = (amountIn * exchangeRate) / 1e18;

            require(amountOut >= amountOutMin, "Mock: Insufficient output");

            // Transfer tokens from caller (the contract that called execute)
            IERC20(tokenIn).transferFrom(msg.sender, address(this), amountIn);

            // Transfer output tokens to recipient
            IERC20(tokenOut).transfer(recipient, amountOut);
        }

        // Suppress unused variable warnings
        commands;
    }

    /// @notice Fund the router with tokens for testing
    /// @param token Token address
    /// @param amount Amount to fund
    function fundRouter(address token, uint256 amount) external {
        IERC20(token).transferFrom(msg.sender, address(this), amount);
    }
}

