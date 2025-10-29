// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/// @title IWETH
/// @notice Interface for Wrapped Ether (WETH)
interface IWETH is IERC20 {
    /// @notice Deposit ETH to get WETH
    function deposit() external payable;

    /// @notice Withdraw WETH to get ETH
    /// @param amount The amount of WETH to withdraw
    function withdraw(uint256 amount) external;
}
