// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../../src/interfaces/weth/IWETH.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/// @title MockWETH
/// @notice Mock Wrapped Ether for testing
contract MockWETH is IWETH, ERC20 {
    constructor() ERC20("Wrapped Ether", "WETH") {}

    /// @notice Deposit ETH to get WETH
    function deposit() external payable override {
        _mint(msg.sender, msg.value);
    }

    /// @notice Withdraw WETH to get ETH
    /// @param amount The amount of WETH to withdraw
    function withdraw(uint256 amount) external override {
        require(balanceOf(msg.sender) >= amount, "Insufficient WETH balance");
        _burn(msg.sender, amount);
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "ETH transfer failed");
    }

    /// @notice Allow contract to receive ETH
    receive() external payable {}
}
