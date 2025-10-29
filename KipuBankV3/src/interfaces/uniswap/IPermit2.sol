// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IPermit2
/// @notice Interface for Permit2 contract for token approvals
interface IPermit2 {
    /// @notice Approves a spender to transfer tokens
    /// @param token The token to approve
    /// @param spender The address to approve
    /// @param amount The amount to approve
    /// @param expiration The expiration time of the approval
    function approve(
        address token,
        address spender,
        uint160 amount,
        uint48 expiration
    ) external;
    
    /// @notice Transfers tokens from one address to another
    /// @param from The address to transfer from
    /// @param to The address to transfer to
    /// @param amount The amount to transfer
    /// @param token The token to transfer
    function transferFrom(
        address from,
        address to,
        uint160 amount,
        address token
    ) external;
}

