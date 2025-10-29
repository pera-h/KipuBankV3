// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../../interfaces/chainlink/AggregatorV3Interface.sol";

/// @title MockChainlinkAggregator
/// @notice Mock Chainlink price feed for testing
contract MockChainlinkAggregator is AggregatorV3Interface {
    uint8 private _decimals;
    int256 private _answer;
    string private _description;
    uint256 private _version = 1;

    constructor(
        uint8 decimals_,
        int256 initialAnswer,
        string memory description_
    ) {
        _decimals = decimals_;
        _answer = initialAnswer;
        _description = description_;
    }

    function decimals() external view override returns (uint8) {
        return _decimals;
    }

    function description() external view override returns (string memory) {
        return _description;
    }

    function version() external view override returns (uint256) {
        return _version;
    }

    function getRoundData(
        uint80 _roundId
    )
        external
        view
        override
        returns (
            uint80 roundId,
            int256 answer,
            uint256 startedAt,
            uint256 updatedAt,
            uint80 answeredInRound
        )
    {
        return (_roundId, _answer, block.timestamp, block.timestamp, _roundId);
    }

    function latestRoundData()
        external
        view
        override
        returns (
            uint80 roundId,
            int256 answer,
            uint256 startedAt,
            uint256 updatedAt,
            uint80 answeredInRound
        )
    {
        return (1, _answer, block.timestamp, block.timestamp, 1);
    }

    /// @notice Update the price
    /// @param newAnswer New price to return
    function updateAnswer(int256 newAnswer) external {
        _answer = newAnswer;
    }
}
