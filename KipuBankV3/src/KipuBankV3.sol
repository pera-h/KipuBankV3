// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "./interfaces/chainlink/AggregatorV3Interface.sol";
import "./interfaces/uniswap/IUniversalRouter.sol";
import "./interfaces/uniswap/IPermit2.sol";
import "./interfaces/uniswap/IPoolManager.sol";
import "./interfaces/weth/IWETH.sol";
import "./libraries/Commands.sol";
import "./libraries/UniswapV4Helper.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";

/// @title KipuBankV3
/// @author pera-h
/// @notice DeFi bank that accepts any Uniswap V4-supported token and converts to USDC
contract KipuBankV3 is AccessControl, ReentrancyGuard {
    using SafeERC20 for IERC20;
    /// @notice roles for access control
    bytes32 public constant OPERATIONS_MANAGER_ROLE =
        keccak256("OPERATIONS_MANAGER_ROLE");
    bytes32 public constant ASSET_MANAGER_ROLE =
        keccak256("ASSET_MANAGER_ROLE");
    bytes32 public constant FUNDS_RECOVERY_ROLE =
        keccak256("FUNDS_RECOVERY_ROLE");

    /// @notice statevariables

    /// @notice The maximum total value of all assets the bank can hold, in USD with 8 decimals.
    uint256 public bankCapInUsd;

    /// @notice The maximum value a user can withdraw in a single transaction, in USD with 8 decimals.
    uint256 public withdrawalLimitInUsd;

    /// @notice The current total value of all assets held by the bank, in USD with 8 decimals.
    uint256 public totalBankValueInUsd;

    /// @notice Mapping from token address to user address to the user's balance.
    mapping(address => mapping(address => uint256)) public balances;

    /// @notice Mapping from a supported token address to its Chainlink price feed address.
    mapping(address => address) public tokenPriceFeeds;

    /// @notice A constant to represent native Ether, following the EIP-7528
    address public constant ETH_ADDRESS =
        0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;

    /// @notice Wrapped ETH address on Sepolia testnet
    address public constant WETH = 0x7b79995e5f793A07Bc00c21412e50Ecae098E7f9;

    /// @notice Uniswap V4 Integration - New in V3
    IUniversalRouter public immutable universalRouter;
    IPermit2 public immutable permit2;
    address public immutable USDC;
    address public immutable poolManager;

    /// @notice Mapping from token address to its PoolKey configuration for swapping to USDC
    mapping(address => PoolKey) public tokenToUsdcPools;

    /// @notice Events
    event Deposit(address indexed user, address indexed token, uint256 amount);
    event Withdrawal(
        address indexed user,
        address indexed token,
        uint256 amount
    );
    event TokenAdded(address indexed token, address indexed priceFeed);
    event BankCapUpdated(uint256 newCapInUsd);
    event WithdrawalLimitUpdated(uint256 newLimitInUsd);
    event BalanceRecovered(
        address indexed admin,
        address indexed user,
        address indexed token,
        uint256 newBalance
    );
    event TokenSwapped(
        address indexed user,
        address indexed tokenIn,
        uint256 amountIn,
        uint256 usdcOut
    );
    event PoolKeyAdded(address indexed token, uint24 fee, int24 tickSpacing);

    /// @notice errors
    error TokenNotSupported(address token);
    error InvalidAmount();
    error InsufficientBalance(uint256 balance, uint256 requested);
    error TransferFailed();
    error MsgValueMustBeZeroForErc20();
    error AmountDoesNotMatchMsgValue();
    error WithdrawalAmountExceedsUsdLimit(
        uint256 amountInUsd,
        uint256 limitInUsd
    );
    error BankCapExceeded(
        uint256 currentTotalValue,
        uint256 depositValue,
        uint256 bankCap
    );
    error InvalidPriceFeed(address token);
    error SwapFailed();
    error SlippageExceeded(uint256 amountOut, uint256 minAmountOut);
    error PoolNotConfigured(address token);
    error InvalidRouter();
    error InvalidUSDC();

    /// @notice constructor, grant all important roles to admin
    /// @param _initialBankCapInUsd Maximum total value the bank can hold (8 decimals)
    /// @param _initialWithdrawalLimitInUsd Maximum withdrawal per transaction (8 decimals)
    /// @param _universalRouter Address of Uniswap V4 UniversalRouter
    /// @param _permit2 Address of Permit2 contract
    /// @param _usdc Address of USDC token
    /// @param _poolManager Address of Uniswap V4 PoolManager
    constructor(
        uint256 _initialBankCapInUsd,
        uint256 _initialWithdrawalLimitInUsd,
        address _universalRouter,
        address _permit2,
        address _usdc,
        address _poolManager
    ) {
        if (_universalRouter == address(0)) revert InvalidRouter();
        if (_usdc == address(0)) revert InvalidUSDC();

        bankCapInUsd = _initialBankCapInUsd;
        withdrawalLimitInUsd = _initialWithdrawalLimitInUsd;

        universalRouter = IUniversalRouter(_universalRouter);
        permit2 = IPermit2(_permit2);
        USDC = _usdc;
        poolManager = _poolManager;

        // Grant all roles to the deployer.
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(OPERATIONS_MANAGER_ROLE, msg.sender);
        _grantRole(ASSET_MANAGER_ROLE, msg.sender);
        _grantRole(FUNDS_RECOVERY_ROLE, msg.sender);
    }

    /// @notice Rules-related functions

    /// @notice Updates the total bank value cap.
    function setBankCapInUsd(
        uint256 _newCap
    ) external onlyRole(OPERATIONS_MANAGER_ROLE) {
        bankCapInUsd = _newCap;
        emit BankCapUpdated(_newCap);
    }

    /// @notice Updates the per-transaction withdrawal limit.
    function setWithdrawalLimitInUsd(
        uint256 _newLimit
    ) external onlyRole(OPERATIONS_MANAGER_ROLE) {
        withdrawalLimitInUsd = _newLimit;
        emit WithdrawalLimitUpdated(_newLimit);
    }

    /// @notice Adds a new token to the list of supported assets by providing its price feed.
    function addToken(
        address _tokenAddress,
        address _priceFeedAddress
    ) external onlyRole(ASSET_MANAGER_ROLE) {
        if (_priceFeedAddress == address(0)) revert InvalidAmount();
        tokenPriceFeeds[_tokenAddress] = _priceFeedAddress;
        emit TokenAdded(_tokenAddress, _priceFeedAddress);
    }

    /// @notice Manually adjusts a user's balance for recovery purposes.
    function recoverBalance(
        address _tokenAddress,
        address _user,
        uint256 _newBalance
    ) external onlyRole(FUNDS_RECOVERY_ROLE) {
        uint256 oldBalance = balances[_tokenAddress][_user];

        if (_newBalance > oldBalance) {
            uint256 diff = _newBalance - oldBalance;
            uint256 valueDiffInUsd = _getValueInUsd(_tokenAddress, diff);
            totalBankValueInUsd += valueDiffInUsd;
        } else if (_newBalance < oldBalance) {
            uint256 diff = oldBalance - _newBalance;
            uint256 valueDiffInUsd = _getValueInUsd(_tokenAddress, diff);
            totalBankValueInUsd -= valueDiffInUsd;
        }

        balances[_tokenAddress][_user] = _newBalance;
        emit BalanceRecovered(msg.sender, _user, _tokenAddress, _newBalance);
    }

    /// @notice deposit and withdrawal multi-token

    /// @notice Deposits ETH or a supported ERC20 token into the bank.
    function deposit(
        address _tokenAddress,
        uint256 _amount
    ) external payable nonReentrant {
        if (_amount == 0) revert InvalidAmount();

        if (
            _tokenAddress != ETH_ADDRESS &&
            tokenPriceFeeds[_tokenAddress] == address(0)
        ) {
            revert TokenNotSupported(_tokenAddress);
        }

        // Check if the deposit would exceed the bank's total value cap.
        uint256 depositValueInUsd = _getValueInUsd(_tokenAddress, _amount);
        if (totalBankValueInUsd + depositValueInUsd > bankCapInUsd) {
            revert BankCapExceeded(
                totalBankValueInUsd,
                depositValueInUsd,
                bankCapInUsd
            );
        }

        if (_tokenAddress == ETH_ADDRESS) {
            if (msg.value != _amount) revert AmountDoesNotMatchMsgValue();
        } else {
            if (msg.value > 0) revert MsgValueMustBeZeroForErc20();
            bool success = IERC20(_tokenAddress).transferFrom(
                msg.sender,
                address(this),
                _amount
            );
            if (!success) revert TransferFailed();
        }

        balances[_tokenAddress][msg.sender] += _amount;

        totalBankValueInUsd += depositValueInUsd;

        emit Deposit(msg.sender, _tokenAddress, _amount);
    }

    /// @notice Withdraws ETH or a supported ERC20 token from the bank.
    function withdraw(
        address _tokenAddress,
        uint256 _amount
    ) external nonReentrant {
        if (_amount == 0) revert InvalidAmount();
        uint256 userBalance = balances[_tokenAddress][msg.sender];
        if (userBalance < _amount)
            revert InsufficientBalance(userBalance, _amount);

        uint256 amountInUsd = _getValueInUsd(_tokenAddress, _amount);
        if (amountInUsd > withdrawalLimitInUsd) {
            revert WithdrawalAmountExceedsUsdLimit(
                amountInUsd,
                withdrawalLimitInUsd
            );
        }

        balances[_tokenAddress][msg.sender] -= _amount;

        totalBankValueInUsd -= amountInUsd;

        if (_tokenAddress == ETH_ADDRESS) {
            (bool success, ) = msg.sender.call{value: _amount}("");
            if (!success) revert TransferFailed();
        } else {
            bool success = IERC20(_tokenAddress).transfer(msg.sender, _amount);
            if (!success) revert TransferFailed();
        }

        emit Withdrawal(msg.sender, _tokenAddress, _amount);
    }

    /// @notice New V3 Functions - Token Pool Management

    /// @notice Adds or updates a PoolKey configuration for swapping a token to USDC
    /// @param _tokenAddress The token to configure
    /// @param _poolKey The PoolKey structure defining the pool parameters
    function addTokenPool(
        address _tokenAddress,
        PoolKey calldata _poolKey
    ) external onlyRole(ASSET_MANAGER_ROLE) {
        if (_tokenAddress == address(0)) revert InvalidAmount();
        if (_tokenAddress == USDC) revert InvalidAmount(); // No need to swap USDC to USDC

        tokenToUsdcPools[_tokenAddress] = _poolKey;

        emit PoolKeyAdded(_tokenAddress, _poolKey.fee, _poolKey.tickSpacing);
    }

    /// @notice Deposits any token and converts it to USDC via Uniswap V4
    /// @param _tokenAddress The token to deposit (can be any Uniswap V4 supported token)
    /// @param _amount The amount to deposit
    /// @param _minUsdcOut The minimum USDC expected from swap (slippage protection)
    function depositArbitraryToken(
        address _tokenAddress,
        uint256 _amount,
        uint256 _minUsdcOut
    ) external payable nonReentrant {
        if (_amount == 0) revert InvalidAmount();

        uint256 usdcReceived;

        // Handle different token types
        if (_tokenAddress == USDC) {
            // Direct USDC deposit - no swap needed
            IERC20(USDC).safeTransferFrom(msg.sender, address(this), _amount);
            usdcReceived = _amount;
        } else if (_tokenAddress == ETH_ADDRESS) {
            // Native ETH - wrap to WETH and swap to USDC
            if (msg.value != _amount) revert AmountDoesNotMatchMsgValue();

            // 1. Wrap ETH to WETH
            IWETH(WETH).deposit{value: _amount}();

            // 2. Swap WETH to USDC via Uniswap V4
            usdcReceived = _swapExactInputSingle(WETH, _amount, _minUsdcOut);

            emit TokenSwapped(msg.sender, ETH_ADDRESS, _amount, usdcReceived);
        } else {
            // Arbitrary ERC20 token - transfer from user and swap
            if (msg.value > 0) revert MsgValueMustBeZeroForErc20();

            // Transfer token from user to this contract
            IERC20(_tokenAddress).safeTransferFrom(
                msg.sender,
                address(this),
                _amount
            );

            // Swap to USDC via Uniswap V4
            usdcReceived = _swapExactInputSingle(
                _tokenAddress,
                _amount,
                _minUsdcOut
            );

            emit TokenSwapped(msg.sender, _tokenAddress, _amount, usdcReceived);
        }

        // Check if deposit would exceed bank cap
        uint256 depositValueInUsd = _getValueInUsd(USDC, usdcReceived);
        if (totalBankValueInUsd + depositValueInUsd > bankCapInUsd) {
            revert BankCapExceeded(
                totalBankValueInUsd,
                depositValueInUsd,
                bankCapInUsd
            );
        }

        // Update balances - credit user with USDC
        balances[USDC][msg.sender] += usdcReceived;
        totalBankValueInUsd += depositValueInUsd;

        emit Deposit(msg.sender, USDC, usdcReceived);
    }

    /// @notice internal helper functions

    /// @notice (Internal) Fetches the token price and normalizes it to 8 decimals.
    function _getPriceUsd8(
        address _tokenAddress
    ) internal view returns (uint256 price8) {
        address feedAddr = tokenPriceFeeds[_tokenAddress];
        if (feedAddr == address(0)) revert TokenNotSupported(_tokenAddress);

        AggregatorV3Interface feed = AggregatorV3Interface(feedAddr);
        (, int256 answer, , , ) = feed.latestRoundData();
        if (answer <= 0) revert InvalidPriceFeed(_tokenAddress);

        uint8 pdec = feed.decimals();
        uint256 u = uint256(answer);
        if (pdec > 8) price8 = u / (10 ** (pdec - 8));
        else if (pdec < 8) price8 = u * (10 ** (8 - pdec));
        else price8 = u;
    }

    /// @notice (Internal) Gets the number of decimals for a given token.
    function _getTokenDecimals(
        address _tokenAddress
    ) internal view returns (uint8) {
        if (_tokenAddress == ETH_ADDRESS) return 18;
        return IERC20Metadata(_tokenAddress).decimals();
    }

    /// @notice (Internal) Calculates the USD value of a given amount of a token.
    function _getValueInUsd(
        address _tokenAddress,
        uint256 _amount
    ) internal view returns (uint256) {
        if (_amount == 0) return 0;
        uint256 price8 = _getPriceUsd8(_tokenAddress);
        uint8 tdec = _getTokenDecimals(_tokenAddress);

        return (_amount * price8) / (10 ** uint256(tdec));
    }

    /// @notice (Internal) Swaps an exact amount of input token for USDC via Uniswap V4
    /// @param _tokenIn The input token address
    /// @param _amountIn The exact amount of input tokens to swap
    /// @param _minAmountOut The minimum amount of USDC expected (slippage protection)
    /// @return amountOut The actual amount of USDC received
    function _swapExactInputSingle(
        address _tokenIn,
        uint256 _amountIn,
        uint256 _minAmountOut
    ) internal returns (uint256 amountOut) {
        // Get the pool configuration for this token -> USDC swap
        PoolKey memory poolKey = tokenToUsdcPools[_tokenIn];

        // Verify pool is configured
        if (Currency.unwrap(poolKey.currency0) == address(0)) {
            revert PoolNotConfigured(_tokenIn);
        }

        // Record USDC balance before swap
        uint256 usdcBalanceBefore = IERC20(USDC).balanceOf(address(this));

        // Approve UniversalRouter to spend the input token
        IERC20(_tokenIn).forceApprove(address(universalRouter), _amountIn);

        // Encode the swap path (single hop: tokenIn -> USDC)
        bytes memory path = UniswapV4Helper.encodeSingleHopPath(
            _tokenIn,
            USDC,
            poolKey.fee
        );

        // Encode the V4_SWAP command inputs
        bytes memory swapInputs = UniswapV4Helper.encodeV4Swap(
            address(this), // recipient (this contract receives USDC)
            _amountIn, // amountIn
            _minAmountOut, // amountOutMin
            path, // encoded path
            false // payerIsUser = false (contract is payer)
        );

        // Create commands array with V4_SWAP command
        bytes memory commands = abi.encodePacked(uint8(Commands.V4_SWAP));
        bytes[] memory inputs = new bytes[](1);
        inputs[0] = swapInputs;

        // Execute the swap via UniversalRouter
        try
            universalRouter.execute(
                commands,
                inputs,
                block.timestamp + 300 // 5 minute deadline
            )
        {
            // Calculate USDC received
            uint256 usdcBalanceAfter = IERC20(USDC).balanceOf(address(this));
            amountOut = usdcBalanceAfter - usdcBalanceBefore;

            // Verify slippage protection
            if (amountOut < _minAmountOut) {
                revert SlippageExceeded(amountOut, _minAmountOut);
            }

            // Reset approval to 0 for security
            IERC20(_tokenIn).forceApprove(address(universalRouter), 0);
        } catch {
            // Reset approval even if swap fails
            IERC20(_tokenIn).forceApprove(address(universalRouter), 0);
            revert SwapFailed();
        }
    }
}
