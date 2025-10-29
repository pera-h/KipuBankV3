// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import "../../KipuBankV3.sol";
import "../../interfaces/uniswap/IPoolManager.sol";
import "../mocks/MockERC20.sol";
import "../mocks/MockUniversalRouter.sol";
import "../mocks/MockChainlinkAggregator.sol";

contract KipuBankV3Test is Test {
    KipuBankV3 public bank;
    MockUniversalRouter public router;
    MockERC20 public usdc;
    MockERC20 public dai;
    MockERC20 public weth;
    MockChainlinkAggregator public usdcPriceFeed;
    MockChainlinkAggregator public daiPriceFeed;
    MockChainlinkAggregator public wethPriceFeed;

    address public owner;
    address public user1;
    address public user2;

    // Constants
    uint256 constant INITIAL_BANK_CAP = 1_000_000e8; // $1M with 8 decimals
    uint256 constant INITIAL_WITHDRAWAL_LIMIT = 10_000e8; // $10k with 8 decimals
    uint256 constant USDC_DECIMALS = 6;
    uint256 constant DAI_DECIMALS = 18;
    uint256 constant WETH_DECIMALS = 18;

    function setUp() public {
        owner = address(this);
        user1 = address(0x1);
        user2 = address(0x2);

        // Deploy mock tokens
        usdc = new MockERC20("USD Coin", "USDC", uint8(USDC_DECIMALS));
        dai = new MockERC20("Dai Stablecoin", "DAI", uint8(DAI_DECIMALS));
        weth = new MockERC20("Wrapped Ether", "WETH", uint8(WETH_DECIMALS));

        // Deploy mock router
        router = new MockUniversalRouter();

        // Deploy mock price feeds
        // USDC: $1.00 (8 decimals)
        usdcPriceFeed = new MockChainlinkAggregator(8, 1e8, "USDC/USD");
        // DAI: $0.999 (8 decimals)
        daiPriceFeed = new MockChainlinkAggregator(8, 0.999e8, "DAI/USD");
        // WETH: $2000 (8 decimals)
        wethPriceFeed = new MockChainlinkAggregator(8, 2000e8, "ETH/USD");

        // Deploy KipuBankV3
        bank = new KipuBankV3(
            INITIAL_BANK_CAP,
            INITIAL_WITHDRAWAL_LIMIT,
            address(router),
            address(0), // permit2 - not used in tests
            address(usdc),
            address(0) // poolManager - not used in tests
        );

        // Add price feeds
        bank.addToken(address(usdc), address(usdcPriceFeed));
        bank.addToken(address(dai), address(daiPriceFeed));
        bank.addToken(address(weth), address(wethPriceFeed));

        // Mint tokens to users for testing
        usdc.mint(user1, 10_000e6); // 10k USDC
        dai.mint(user1, 10_000e18); // 10k DAI
        weth.mint(user1, 10e18); // 10 WETH

        usdc.mint(user2, 5_000e6);
        dai.mint(user2, 5_000e18);
        weth.mint(user2, 5e18);

        // Fund router with USDC for swaps
        usdc.mint(address(router), 1_000_000e6); // 1M USDC in router
    }

    /// @notice Test 1: Constructor initialization
    function testConstructor() public {
        assertEq(address(bank.universalRouter()), address(router));
        assertEq(bank.USDC(), address(usdc));
        assertEq(bank.bankCapInUsd(), INITIAL_BANK_CAP);
        assertEq(bank.withdrawalLimitInUsd(), INITIAL_WITHDRAWAL_LIMIT);

        console.log("Test 1: Constructor initialized correctly");
    }

    /// @notice Test 2: Constructor reverts with zero addresses
    function testConstructorRevertsZeroAddress() public {
        vm.expectRevert(KipuBankV3.InvalidRouter.selector);
        new KipuBankV3(
            INITIAL_BANK_CAP,
            INITIAL_WITHDRAWAL_LIMIT,
            address(0), // zero router
            address(0),
            address(usdc),
            address(0)
        );

        vm.expectRevert(KipuBankV3.InvalidUSDC.selector);
        new KipuBankV3(
            INITIAL_BANK_CAP,
            INITIAL_WITHDRAWAL_LIMIT,
            address(router),
            address(0),
            address(0), // zero USDC
            address(0)
        );

        console.log("Test 2: Constructor reverts with zero addresses");
    }

    /// @notice Test 3: Add token pool
    function testAddTokenPool() public {
        PoolKey memory poolKey = PoolKey({
            currency0: Currency.wrap(address(dai)),
            currency1: Currency.wrap(address(usdc)),
            fee: 3000, // 0.3%
            tickSpacing: 60,
            hooks: IHooks(address(0))
        });

        vm.expectEmit(true, false, false, true);
        emit KipuBankV3.PoolKeyAdded(address(dai), 3000, 60);

        bank.addTokenPool(address(dai), poolKey);

        // Verify pool was added
        (Currency c0, Currency c1, uint24 fee, int24 tickSpacing, ) = bank
            .tokenToUsdcPools(address(dai));

        assertEq(Currency.unwrap(c0), address(dai));
        assertEq(Currency.unwrap(c1), address(usdc));
        assertEq(fee, 3000);
        assertEq(tickSpacing, 60);

        console.log("Test 3: Token pool added successfully");
    }

    /// @notice Test 4: Add token pool reverts for unauthorized
    function testAddTokenPoolUnauthorized() public {
        PoolKey memory poolKey = PoolKey({
            currency0: Currency.wrap(address(dai)),
            currency1: Currency.wrap(address(usdc)),
            fee: 3000,
            tickSpacing: 60,
            hooks: IHooks(address(0))
        });

        vm.prank(user1);
        vm.expectRevert();
        bank.addTokenPool(address(dai), poolKey);

        console.log("Test 4: Unauthorized pool addition reverts");
    }

    /// @notice Test 5: Deposit USDC directly (no swap)
    function testDepositUSDCDirect() public {
        uint256 depositAmount = 1000e6; // 1000 USDC

        vm.startPrank(user1);
        usdc.approve(address(bank), depositAmount);

        vm.expectEmit(true, true, false, true);
        emit KipuBankV3.Deposit(user1, address(usdc), depositAmount);

        bank.depositArbitraryToken(address(usdc), depositAmount, depositAmount);
        vm.stopPrank();

        // Check balance
        assertEq(bank.balances(address(usdc), user1), depositAmount);

        console.log("Test 5: Direct USDC deposit successful");
    }

    /// @notice Test 6: Deposit arbitrary token with swap (DAI -> USDC)
    function testDepositArbitraryTokenWithSwap() public {
        // Setup: Add DAI pool
        PoolKey memory daiPool = PoolKey({
            currency0: Currency.wrap(address(dai)),
            currency1: Currency.wrap(address(usdc)),
            fee: 3000,
            tickSpacing: 60,
            hooks: IHooks(address(0))
        });
        bank.addTokenPool(address(dai), daiPool);

        // Set exchange rate: 1 DAI = 0.999 USDC (accounting for decimals)
        // 1 DAI (18 decimals) = 0.999 USDC (6 decimals)
        // 1e18 DAI = 0.999e6 USDC
        // Rate = 0.999e6 * 1e18 / 1e18 = 0.999e6
        router.setExchangeRate(999000); // 0.999 * 1e6

        uint256 daiAmount = 1000e18; // 1000 DAI
        uint256 expectedUsdc = 999e6; // ~999 USDC
        uint256 minUsdc = 995e6; // 0.5% slippage tolerance

        vm.startPrank(user1);
        dai.approve(address(bank), daiAmount);

        // Approve router to spend DAI (for the mock router)
        dai.approve(address(router), daiAmount);

        vm.expectEmit(true, true, false, false);
        emit KipuBankV3.TokenSwapped(user1, address(dai), daiAmount, 0);

        bank.depositArbitraryToken(address(dai), daiAmount, minUsdc);
        vm.stopPrank();

        // Check USDC balance (should have received ~999 USDC)
        uint256 usdcBalance = bank.balances(address(usdc), user1);
        assertGe(usdcBalance, minUsdc);
        assertLe(usdcBalance, expectedUsdc + 1e6); // Allow 1 USDC tolerance

        console.log("Test 6: Arbitrary token deposit with swap successful");
        console.log("   DAI deposited:", daiAmount / 1e18);
        console.log("   USDC received:", usdcBalance / 1e6);
    }

    /// @notice Test 7: Slippage protection works
    function testSlippageProtection() public {
        // Setup pool
        PoolKey memory daiPool = PoolKey({
            currency0: Currency.wrap(address(dai)),
            currency1: Currency.wrap(address(usdc)),
            fee: 3000,
            tickSpacing: 60,
            hooks: IHooks(address(0))
        });
        bank.addTokenPool(address(dai), daiPool);

        // Set unfavorable exchange rate
        router.setExchangeRate(900000); // 0.9 USDC per DAI

        uint256 daiAmount = 1000e18;
        uint256 minUsdc = 995e6; // Expecting at least 995 USDC, but will get 900

        vm.startPrank(user1);
        dai.approve(address(bank), daiAmount);
        dai.approve(address(router), daiAmount);

        // Should revert due to slippage
        vm.expectRevert();
        bank.depositArbitraryToken(address(dai), daiAmount, minUsdc);
        vm.stopPrank();

        console.log("Test 7: Slippage protection works");
    }

    /// @notice Test 8: Bank cap enforcement
    function testBankCapEnforcement() public {
        // Deposit close to cap
        uint256 depositAmount = 999_000e6; // 999k USDC (cap is 1M)

        vm.startPrank(user1);
        usdc.mint(user1, depositAmount);
        usdc.approve(address(bank), depositAmount);
        bank.depositArbitraryToken(address(usdc), depositAmount, depositAmount);
        vm.stopPrank();

        // Try to deposit more (should fail)
        uint256 excessAmount = 2_000e6; // 2k more USDC

        vm.startPrank(user2);
        usdc.approve(address(bank), excessAmount);

        vm.expectRevert();
        bank.depositArbitraryToken(address(usdc), excessAmount, excessAmount);
        vm.stopPrank();

        console.log("Test 8: Bank cap enforcement works");
    }

    /// @notice Test 9: Multiple users can deposit
    function testMultipleUsersDeposit() public {
        uint256 amount1 = 1000e6;
        uint256 amount2 = 500e6;

        // User 1 deposits
        vm.startPrank(user1);
        usdc.approve(address(bank), amount1);
        bank.depositArbitraryToken(address(usdc), amount1, amount1);
        vm.stopPrank();

        // User 2 deposits
        vm.startPrank(user2);
        usdc.approve(address(bank), amount2);
        bank.depositArbitraryToken(address(usdc), amount2, amount2);
        vm.stopPrank();

        assertEq(bank.balances(address(usdc), user1), amount1);
        assertEq(bank.balances(address(usdc), user2), amount2);

        console.log("Test 9: Multiple users can deposit");
    }

    /// @notice Test 10: Withdraw USDC after deposit
    function testWithdrawUSDC() public {
        uint256 depositAmount = 1000e6;

        // Deposit
        vm.startPrank(user1);
        usdc.approve(address(bank), depositAmount);
        bank.depositArbitraryToken(address(usdc), depositAmount, depositAmount);

        // Withdraw
        uint256 withdrawAmount = 500e6;
        bank.withdraw(address(usdc), withdrawAmount);
        vm.stopPrank();

        // Check balances
        assertEq(
            bank.balances(address(usdc), user1),
            depositAmount - withdrawAmount
        );
        assertEq(
            usdc.balanceOf(user1),
            10_000e6 - depositAmount + withdrawAmount
        );

        console.log("Test 10: Withdraw USDC works");
    }

    /// @notice Test 11: Pool not configured reverts
    function testPoolNotConfiguredReverts() public {
        // Try to deposit WETH without configuring pool
        uint256 wethAmount = 1e18;

        vm.startPrank(user1);
        weth.approve(address(bank), wethAmount);
        weth.approve(address(router), wethAmount);

        vm.expectRevert(
            abi.encodeWithSelector(
                KipuBankV3.PoolNotConfigured.selector,
                address(weth)
            )
        );
        bank.depositArbitraryToken(address(weth), wethAmount, 1000e6);
        vm.stopPrank();

        console.log("Test 11: Pool not configured reverts correctly");
    }

    /// @notice Test 12: Zero amount deposit reverts
    function testZeroAmountReverts() public {
        vm.startPrank(user1);
        vm.expectRevert(KipuBankV3.InvalidAmount.selector);
        bank.depositArbitraryToken(address(usdc), 0, 0);
        vm.stopPrank();

        console.log("Test 12: Zero amount deposit reverts");
    }
}
