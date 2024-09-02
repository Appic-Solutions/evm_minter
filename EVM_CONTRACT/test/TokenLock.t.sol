// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/TokenLock.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract MockERC20 is ERC20 {
    constructor(string memory name, string memory symbol) ERC20(name, symbol) {
        _mint(msg.sender, 1_000_000 * 10 ** decimals());
    }
}

contract TokenLockTest is Test {
    TokenLock public tokenLock;
    MockERC20 public token;
    address public minter = address(1);
    address public user = address(2);

    function setUp() public {
        // Deploy the contract
        tokenLock = new TokenLock();

        // Deploy the mock token and assign balances
        token = new MockERC20("Mock Token", "MTKN");

        // Set the minter role to minter address
        tokenLock.grantMinterRole(minter);

        // Allocate tokens to user for testing
        token.transfer(user, 1000 * 10 ** token.decimals());
        token.transfer(address(4), 1000 * 10 ** token.decimals());
        token.transfer(address(5), 1000 * 10 ** token.decimals());
    }

    function testGrantMinterRole() public {
        // Act
        tokenLock.grantMinterRole(minter);
        bool hasMinterRole = tokenLock.hasRole(tokenLock.MINTER_ROLE(), minter);

        // Assert
        assertTrue(hasMinterRole);
    }

    function testLockTokens() public {
        // Arrange
        uint256 amount = 100 * 10 ** token.decimals();
        vm.startPrank(user);
        token.approve(address(tokenLock), amount);

        // Act
        bytes memory principalId = "testPrincipalId";
        tokenLock.lockTokens(address(token), amount, principalId);

        // Assert
        assertEq(token.balanceOf(minter), amount);
        assertEq(tokenLock.tokenAmount(address(token)), amount);
    }

    function testLockNativeCurrency() public {
        // Arrange
        uint256 amount = 1 ether;

        // Act
        bytes memory principalId = "testPrincipalId";
        vm.deal(user, amount);
        vm.prank(user);
        tokenLock.lockTokens{value: amount}(address(0), amount, principalId);

        // Assert
        assertEq(address(minter).balance, amount);
        assertEq(tokenLock.tokenAmount(address(0)), amount);
    }

    function testAddFee() public {
        // Arrange
        uint256 feeAmount = 0.1 ether;
        vm.deal(user, feeAmount);

        // Act
        vm.prank(user);
        tokenLock.addFee{value: feeAmount}();

        // Assert
        assertEq(address(minter).balance, feeAmount);
        assertEq(tokenLock.feeTank(user), feeAmount);
    }

    function testWithdrawTokens() public {
        // Arrange
        uint256 amount = 100 * 10 ** token.decimals();
        uint256 fee = 0;
        vm.startPrank(user);
        token.approve(address(tokenLock), amount);
        tokenLock.lockTokens(address(token), amount, "");

        // Act
        vm.stopPrank();
        vm.startPrank(minter);
        token.transfer(address(tokenLock), amount);
        uint256 balBefore = token.balanceOf(user);
        tokenLock.withdrawTokens(user, address(token), amount, fee);
        uint256 balAfter = token.balanceOf(user);

        // Assert
        assertEq(balAfter - balBefore, amount);
        assertEq(tokenLock.tokenAmount(address(token)), 0);
    }

    function testWithdrawNativeCurrency() public {
        // Arrange
        uint256 amount = 1 ether;
        uint256 fee = 0.1 ether;
        vm.deal(user, amount + fee);
        vm.prank(user);
        tokenLock.lockTokens{value: amount}(address(0), amount, "");

        // Act
        vm.prank(user);
        tokenLock.addFee{value: fee}();

        vm.startPrank(minter);
        tokenLock.withdrawTokens{value: amount}(user, address(0), amount, fee);

        // Assert
        assertEq(user.balance, amount);
        assertEq(tokenLock.tokenAmount(address(0)), 0);
    }

    function testGrantMinterRoleByOwner() public {
        // Act
        tokenLock.grantMinterRole(minter);
        bool hasMinterRole = tokenLock.hasRole(tokenLock.MINTER_ROLE(), minter);

        // Assert
        assertTrue(hasMinterRole);
    }

    function testGrantMinterRoleByNonOwner() public {
        // Arrange
        address nonOwner = address(3);
        vm.prank(nonOwner); // Set the next call's sender to nonOwner

        // Act & Assert
        vm.expectRevert();
        tokenLock.grantMinterRole(minter);
    }

    function testRevokeMinterRoleByOwner() public {
        // Arrange
        tokenLock.grantMinterRole(minter);
        assertTrue(tokenLock.hasRole(tokenLock.MINTER_ROLE(), minter));

        // Act
        tokenLock.rovokeMinterRole(minter);
        bool hasMinterRole = tokenLock.hasRole(tokenLock.MINTER_ROLE(), minter);

        // Assert
        assertFalse(hasMinterRole);
    }

    function testRevokeMinterRoleByNonOwner() public {
        // Arrange
        tokenLock.grantMinterRole(minter);
        address nonOwner = address(3);
        vm.prank(nonOwner); // Set the next call's sender to nonOwner

        // Act & Assert
        vm.expectRevert();
        tokenLock.rovokeMinterRole(minter);
    }

    function testWithdrawTokensMultipleUsers() public {
        // Arrange
        address[] memory users = new address[](2);
        users[0] = address(4);
        users[1] = address(5);

        address[] memory tokens = new address[](2);
        tokens[0] = address(token);
        tokens[1] = address(token);

        uint256[] memory amounts = new uint256[](2);
        amounts[0] = 50 * 10 ** token.decimals();
        amounts[1] = 75 * 10 ** token.decimals();

        uint256[] memory fees = new uint256[](2);
        fees[0] = 0;
        fees[1] = 0;

        // Distribute tokens to users and approve them to TokenLock contract
        vm.startPrank(users[0]);
        token.approve(address(tokenLock), amounts[0]);
        tokenLock.lockTokens(address(token), amounts[0], "");
        vm.stopPrank();

        vm.startPrank(users[1]);
        token.approve(address(tokenLock), amounts[1]);
        tokenLock.lockTokens(address(token), amounts[1], "");
        vm.stopPrank();

        uint256 bal1 = token.balanceOf(users[0]);
        uint256 bal2 = token.balanceOf(users[1]);

        // Act
        vm.startPrank(minter);
        token.transfer(address(tokenLock), amounts[0] + amounts[1]);
        tokenLock.withdrawTokensMultipleUsers(users, tokens, amounts, fees);
        vm.stopPrank();

        // Assert
        assertEq(token.balanceOf(users[0]) - bal1, amounts[0]);
        assertEq(token.balanceOf(users[1]) - bal2, amounts[1]);
        assertEq(tokenLock.tokenAmount(address(token)), 0);
    }

    function testWithdrawNativeCurrencyMultipleUsers() public {
        // Arrange
        address[] memory users = new address[](2);
        users[0] = address(4);
        users[1] = address(5);

        address[] memory tokens = new address[](2);
        tokens[0] = address(0); // Native currency
        tokens[1] = address(0); // Native currency

        uint256[] memory amounts = new uint256[](2);
        amounts[0] = 1 ether;
        amounts[1] = 2 ether;

        uint256[] memory fees = new uint256[](2);
        fees[0] = 0.1 ether;
        fees[1] = 0.2 ether;

        // Deal native currency to users and lock it in the contract
        vm.deal(users[0], amounts[0] + fees[0]);
        vm.prank(users[0]);
        tokenLock.lockTokens{value: amounts[0]}(address(0), amounts[0], "");

        vm.deal(users[1], amounts[1] + fees[1]);
        vm.prank(users[1]);
        tokenLock.lockTokens{value: amounts[1]}(address(0), amounts[1], "");

        // Act
        vm.prank(users[0]);
        tokenLock.addFee{value: fees[0]}();
        vm.prank(users[1]);
        tokenLock.addFee{value: fees[1]}();

        vm.startPrank(minter);
        tokenLock.withdrawTokensMultipleUsers{value: amounts[0] + amounts[1]}(
            users,
            tokens,
            amounts,
            fees
        );
        vm.stopPrank();

        // Assert
        assertEq(users[0].balance, amounts[0]);
        assertEq(users[1].balance, amounts[1]);
        assertEq(tokenLock.tokenAmount(address(0)), 0);
    }
}
