// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title VulnerableVault
 * @notice Realistic DeFi Vault vulnerable to cross-function and single-function reentrancy.
 * State update occurs AFTER the external call, violating Checks-Effects-Interactions (CEI).
 */
contract VulnerableVault {
    mapping(address => uint256) public balances;
    uint256 public totalDeposits;
    bool public locked;

    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);

    // Deposit native ETH into vault
    function deposit() external payable {
        require(msg.value > 0, "Deposit must be positive");
        balances[msg.sender] += msg.value;
        totalDeposits += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    // Vulnerable withdraw: External call made prior to state reduction
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // VULNERABILITY (SWC-107): Untrusted external call before state decrement
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "ETH transfer failed");

        // State update performed after interaction
        balances[msg.sender] -= amount;
        totalDeposits -= amount;
        emit Withdrawal(msg.sender, amount);
    }

    // Solvency query
    function getVaultBalance() external view returns (uint256) {
        return address(this).balance;
    }
}
