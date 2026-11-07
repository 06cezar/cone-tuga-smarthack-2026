// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @title ConeTuga findings ledger
/// @notice Write-once hashes of ConeTuga's findings log. Every 10 log rows, the tool writes one 32-byte hash here: the
/// hash of those rows and of the batch before them. Only the account that deployed the contract can add a hash, each
/// batch number is written once, in order, and nothing can change or remove it. Checking the log on the laptop means
/// recomputing the hashes from its rows and comparing them with the ones stored here.
contract FindingsLedger {
    /// @notice The account allowed to add hashes: the one that deployed this contract.
    address public immutable owner;

    bytes32[] private hashes;

    /// @notice A batch's hash was stored.
    event Anchored(uint256 indexed batch, bytes32 digest);

    error NotOwner();
    error WrongBatch(uint256 expected, uint256 given);

    constructor() {
        owner = msg.sender;
    }

    /// @notice Store `digest`, the hash of `batch`, which must be the next one: batches are numbered 0, 1, 2... with
    /// no gaps, so a resent transaction can never store a batch twice.
    function anchor(uint256 batch, bytes32 digest) external {
        if (msg.sender != owner) revert NotOwner();
        if (batch != hashes.length) revert WrongBatch(hashes.length, batch);
        hashes.push(digest);
        emit Anchored(batch, digest);
    }

    /// @notice How many batches are stored.
    function count() external view returns (uint256) {
        return hashes.length;
    }

    /// @notice The stored hash of `batch` (reverts for a batch not stored yet).
    function batchHash(uint256 batch) external view returns (bytes32) {
        return hashes[batch];
    }
}
