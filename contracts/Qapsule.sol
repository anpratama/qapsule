// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title Qapsule - post-quantum encrypted time-capsules on QoreChain
/// @notice The contract is the time gate and the public record. Message content
///         is encrypted in the browser with AES-256-GCM; the content key is
///         XOR-split into Share A and Share B. Share A is encapsulated to the
///         recipient with ML-KEM-1024 (FIPS 203) and stored here. Share B is
///         never stored - only its hash commitment is. This contract refuses
///         to accept the reveal of Share B before `unlockTime`; after the
///         reveal, anyone can verify Share B against the commitment, and the
///         recipient combines the shares and decrypts locally.
/// @dev Hash note: the EVM lane has no SHAKE-256 opcode, so the on-chain reveal
///      check uses keccak256(shareB). The SHAKE-256 hash of the ciphertext
///      (computed client-side, the QoreChain-native hash) is stored as the
///      content integrity anchor in `contentHash`.
contract Qapsule {
    struct Capsule {
        address sender;
        address recipient;
        uint64 unlockTime;
        bytes32 contentHash;      // SHAKE-256 of the ciphertext (client-computed)
        bytes32 shareBCommitment; // keccak256(shareB)
        bytes encapsulatedShareA; // ML-KEM-1024 ciphertext wrapping Share A
        string storageRef;        // where the ciphertext lives (capsule file / IPFS CID)
        bytes32 revealedShareB;   // zero until revealed
        bool revealed;
    }

    Capsule[] private _capsules;

    event CapsuleCreated(
        uint256 indexed id,
        address indexed sender,
        address indexed recipient,
        uint64 unlockTime
    );
    event ShareBRevealed(uint256 indexed id, bytes32 shareB);

    error InvalidRecipient();
    error UnlockNotInFuture();
    error UnknownCapsule();
    error NotReleaser();
    error TooEarly(uint64 unlockTime, uint64 nowTs);
    error AlreadyRevealed();
    error CommitmentMismatch();

    /// @notice Register a new capsule. Share B itself is NOT passed here -
    ///         only its commitment; the sender keeps Share B until reveal.
    function createCapsule(
        address recipient,
        uint64 unlockTime,
        bytes32 contentHash,
        bytes32 shareBCommitment,
        bytes calldata encapsulatedShareA,
        string calldata storageRef
    ) external returns (uint256 id) {
        if (recipient == address(0)) revert InvalidRecipient();
        if (unlockTime <= block.timestamp) revert UnlockNotInFuture();
        id = _capsules.length;
        _capsules.push(
            Capsule({
                sender: msg.sender,
                recipient: recipient,
                unlockTime: unlockTime,
                contentHash: contentHash,
                shareBCommitment: shareBCommitment,
                encapsulatedShareA: encapsulatedShareA,
                storageRef: storageRef,
                revealedShareB: bytes32(0),
                revealed: false
            })
        );
        emit CapsuleCreated(id, msg.sender, recipient, unlockTime);
    }

    /// @notice Reveal Share B for a capsule whose unlock time has passed.
    ///         Only the capsule's sender (the releaser) may call this, and the
    ///         share is checked against the on-chain commitment.
    function revealShareB(uint256 id, bytes32 shareB) external {
        if (id >= _capsules.length) revert UnknownCapsule();
        Capsule storage c = _capsules[id];
        if (msg.sender != c.sender) revert NotReleaser();
        if (c.revealed) revert AlreadyRevealed();
        if (block.timestamp < c.unlockTime)
            revert TooEarly(c.unlockTime, uint64(block.timestamp));
        if (keccak256(abi.encodePacked(shareB)) != c.shareBCommitment)
            revert CommitmentMismatch();
        c.revealedShareB = shareB;
        c.revealed = true;
        emit ShareBRevealed(id, shareB);
    }

    function capsuleCount() external view returns (uint256) {
        return _capsules.length;
    }

    function getCapsule(
        uint256 id
    )
        external
        view
        returns (
            address sender,
            address recipient,
            uint64 unlockTime,
            bytes32 contentHash,
            bytes32 shareBCommitment,
            bytes memory encapsulatedShareA,
            string memory storageRef,
            bytes32 revealedShareB,
            bool revealed
        )
    {
        if (id >= _capsules.length) revert UnknownCapsule();
        Capsule storage c = _capsules[id];
        return (
            c.sender,
            c.recipient,
            c.unlockTime,
            c.contentHash,
            c.shareBCommitment,
            c.encapsulatedShareA,
            c.storageRef,
            c.revealedShareB,
            c.revealed
        );
    }
}
