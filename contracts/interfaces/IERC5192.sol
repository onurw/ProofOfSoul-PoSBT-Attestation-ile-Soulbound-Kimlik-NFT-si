// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

/// @title Minimal ERC-5192 interface (Soulbound NFTs)
interface IERC5192 {
    /// @notice Emitted when the locking status is set to locked.
    event Locked(uint256 tokenId);
    /// @notice Emitted when the locking status is set to unlocked.
    event Unlocked(uint256 tokenId);
    /// @notice Returns true if the NFT is locked (non-transferable).
    function locked(uint256 tokenId) external view returns (bool);
}
