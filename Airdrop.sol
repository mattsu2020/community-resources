// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.20;

import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/ERC20Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";

contract Airdrop is OwnableUpgradeable, PausableUpgradeable {
    // admin address which can propose adding a new merkle root
    address public proposalAuthority;
    // admin address which approves or rejects a proposed merkle root
    address public reviewAuthority;
    address public tokenAddress;
    uint256 public totalOutput;
    uint256 public claimStartTime;
    uint256 public claimEndInterval;
    uint256 public totalClaim;

    uint256 rootCounts;
    // merkleRoot
    bytes32[] public merkleRoots;
    bytes32[] public pendingMerkleRoots;

    // history
    address[] public allClaimAddress;
    mapping(address => uint256) public claimHistory;
    // This is a packed array of booleans.
    mapping(uint256 => mapping(uint256 => uint256)) private claimedBitMaps;

    event Claimed(
        uint256 rootIndex,
        uint256 _index,
        address _account,
        uint256 _amount
    );

    modifier onlyValidAddress(address addr) {
        require(addr != address(0), "Illegal address");
        _;
    }

    receive() external payable {}

    function initialize(
        address _tokenAddress,
        address _proposalAuthority,
        address _reviewAuthority,
        uint256 _rootCounts,
        uint256 _totalOutput,
        uint256 _claimEndInterval
    ) external onlyValidAddress(_proposalAuthority) onlyValidAddress(_reviewAuthority) virtual initializer {
        tokenAddress = _tokenAddress;
        proposalAuthority = _proposalAuthority;
        reviewAuthority = _reviewAuthority;
        rootCounts = _rootCounts;
        totalOutput = _totalOutput;
        claimEndInterval = _claimEndInterval;
        // Initialize OZ contracts
        __Ownable_init_unchained();
    }

    function setProposalAuthority(address _account) public onlyValidAddress(_account) {
        require(msg.sender == proposalAuthority, "CP");
        proposalAuthority = _account;
    }

    function setReviewAuthority(address _account) public onlyValidAddress(_account) {
        require(msg.sender == reviewAuthority, "CR");
        reviewAuthority = _account;
    }

    // Each week, the proposal authority calls to submit the merkle root for a new airdrop.
    function proposeMerkleRoot(bytes32[] memory _merkleRoots) public {
        require(rootCounts == _merkleRoots.length, "CRML");
        require(msg.sender == proposalAuthority, "CPA");
        require(pendingMerkleRoots.length == 0, "CPL");
        require(merkleRoots.length == 0, "CML");
        for (uint i = 0; i < rootCounts; i++) {
            require(_merkleRoots[i] != 0x00, "CMR");
            pendingMerkleRoots.push(_merkleRoots[i]);
        }
    }

    // After validating the correctness of the pending merkle root, the reviewing authority
    // calls to confirm it and the distribution may begin.
    function reviewPendingMerkleRoot(bool _approved) public {
        require(msg.sender == reviewAuthority, "CR");
        require(rootCounts == pendingMerkleRoots.length, "CRPML");
        require(merkleRoots.length == 0, "CML");
        for (uint i = 0; i < rootCounts; i++) {
            require(pendingMerkleRoots[i] != 0x00, "CPMR");
            if (_approved) {
                merkleRoots.push(pendingMerkleRoots[i]);
            }
            delete pendingMerkleRoots[i];
        }

        claimStartTime = block.timestamp;
    }

    function isClaimed(uint256 rootIndex, uint256 index) public view returns (bool) {
        uint256 claimedWordIndex = index / 256;
        uint256 claimedBitIndex = index % 256;
        uint256 claimedWord = claimedBitMaps[rootIndex][claimedWordIndex];
        uint256 mask = (1 << claimedBitIndex);
        return claimedWord & mask == mask;
    }

    function _setClaimed(uint256 rootIndex, uint256 index) internal {
        uint256 claimedWordIndex = index / 256;
        uint256 claimedBitIndex = index % 256;
        claimedBitMaps[rootIndex][claimedWordIndex] = claimedBitMaps[rootIndex][claimedWordIndex] | (1 << claimedBitIndex);
    }

    function allClaimAddressLength() public view returns (uint256) {
        return allClaimAddress.length;
    }

    function verify(bytes32[] calldata proof, bytes32 root, bytes32 leaf) internal pure returns (bool) {
        bytes32 computedHash = leaf;

        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 proofElement = proof[i];

            if (computedHash <= proofElement) {
                // Hash(current computed hash + current element of the proof)
                computedHash = keccak256(abi.encodePacked(computedHash, proofElement));
            } else {
                // Hash(current element of the proof + current computed hash)
                computedHash = keccak256(abi.encodePacked(proofElement, computedHash));
            }
        }

        // Check if the computed hash (root) is equal to the provided root
        return computedHash == root;
    }

    function pause() public onlyOwner {
        super._pause();
    }

    function unpause() public onlyOwner {
        super._unpause();
    }
}
