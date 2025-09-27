// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import "./interfaces/IERC5192.sol";

/**
 * @title ProofOfSoul (PoSBT)
 * @notice Attestation (EIP-712 imza) ile mint edilen, transfer edilemeyen Soulbound NFT.
 * - ERC-5192 locked davranışı (transfer yok)
 * - ATTESTER_ROLE: imza üreten/veren otorite(ler)
 * - REVOKER_ROLE: geri alma (revoke) yetkisi
 * - Sahip (subject) self-burn yapabilir
 *
 * Metadata:
 * - schemaId (uint256) + dataHash (bytes32) + issuer(attester) + issuedAt
 * - tokenURI isteğe bağlı sabit/harici JSON (IPFS/HTTP)
 */
contract PoSBT is ERC721, EIP712, AccessControl, IERC5192 {
    using ECDSA for bytes32;

    // --- Roles ---
    bytes32 public constant ATTESTER_ROLE = keccak256("ATTESTER_ROLE");
    bytes32 public constant REVOKER_ROLE  = keccak256("REVOKER_ROLE");

    // --- Storage ---
    uint256 public nextTokenId;
    string  public baseURI;

    struct SoulRecord {
        uint256 schemaId;
        bytes32 dataHash;     // off-chain verinin hash'i (örn: KYC payload hash)
        address attester;
        uint64  issuedAt;
        bool    revoked;
        string  uri;          // opsiyonel özel URI (boşsa baseURI+tokenId)
    }
    mapping(uint256 => SoulRecord) public souls;

    // subject => nonce anti-replay
    mapping(address => uint256) public nonces;

    // ERC-5192: tüm tokenlar locked; burn edilince "unlock" ediliyor sayılabilir
    mapping(uint256 => bool) private _existsLocked;

    // --- EIP-712 types ---
    // Attester imzası gereken veri (attester bu mesajı imzalar)
    // keccak256("Attestation(address subject,uint256 schemaId,bytes32 dataHash,string uri,uint256 expiry,uint256 nonce)")
    bytes32 private constant ATTEST_TYPEHASH =
        keccak256("Attestation(address subject,uint256 schemaId,bytes32 dataHash,string uri,uint256 expiry,uint256 nonce)");

    // --- Events ---
    event Minted(uint256 indexed tokenId, address indexed subject, address indexed attester, uint256 schemaId, bytes32 dataHash, string uri);
    event Revoked(uint256 indexed tokenId, address indexed by);
    event Burned(uint256 indexed tokenId);

    constructor(string memory _name, string memory _symbol, string memory _baseURI)
        ERC721(_name, _symbol)
        EIP712("ProofOfSoul", "1")
    {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(REVOKER_ROLE, msg.sender);
        baseURI = _baseURI;
    }

    // ---------- Soulbound / ERC-5192 ----------
    function locked(uint256 tokenId) external view override returns (bool) {
        require(_exists(tokenId), "PoSBT: nonexistent");
        return _existsLocked[tokenId];
    }

    // Transferleri tamamen engelle
    function _update(address to, uint256 tokenId, address auth) internal override returns (address) {
        address from = _ownerOf(tokenId);
        // mint: from==0; burn: to==0; normal transfer: from!=0 && to!=0 -> yasak
        if (from != address(0) && to != address(0)) revert("PoSBT: non-transferable");
        return super._update(to, tokenId, auth);
    }

    // ---------- Mint (EIP-712 ile) ----------
    struct Attestation {
        address subject;    // NFT sahibi olacak kişi
        uint256 schemaId;   // hangi şema (örn 1=KYC-Lite, 2=Alumni vb.)
        bytes32 dataHash;   // verinin hash'i
        string  uri;        // opsiyonel (IPFS/HTTPS metadata)
        uint256 expiry;     // imzanın son kullanma zamanı (unix), 0 ise sınırsız
        uint256 nonce;      // subject özel nonce (replay koruması)
    }

    /**
     * @notice Attester imzasını doğrular, geçerliyse subject'e soulbound mint eder.
     * @param att Struct
     * @param attesterSigned EIP-712 imzası (attester tarafından)
     */
    function mintWithSig(Attestation calldata att, bytes calldata attesterSigned) external returns (uint256 tokenId) {
        // att.subject çağırmak zorunda değil; herkes başvuruyu relay edebilir.
        require(att.subject != address(0), "PoSBT: subject=0");

        // replay koruması: subject -> expected nonce
        require(att.nonce == nonces[att.subject], "PoSBT: bad nonce");

        // expiry
        if (att.expiry != 0) require(block.timestamp <= att.expiry, "PoSBT: expired");

        // EIP-712 digest ve signer
        bytes32 digest = _hashTypedDataV4(keccak256(abi.encode(
            ATTEST_TYPEHASH,
            att.subject,
            att.schemaId,
            att.dataHash,
            keccak256(bytes(att.uri)),
            att.expiry,
            att.nonce
        )));
        address signer = ECDSA.recover(digest, attesterSigned);
        require(hasRole(ATTESTER_ROLE, signer), "PoSBT: signer not attester");

        // mint
        tokenId = ++nextTokenId;
        _safeMint(att.subject, tokenId);
        _existsLocked[tokenId] = true;
        emit Locked(tokenId); // ERC-5192 event

        souls[tokenId] = SoulRecord({
            schemaId: att.schemaId,
            dataHash: att.dataHash,
            attester: signer,
            issuedAt: uint64(block.timestamp),
            revoked: false,
            uri: att.uri
        });

        // nonce tüket
        nonces[att.subject] = att.nonce + 1;

        emit Minted(tokenId, att.subject, signer, att.schemaId, att.dataHash, att.uri);
    }

    // ---------- Revoke / Burn ----------
    /**
     * @notice Revoker veya ilgili attester token'ı "revoked=true" işaretler (yakmaz).
     */
    function revoke(uint256 tokenId) external {
        require(_exists(tokenId), "PoSBT: no token");
        SoulRecord storage s = souls[tokenId];
        require(
            hasRole(REVOKER_ROLE, msg.sender) || msg.sender == s.attester,
            "PoSBT: no revoke permission"
        );
        require(!s.revoked, "PoSBT: already revoked");
        s.revoked = true;
        emit Revoked(tokenId, msg.sender);
    }

    /**
     * @notice Sadece sahibi "self-burn" ile token'ını yakabilir (veri kalır).
     */
    function burn(uint256 tokenId) external {
        require(ownerOf(tokenId) == msg.sender, "PoSBT: not owner");
        _burn(tokenId);
        _existsLocked[tokenId] = false;
        emit Unlocked(tokenId); // ERC-5192: burn ile artık "kilitli token" yok
        emit Burned(tokenId);
    }

    // ---------- Admin yardımcıları ----------
    function setBaseURI(string calldata newBase) external onlyRole(DEFAULT_ADMIN_ROLE) {
        baseURI = newBase;
    }

    function grantAttester(address a) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _grantRole(ATTESTER_ROLE, a);
    }

    function revokeAttester(address a) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _revokeRole(ATTESTER_ROLE, a);
    }

    function grantRevoker(address a) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _grantRole(REVOKER_ROLE, a);
    }

    function revokeRevoker(address a) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _revokeRole(REVOKER_ROLE, a);
    }

    // ---------- Views / Metadata ----------
    function tokenURI(uint256 tokenId) public view override returns (string memory) {
        require(_exists(tokenId), "PoSBT: no token");
        string memory custom = souls[tokenId].uri;
        if (bytes(custom).length > 0) return custom;
        if (bytes(baseURI).length == 0) return "";
        return string(abi.encodePacked(baseURI, Strings.toString(tokenId), ".json"));
    }
}
