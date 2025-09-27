# ProofOfSoul (PoSBT) — EIP-712 Attestation + ERC-5192 Soulbound

PoSBT, attester(lar) tarafından **EIP-712** imzasıyla onaylanan kimlik/kanıt verilerini **transfer edilemeyen** bir NFT (SBT) olarak basar.

## Özellikler
- **Soulbound (ERC-5192)**: Transfer tamamen engelli, `locked(tokenId)=true`
- **EIP-712 Attestation** ile mint: attester imzası doğrulanır, replay için subject tabanlı nonce
- **Roller**: `ATTESTER_ROLE`, `REVOKER_ROLE`, `DEFAULT_ADMIN_ROLE`
- **Revoke** (işaretleme) ve **self-burn**
- **URI**: IPFS/HTTPS metadata veya `baseURI/<id>.json`

## Hızlı Başlangıç
```bash
npm install
npm run build
npm run node
# yeni terminal
npm run deploy:local
