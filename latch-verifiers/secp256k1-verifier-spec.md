# Secp256k1 Verifier Spec

> **Status: Not started. Architecture decisions required before implementation.**

This spec is a placeholder. The secp256k1 verifier is the MetaMask / EVM wallet path. It is explicitly out of scope until the Ed25519 Phantom and WebAuthn verifiers are complete.

---

## Open Architecture Questions

These must be resolved before implementation begins:

### 1. Signing convention

MetaMask's `personal_sign` uses EIP-191:

```
"\x19Ethereum Signed Message:\n" + len(message) + message
```

Similar problem to Phantom — MetaMask wraps the message before signing. The on-chain verifier must reconstruct the same wrapper. What is `message` in the Latch context? Options:

- Raw 32-byte auth payload hash → `"\x19Ethereum Signed Message:\n32" + hash`
- Hex-encoded hash → `"\x19Ethereum Signed Message:\n64" + hex(hash)`

Decision needed: which format, and does it match what MetaMask actually signs.

### 2. Verify vs recover

The Soroban host exposes `e.crypto().secp256k1_recover()` — not `secp256k1_verify()`. Recovery derives the public key from the signature and message. Verification checks a signature against a known public key.

Two paths:
- **Recovery**: `recover(hash, sig) -> pub_key`, then compare recovered pub_key to registered `key_data`
- **Direct verify**: not natively available in the Soroban host for secp256k1

Recovery is the likely path. Key format and comparison logic need to be defined.

### 3. Key data format

The factory already specifies: 65-byte uncompressed secp256k1 public key, first byte `0x04`.

But Ethereum wallets often operate with 20-byte addresses derived from the key, not the key itself. Decide:
- Store the full 65-byte uncompressed pubkey as `key_data` (consistent with factory spec)
- Or store the 20-byte Ethereum address and recover + compare address

The factory spec currently requires the full 65-byte pubkey. Stick with that unless there's a strong reason to change it.

### 4. Reference implementation

No reference implementation exists anywhere in the codebase. The OZ `stellar-accounts` library does not include a secp256k1 verifier. This is being built from scratch using `e.crypto().secp256k1_recover()`.

---

## Known Constraints

- Soroban host provides `secp256k1_recover`, not `secp256k1_verify`
- Factory `key_data` shape: 65 bytes, first byte `0x04`
- Must implement all three `Verifier` trait methods
- `canonicalize_key` must handle compressed vs uncompressed pubkey representations if both are possible inputs

---

## Dependencies on Other Work

This verifier can only be specced in full once:
1. The signing convention is confirmed against MetaMask's actual behavior
2. The recovery-based verification approach is validated on testnet
3. The key format decision is locked

Pick this back up after Ed25519 Phantom and WebAuthn verifiers are shipped.
