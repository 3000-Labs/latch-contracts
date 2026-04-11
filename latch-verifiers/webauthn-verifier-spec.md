# WebAuthn Verifier Spec

A stateless singleton Soroban contract that verifies WebAuthn authentication assertions on behalf of Latch smart accounts. Deployed once, shared across all accounts on the network.

## What WebAuthn Is

WebAuthn is a W3C standard for authenticating with public key cryptography using platform or hardware authenticators. The underlying cryptographic primitive is **secp256r1 (P-256)** — distinct from Stellar's Ed25519 and Ethereum's secp256k1. The biometric or PIN (Touch ID, Face ID, Windows Hello, YubiKey) is the local unlock mechanism for the private key — it never leaves the device. What leaves the device is a P-256 signature.

**Devices covered by this verifier:**
- Apple Touch ID / Face ID
- Android biometrics / PIN
- Windows Hello
- YubiKey and other hardware keys
- Any device implementing the WebAuthn standard

This is the primary passkey path for Latch. It requires no external wallet app — the device itself is the signer.

---

## What the Verifier Receives

Unlike Ed25519 where the client signs a simple message, WebAuthn produces a structured authentication assertion containing three components:

1. **`signature`** — 64-byte P-256/secp256r1 signature
2. **`authenticator_data`** — raw bytes from the authenticator (min 37 bytes): 32-byte rpIdHash + 1-byte flags + 4-byte counter + optional extensions
3. **`client_data`** — JSON blob produced by the browser/platform containing `type`, `challenge`, and `origin`

The verifier must validate all three before accepting the signature as valid.

---

## The Challenge Mechanism

WebAuthn does not sign an arbitrary message. It embeds the "thing to sign" as a `challenge` field inside `clientDataJSON`, base64url-encoded. The browser/platform constructs the JSON and the authenticator signs over it.

For Latch, the challenge is the base64url encoding of the 32-byte Soroban auth payload hash:

```
challenge = base64url(auth_payload_hash)
```

The verifier reconstructs the expected challenge from the `hash` it receives from the Soroban host and checks it matches the `challenge` field in the client data JSON. This is how the auth payload hash is bound to the WebAuthn ceremony.

No custom prefix is needed — the base64url encoding is the WebAuthn protocol's own binding mechanism. This is why WebAuthn does not have the Phantom 32-byte constraint problem.

---

## Verification Steps

The full verification procedure follows W3C WebAuthn Level 2, §7.2, with blockchain-specific omissions:

1. **Check `clientData` length** — must be ≤ 1024 bytes
2. **Parse `clientDataJSON`** — extract `type` and `challenge` fields
3. **Validate `type`** — must be `"webauthn.get"` (not `"webauthn.create"`)
4. **Validate `challenge`** — must equal `base64url(auth_payload_hash)`
5. **Check `authenticatorData` length** — must be ≥ 37 bytes
6. **Check User Present (UP) flag** — bit 0 of flags byte (byte 32 of authenticatorData) must be set
7. **Check User Verified (UV) flag** — bit 2 of flags byte must be set
8. **Check Backup Eligibility/State consistency** — if BS=1 then BE must also be 1
9. **Compute verification message** — `SHA256(authenticatorData || SHA256(clientData))`
10. **Verify P-256 signature** — `secp256r1_verify(pub_key, SHA256(message), signature)`

**Intentionally omitted** (standard blockchain adaptations, following OZ and g2c reference):
- Origin validation — handled by authenticator and dapp frontend
- RP ID hash validation — platform-level security measure
- Signature counter check — Soroban nonce protection makes this redundant
- Extension output verification — not relevant to core auth

---

## Trait Compliance

Fully implements all three OZ `Verifier` trait methods.

```rust
fn verify(e: &Env, hash: Bytes, key_data: Bytes, sig_data: Bytes) -> bool
fn canonicalize_key(e: &Env, key_data: Bytes) -> Bytes
fn batch_canonicalize_key(e: &Env, key_data: Vec<Bytes>) -> Vec<Bytes>
```

Note: `KeyData` and `SigData` are both typed as `Bytes` (not fixed-size), unlike Ed25519 where fixed sizes are known at compile time. WebAuthn key data has a variable-length credential ID suffix, and sig data is an XDR-encoded struct.

---

## Types

### `KeyData` — `Bytes` (variable length, minimum 66 bytes)

```
[0x04][65-byte P-256 uncompressed public key][optional credential ID]
```

- First byte must be `0x04` (uncompressed point prefix)
- Bytes 0–64: the 65-byte secp256r1 public key
- Bytes 65+: credential ID (optional suffix, variable length)

The credential ID is client-side metadata used to identify which credential to use during authentication. It is not part of the cryptographic key identity. `canonicalize_key` strips it.

The factory validates `key_data.len() > 65` and `key_data[0] == 0x04` before account deployment.

### `SigData` — `Bytes` (XDR-encoded `WebAuthnSigData`)

The sig data is the XDR encoding of the `WebAuthnSigData` struct from the OZ library:

```rust
pub struct WebAuthnSigData {
    pub signature: BytesN<64>,         // P-256 signature (r || s, 32 bytes each)
    pub authenticator_data: Bytes,     // Raw authenticator data (≥37 bytes)
    pub client_data: Bytes,            // Raw clientDataJSON bytes
}
```

The contract XDR-decodes this struct at the start of `verify`.

---

## `canonicalize_key`

Strips the credential ID suffix and returns only the 65-byte public key bytes.

```
canonicalize_key(key_data) -> key_data[0..65]
```

This is critical for the smart account's duplicate detection. Two registrations of the same P-256 key with different credential IDs must be detected as the same key and rejected. `canonicalize_key` produces the same 65-byte output for both, enabling deduplication.

Panics with `Error(Contract, #3119)` if `key_data.len() < 65`.

---

## Statelessness

No storage. No constructor. Every call is a pure function of its inputs. The same deployed instance is shared across all accounts.

---

## Workspace Location

```
latch-contracts/
└── latch-verifiers/
    └── webauthn-verifier/
        └── contracts/
            └── webauthn-verifier/
                └── src/
                    ├── lib.rs
                    └── test.rs
```

The implementation delegates entirely to `stellar_accounts::verifiers::webauthn`. The contract is a thin wrapper that XDR-decodes the inputs and calls the library. The g2c reference at `latch/reference/g2c/contracts/webauthn-verifier/src/contract.rs` is the direct model.

---

## Implementation Skeleton

```rust
#[contract]
pub struct WebAuthnVerifier;

#[contractimpl]
impl Verifier for WebAuthnVerifier {
    type KeyData = Bytes;
    type SigData = Bytes;

    fn verify(e: &Env, hash: Bytes, key_data: Bytes, sig_data: Bytes) -> bool {
        let sig_struct = WebAuthnSigData::from_xdr(e, &sig_data)
            .expect("sig_data must be valid WebAuthnSigData");

        let pub_key: BytesN<65> = extract_from_bytes(e, &key_data, 0..65)
            .expect("key_data must contain a 65-byte public key");

        webauthn::verify(e, &hash, &pub_key, &sig_struct)
    }

    fn canonicalize_key(e: &Env, key_data: Bytes) -> Bytes {
        webauthn::canonicalize_key(e, &key_data)
    }

    fn batch_canonicalize_key(e: &Env, key_data: Vec<Bytes>) -> Vec<Bytes> {
        webauthn::batch_canonicalize_key(e, &key_data)
    }
}
```

---

## Test Plan

### `verify` — valid WebAuthn assertion
- Generate a P-256 keypair
- Construct valid `authenticatorData` with UP + UV flags set
- Construct `clientDataJSON` with `type: "webauthn.get"` and `challenge: base64url(payload_hash)`
- Compute `SHA256(authenticatorData || SHA256(clientDataJSON))` and sign with P-256 key
- Build `WebAuthnSigData`, XDR-encode it
- Call `verify(hash, key_data, sig_data)` — must return `true`

### `verify` — wrong challenge
- Use a different payload hash in the challenge field
- Must panic with `Error(Contract, #3114)`

### `verify` — wrong type field
- Set `type: "webauthn.create"` in client data JSON
- Must panic with `Error(Contract, #3113)`

### `verify` — UP flag not set
- Construct authenticator data with UP bit cleared
- Must panic with `Error(Contract, #3116)`

### `verify` — UV flag not set
- Construct authenticator data with UV bit cleared
- Must panic with `Error(Contract, #3117)`

### `verify` — invalid BE/BS state (BE=0, BS=1)
- Set BS bit but not BE bit in authenticator data flags
- Must panic with `Error(Contract, #3118)`

### `verify` — authenticator data too short
- Pass authenticator data shorter than 37 bytes
- Must panic with `Error(Contract, #3115)`

### `verify` — client data too long
- Pass client data JSON exceeding 1024 bytes
- Must panic with `Error(Contract, #3111)`

### `verify` — malformed client data JSON
- Pass invalid JSON bytes as client data
- Must panic with `Error(Contract, #3112)`

### `verify` — corrupted signature
- Valid ceremony, corrupt one byte of the signature
- Must panic with `Error(Crypto, InvalidInput)`

### `canonicalize_key` — strips credential ID suffix
- Pass 65-byte pubkey + 16-byte credential ID
- Returned `Bytes` must equal only the 65-byte pubkey

### `canonicalize_key` — two registrations of same key, different credential ID
- Same 65-byte pubkey, different credential ID suffix
- Both must produce identical canonical output

### `canonicalize_key` — short input fails
- Pass fewer than 65 bytes
- Must panic with `Error(Contract, #3119)`

### `batch_canonicalize_key` — preserves order
- Pass three keys with credential ID suffixes
- Output must have length 3, each entry equal to the first 65 bytes of the corresponding input

---

## Relationship to Other Verifiers

| | Ed25519 Phantom | WebAuthn |
|--|--|--|
| Curve | Ed25519 | secp256r1 (P-256) |
| Key format | 32 bytes raw | 65+ bytes (pubkey + credential ID) |
| Sig format | `BytesN<64>` directly | XDR-encoded `WebAuthnSigData` struct |
| Signing convention | `prefix + hex(hash)` | Challenge embedded in clientDataJSON |
| Host builtin | `ed25519_verify` | `secp256r1_verify` |
| Prefix needed | Yes (Phantom constraint) | No (base64url challenge binding) |
| Delegation to OZ lib | Partial (`canonicalize_key` only) | Full |

---

## What This Is Not

- Not responsible for origin or RP ID validation. Those are omitted intentionally per the standard blockchain adaptation.
- Not responsible for credential registration. This verifier only handles authentication assertions (`webauthn.get`), not registration ceremonies (`webauthn.create`).
- Not coupled to any specific authenticator. Any device that produces a valid WebAuthn assertion with a P-256 key works.
- Not responsible for replay protection. The Soroban auth framework handles that at the host level.
