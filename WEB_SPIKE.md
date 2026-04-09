# Web Spike: Factory + Smart Account Creation

## Goal

Give the web developer a narrow spike that proves the new `latch-account-factory` can create
a real smart account from the browser using signer paths that are available today.

This spike proves:

- the web client can build valid `AccountInitParams`
- the factory derives the expected deterministic account address
- the factory deploys the Latch-native smart account
- two signer paths work end to end: Ed25519 (Phantom) and Delegated (G-address)

## What Is Available Now

| Contract | Status | Location |
|---|---|---|
| Factory | Ready | `latch-contracts/latch-account-factory` |
| Smart account | Ready | `latch-contracts/latch-smart-account` |
| Ed25519 verifier | Ready (testnet) | `latch/latch-demo/contracts/ed25519-verifier` |
| WebAuthn verifier | Not built yet | — |
| Secp256k1 verifier | Not built yet | — |

WebAuthn and Secp256k1 are explicitly out of scope for this spike.

## Signer Paths in Scope

### Path 1: Ed25519 — Phantom wallet

`Signer::External(ed25519_verifier, 32_byte_pubkey)`

The Ed25519 verifier from `latch-demo` is already deployed on testnet. It handles the
Phantom-prefixed auth format (`"Stellar Smart Account Auth:\n" + hex(payload)`).

### Path 2: Delegated — G-address

`Signer::Delegated(g_address)`

No verifier needed. The Soroban host verifies the Stellar keypair signature natively.
This is the primary G-address onboarding path.

## Scope

- the factory from `latch-contracts/latch-account-factory`
- the Latch smart account from `latch-contracts/latch-smart-account`
- the Ed25519 verifier from `latch/latch-demo/contracts/ed25519-verifier`
- a small local web page or script
- no polished UI required
- local Soroban environment first, testnet second

## Contract Set

### Factory

`/Users/user/SuperFranky/latch-contracts/latch-account-factory`

### Smart account

`/Users/user/SuperFranky/latch-contracts/latch-smart-account`

### Ed25519 verifier

`/Users/user/SuperFranky/latch/latch-demo/contracts/ed25519-verifier`

Already deployed on testnet. The verifier expects:
- `key_data`: 32-byte Ed25519 public key
- `sig_data`: XDR-encoded `Ed25519SigData { prefixed_message, signature }`
  where `prefixed_message = "Stellar Smart Account Auth:\n" + hex(payload)`

### WebAuthn/passkey client reference (for later)

`/Users/user/SuperFranky/latch/reference/g2c/packages/passkey-sdk`

Not needed for this spike. Referenced here for when WebAuthn is added.

## End-to-End Flow

### Path 1: Ed25519 (Phantom)

1. Build and deploy the Ed25519 verifier (or use existing testnet deployment).
2. Build and deploy the Latch smart-account Wasm.
3. Deploy the Latch factory with:
   - `smart_account_wasm_hash` pointing to the Latch smart-account Wasm hash
   - `ed25519_verifier` pointing to the deployed Ed25519 verifier
   - other verifier slots filled with placeholder addresses as needed
4. Connect Phantom wallet and read the Ed25519 public key.
5. Build `AccountInitParams` with:
   - one `Ed25519` signer using the Phantom public key as `key_data`
   - `threshold = null`
   - random `account_salt`
6. Call `get_account_address`.
7. Call `create_account`.
8. Confirm returned address matches precomputed address.
9. Confirm the created account is deployed and stores the Ed25519 external signer.

### Path 2: Delegated (G-address)

1. Use the same factory deployment from Path 1.
2. Build `AccountInitParams` with:
   - one `Delegated` signer using the user's G-address
   - `threshold = null`
   - random `account_salt`
3. Call `get_account_address`.
4. Call `create_account`.
5. Confirm returned address matches precomputed address.
6. Confirm the created account stores the G-address as a delegated signer.

## Success Criteria

The spike is successful if the web client demonstrates:

1. `get_account_address` is deterministic — same params, same address every call.
2. `create_account` returns the same address as `get_account_address`.
3. `create_account` called twice with the same params does not create a second account.
4. Changing `account_salt` produces a different address.
5. An Ed25519 signer (Phantom) can create a smart account through the factory.
6. A Delegated signer (G-address) can create a smart account through the factory.
7. The created account was deployed from the factory, not manually.

## What This Spike Does Not Cover

- WebAuthn / passkey signing
- Secp256k1 signing
- Latch-owned verifier contracts (using latch-demo Ed25519 verifier as stand-in)
- Transaction execution through the created account (auth flow, not just deployment)

## Recommended Environment

Local Soroban first, testnet once local is stable.

Suggested setup:

- build the Latch factory
- build the Latch smart-account
- build the Ed25519 verifier (or reuse testnet deployment)
- deploy all locally
- wire the web client against local RPC

## Web Developer Deliverable

- one small page or script that creates accounts through the factory via both signer paths
- one captured example showing deterministic address derivation
- one example showing `account_salt` changes the derived address
- a short note on how `key_data` was extracted from Phantom

## Nice-to-Have

Debug panel showing:

- Phantom public key
- encoded `key_data`
- G-address
- derived account address for each path

## What This Unlocks Next

Once this spike is working, the next contract work is Latch-owned verifiers:

- `latch-verifiers/ed25519`
- `latch-verifiers/secp256k1`
- `latch-verifiers/webauthn`

Once those exist, the `latch-demo` Ed25519 verifier stand-in can be replaced and
the full production architecture is proven end to end.
