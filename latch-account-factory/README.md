# Latch Account Factory

A deterministic, idempotent smart account factory for Soroban. Validates and canonicalizes signer inputs, derives account addresses before deployment, and deploys smart account instances against pre-deployed shared verifier and policy contracts.

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Workspace Structure](#workspace-structure)
- [Public Interface](#public-interface)
- [Key Concepts](#key-concepts)
  - [Signer Kinds](#signer-kinds)
  - [Address Derivation](#address-derivation)
  - [Singleton Contracts](#singleton-contracts)
  - [Threshold Policy](#threshold-policy)
  - [Account Multiplicity](#account-multiplicity)
- [Validation Rules](#validation-rules)
- [Storage](#storage)
- [Events](#events)
- [Security Properties](#security-properties)
- [Non-Goals](#non-goals)
- [Development](#development)
- [Testing](#testing)

---

## Architecture Overview

```
  (deployed before factory)
  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐
  │ ed25519-verifier │  │secp256k1-verifier│  │webauthn-verifier │  │threshold-policy  │
  └────────┬─────────┘  └────────┬─────────┘  └────────┬─────────┘  └────────┬─────────┘
           │ address              │ address              │ address              │ address
           └──────────────────────┴──────────────────────┴──────────┬──────────┘
                                                                     │ passed in at construction
                                                          ┌──────────▼──────────┐
caller ──────────────────────────────────────────────────▶│  Factory Contract   │
                                                          │                     │
                                                          │  - validates input  │
                                                          │  - derives address  │
                                                          │  - deploys account  │
                                                          └──────────┬──────────┘
                                                                     │ deploy_v2
                                                          ┌──────────▼──────────┐
                                                          │   Smart Account     │
                                                          │   (per user)        │
                                                          │                     │
                                                          │ Signer::External(   │
                                                          │   verifier_addr,    │──▶ verifier.verify(...)
                                                          │   key_data          │
                                                          │ )                   │
                                                          └─────────────────────┘
```

The factory is the **only** deployment path for Latch smart accounts. The four singleton contracts (three verifiers + threshold policy) are deployed independently before the factory and passed in as addresses at construction. The factory only ever deploys smart account instances — one per user.

The factory itself holds no user state. All user-specific data lives in the deployed smart account contracts.

---

## Workspace Structure

```
latch-account-factory/
├── contracts/
│   ├── factory-contract/          # Main factory contract
│   │   ├── src/
│   │   │   ├── lib.rs             # Contract logic
│   │   │   └── test.rs            # Unit + integration tests
│   │   └── testdata/              # Compiled wasm stubs for tests
│   │       ├── dummy_account.wasm
│   │       └── dummy_singleton.wasm
│   ├── dummy-account/             # Minimal account stub (test only)
│   └── dummy-singleton/           # Minimal no-op stub (test only)
├── Cargo.toml                     # Workspace definition
└── README.md
```

**Related workspaces** (separate root-level workspaces, not members here):

| Workspace | Contents |
|---|---|
| `latch-smart-account/` | The smart account contract itself |
| `latch-verifiers/` | Ed25519, Secp256k1, WebAuthn verifier contracts |
| `latch-threshold-policy/` | The simple threshold policy contract |

The behavioral spec lives at [`../factory-spec.md`](../factory-spec.md).

---

## Public Interface

### Constructor

```rust
fn __constructor(
    env: Env,
    smart_account_wasm_hash: BytesN<32>,
    ed25519_verifier: Address,
    secp256k1_verifier: Address,
    webauthn_verifier: Address,
    threshold_policy: Address,
)
```

Called once at factory deployment. Stores the config as immutable instance storage. Calling again panics with `AlreadyInitialized`.

The verifier and policy contracts must be **deployed before the factory**. Their addresses are passed in and stored — the factory will never deploy them. Only `smart_account_wasm_hash` is a hash, because the factory deploys a new smart account instance per user on `create_account`.

---

### `get_account_address`

```rust
fn get_account_address(env: Env, params: AccountInitParams) -> Address
```

Pure computation. Validates and canonicalizes `params`, then returns the deterministic address the account would be deployed to. **No state changes, no deployment.** Use this to precompute the address before calling `create_account`, or to derive an existing account's address from its parameters.

---

### `create_account`

```rust
fn create_account(env: Env, params: AccountInitParams) -> Address
```

Validates, canonicalizes, derives the account address, and deploys it. If an account already exists at that address, returns it immediately without re-deploying (idempotent). Lazily deploys required verifier singletons and the threshold policy singleton on first use.

Emits `AccountCreated { account: Address }` on first deployment only.

---

### `get_verifier`

```rust
fn get_verifier(env: Env, signer_kind: SignerKind) -> Address
```

Returns the address of the verifier for the given signer kind, as stored in the factory config. The verifier is always deployed — it was a prerequisite for deploying the factory. Useful for clients that need to display or reference verifier addresses.

---

### `get_threshold_policy`

```rust
fn get_threshold_policy(env: Env) -> Address
```

Returns the address of the threshold policy, as stored in the factory config. Like the verifiers, it is always deployed before the factory.

---

## Key Concepts

### Signer Kinds

Three signer kinds are supported in v1:

| Kind | `key_data` format | Key length | Notes |
|---|---|---|---|
| `Ed25519` | 32-byte raw public key | 32 bytes exactly | Standard Stellar/SSH key format |
| `Secp256k1` | Uncompressed public key | 65 bytes, first byte `0x04` | EVM-compatible, recovery-based verification |
| `WebAuthn` | 65-byte P-256 pubkey + credential ID | > 65 bytes, first byte `0x04` | Covers passkeys, Touch ID, Face ID, hardware keys |

The factory performs **shape validation only** — it checks lengths and prefixes but does not verify signatures. Cryptographic verification is the verifier contract's responsibility.

**WebAuthn covers:** Apple Touch ID, Apple Face ID, Android biometrics, Android PIN, Windows Hello, YubiKey, and any device that implements the WebAuthn standard. The underlying cryptographic primitive is always P-256 (secp256r1). The biometric or PIN is just the local unlock mechanism — it never leaves the device.

---

### Address Derivation

Account addresses are **deterministic** — derived from parameters, not from caller identity. The same parameters always produce the same address, regardless of who calls the factory or when.

The derivation process:

1. Canonicalize the signer list (sort + deduplicate)
2. Normalize the effective threshold
3. Hash a structured preimage using SHA-256:

```
LatchAccountSaltV1 = SHA256(
  "latch.factory.account.v1"  ||
  account_salt                ||   // 32 bytes
  signer_count                ||   // 4 bytes big-endian
  for each canonical signer:
    signer_kind_code          ||   // 1 byte (0x01/0x02/0x03)
    key_data_length           ||   // 4 bytes big-endian
    key_data                  ||   // variable
  effective_threshold              // 4 bytes big-endian
)
```

Signer kind codes (stable, part of the address derivation surface — must not change in v1):

| Kind | Code |
|---|---|
| `Ed25519` | `0x01` |
| `Secp256k1` | `0x02` |
| `WebAuthn` | `0x03` |

The final account address is then:

```
SmartAccountAddress = DeployAddress(
  deployer = factory_address,
  salt     = LatchAccountSaltV1,
  wasm     = smart_account_wasm_hash
)
```

This means:
- Signer order does **not** affect the address (signers are sorted first)
- `None` and `Some(1)` threshold produce the same address for single-signer accounts (both normalize to `1`)
- Caller identity, relayer identity, and fee payer identity do **not** affect the address

---

### Singleton Contracts

Verifiers and the threshold policy are **singletons** — one instance shared across all accounts on the network. They hold no per-user state; they are pure stateless logic contracts.

They are **deployed independently before the factory** and their addresses are passed into the factory constructor. The factory never deploys them — it simply reads their addresses from config and passes them to each new smart account at creation time.

This means the deployment order is:

```
1. stellar contract install  (upload smart account wasm, get hash)
2. stellar contract deploy   ed25519-verifier
3. stellar contract deploy   secp256k1-verifier
4. stellar contract deploy   webauthn-verifier
5. stellar contract deploy   threshold-policy
6. stellar contract deploy   factory  (pass hash + 4 addresses)
```

---

### Threshold Policy

The `SimpleThresholdPolicy` from the OpenZeppelin Stellar Contracts library is used. It enforces M-of-N authorization: a transaction must be signed by at least `threshold` of the account's registered signers.

The threshold policy is installed **per account** with the threshold value at account creation. Each account's threshold is stored in the policy contract's **persistent storage**, keyed by `(account_address, context_rule_id)`.

**Important caveat (from OZ):** The policy threshold is not automatically updated when signers are added or removed from an account after creation. If the threshold becomes unreachable (e.g. signers were removed leaving fewer than the threshold), the account is permanently locked. To avoid this, call `set_threshold()` on the policy contract before removing signers or after adding them.

The threshold policy is only deployed and installed for accounts with 2 or more signers. Single-signer accounts use no policy — the signer is the sole authority.

---

### Account Multiplicity

The same signer set can create multiple independent accounts by using different `account_salt` values:

```
signer: [Ed25519(pubkey_A)], threshold: None, account_salt: [0x01...] → Account 1
signer: [Ed25519(pubkey_A)], threshold: None, account_salt: [0x02...] → Account 2
```

The `account_salt` is a **protocol input**, not a display label. Product code should:
- Generate a random 32-byte salt for normal account creation
- Store the salt client-side or server-side if the user needs to recover the address
- Keep nicknames, themes, or labels as separate metadata — not baked into the salt

---

## Validation Rules

| Check | Error |
|---|---|
| Zero signers | `NoSigners` |
| Duplicate `(signer_kind, key_data)` | `DuplicateSigner` |
| Multisig with no threshold | `MissingThreshold` |
| Threshold `= 0` or `> n` | `InvalidThreshold` |
| Single-signer with threshold `> 1` | `InvalidThreshold` |
| Ed25519 `key_data.len() != 32` | `InvalidEd25519Key` |
| Secp256k1 `key_data.len() != 65` or first byte `!= 0x04` | `InvalidSecp256k1Key` |
| WebAuthn `key_data.len() <= 65` or first byte `!= 0x04` | `InvalidWebAuthnKey` |
| Config not set (factory not initialized) | `MissingConfig` |
| Constructor called twice | `AlreadyInitialized` |

---

## Storage

The factory uses **instance storage** only.

| Key | Type | Contents |
|---|---|---|
| `DataKey::Config` | `FactoryConfig` | Smart account wasm hash + four pre-deployed singleton addresses |

TTL is extended to 30 days (`518400` ledgers) on every call that reads config, and also in the constructor. This is done in `get_config()`, which is called by every public function that touches state.

The factory stores **nothing** about deployed accounts. Account addresses are recomputed deterministically on demand from parameters.

---

## Events

| Event | Emitted when | Data |
|---|---|---|
| `AccountCreated { account: Address }` | A new account is deployed | The deployed account's address |

The event is emitted only on actual first deployment. The idempotent path (account already exists) emits nothing.

---

## Security Properties

**Caller identity does not affect account address.** The deployment salt is derived entirely from canonical account parameters. A relayer or fee payer cannot change which address an account lands at.

**Malformed input is rejected before any deployment.** All validation and canonicalization happens before `deploy_v2` is called. There is no partial-deployment state.

**Account creation is atomic.** `deploy_v2` runs the smart account constructor in the same transaction. The account either exists with its full signer and policy configuration or does not exist at all.

**Verifier contracts are stateless.** They hold no per-user state. An attacker cannot corrupt verifier state to compromise other accounts.

**Config is immutable.** There is no admin function to update the config. A different set of contracts requires deploying a new factory. This prevents an operator from silently changing the account logic deployed to new users.

**No private keys are ever stored or passed.** The factory only handles public key material (`key_data`). Private keys never appear in any transaction argument or storage slot.

**TTL archival cannot corrupt state.** The config TTL is extended on every call. If the factory is completely unused for 30 days, the config is archived but restorable — the factory does not hold any user funds or time-sensitive state, so archival has no security impact beyond temporary unavailability.

### Potential Risks to Review

- **Threshold drift after signer set changes:** If a deployed account's signer set is modified post-creation, the threshold policy is not automatically updated. This is an account-level concern, not a factory concern, but auditors should verify the account contract's signer management functions enforce safe threshold transitions.
- **Singleton contract trust:** The verifier and policy addresses passed to the constructor are trusted at deployment time. An auditor should verify that these addresses point to the correct audited contracts — there is no on-chain enforcement of what code lives at those addresses after the fact.
- **No upgrade path:** The factory cannot be upgraded. If a bug is found in any singleton or the smart account wasm, a new factory must be deployed. There is no migration path for accounts already deployed under the old factory.

---

## Non-Goals

The factory does not handle:

- Signature verification (that is the verifier contracts' job)
- Recovery flows
- Session keys or temporary signers
- Spending limits
- Account upgrades or signer rotation after creation
- Bridge or funding logic
- Private key custody of any kind

---

## Development

### Prerequisites

```bash
# Rust toolchain
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Stellar CLI (v25.2.0+)
cargo install --locked stellar-cli
```

### Build

```bash
# Build the factory contract
stellar contract build --package factory-contract

# Build test stubs (needed before running tests for the first time,
# or after changing dummy-account / dummy-singleton)
stellar contract build --package dummy-account
stellar contract build --package dummy-singleton
cp target/wasm32v1-none/release/dummy_account.wasm contracts/factory-contract/testdata/
cp target/wasm32v1-none/release/dummy_singleton.wasm contracts/factory-contract/testdata/
```

### Run Tests

```bash
cargo test
```

---

## Testing

The test suite has two layers:

### Layer 1 — Validation tests (zero wasm required)

These use `install_factory_stub` which registers the factory with zero hashes. They only call `get_account_address` and never reach `deploy_v2`, so no real wasm is needed.

Covers: duplicate signers, threshold edge cases (0, > n, missing), all three invalid key shapes, signer order invariance, salt changes address, key data changes address.

### Layer 2 — Deployment and config tests (real wasm required)

These use `install_factory` which registers the four singleton stubs with `env.register(dummy_singleton::WASM, ())`, uploads `dummy_account.wasm` as the account wasm hash, and registers the factory with the real addresses and hash. Returns a `FactorySetup` struct so tests can assert against the known singleton addresses.

Covers:

| Test | What it verifies |
|---|---|
| `get_verifier_returns_stored_addresses` | All three verifier addresses match what was passed in |
| `get_threshold_policy_returns_stored_address` | Policy address matches what was passed in |
| `each_verifier_address_is_distinct` | Three verifiers are different contracts |
| `create_account_deploys_at_precomputed_address` | `get_account_address` and `create_account` agree |
| `create_account_deploys_contract_at_address` | Deployed address has executable code |
| `create_account_emits_account_created_event` | `AccountCreated` event is emitted |
| `create_account_is_idempotent` | Second call returns same address, emits no event |
| `create_account_with_secp256k1_signer` | Secp256k1 full deployment path |
| `create_account_with_webauthn_signer` | WebAuthn full deployment path |
| `create_account_multisig_deploys_at_precomputed_address` | Multisig address matches precomputed |
| `create_account_mixed_signers_multisig` | All three signer kinds in one account |

### Regenerating test wasm

The wasm stubs in `testdata/` are compiled outputs. After any change to `dummy-account` or `dummy-singleton`:

```bash
stellar contract build --package dummy-account
stellar contract build --package dummy-singleton
cp target/wasm32v1-none/release/dummy_account.wasm contracts/factory-contract/testdata/
cp target/wasm32v1-none/release/dummy_singleton.wasm contracts/factory-contract/testdata/
```

The stubs are committed to the repo so CI does not need a wasm build step to run `cargo test`.
