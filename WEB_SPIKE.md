# Web Dev Spike: Factory Onboarding for G-Address and WebAuthn Users

## Goal

Give the web developer one narrow spike that proves the current Latch account-creation stack works end to end.

This spike must prove two onboarding modes through the new factory:

- an existing Stellar `G...` account holder can create a smart account through a delegated signer
- a passkey user can create a smart account through a real WebAuthn verifier

This spike is about account creation and deterministic address derivation first. It is not yet the full production verifier rollout.

## What Is Under Test

Contracts we own and want the web developer to integrate against:

- `/Users/user/SuperFranky/latch-contracts/latch-account-factory/contracts/factory-contract`
- `/Users/user/SuperFranky/latch-contracts/latch-smart-account`

Temporary reference contract we will use only for the real passkey path:

- `/Users/user/SuperFranky/latch/reference/g2c/contracts/webauthn-verifier`

Temporary placeholder singleton for unused verifier and policy slots:

- `/Users/user/SuperFranky/latch-contracts/latch-account-factory/contracts/dummy-singleton`

## Important Design Constraint

The factory does not deploy verifier contracts itself in the current implementation.
It expects addresses for already-deployed singleton contracts at construction time.

That means this spike has two different deployment shapes:

- the smart-account contract is installed as Wasm code and referenced by hash
- verifier and policy contracts are deployed first and passed to the factory as addresses

## Contracts to Build

### 1. Latch smart account

Path:

- `/Users/user/SuperFranky/latch-contracts/latch-smart-account`

Build:

```bash
cd /Users/user/SuperFranky/latch-contracts/latch-smart-account
cargo build --target wasm32v1-none --release
```

Expected artifact:

- `/Users/user/SuperFranky/latch-contracts/latch-smart-account/target/wasm32v1-none/release/smart_account.wasm`

Use:

- install this Wasm and capture the returned `smart_account_wasm_hash`
- do not deploy this contract directly for the spike

### 2. Latch factory

Path:

- `/Users/user/SuperFranky/latch-contracts/latch-account-factory/contracts/factory-contract`

Build:

```bash
cd /Users/user/SuperFranky/latch-contracts/latch-account-factory
cargo build --target wasm32v1-none --release -p factory-contract -p dummy-singleton
```

Expected artifacts:

- `/Users/user/SuperFranky/latch-contracts/latch-account-factory/target/wasm32v1-none/release/factory_contract.wasm`
- `/Users/user/SuperFranky/latch-contracts/latch-account-factory/target/wasm32v1-none/release/dummy_singleton.wasm`

Use:

- deploy `factory_contract.wasm`
- deploy `dummy_singleton.wasm` as many times as needed for unused singleton slots

### 3. Real WebAuthn verifier

Path:

- `/Users/user/SuperFranky/latch/reference/g2c/contracts/webauthn-verifier`

Build:

```bash
cd /Users/user/SuperFranky/latch/reference/g2c
cargo build --target wasm32v1-none --release -p g2c-webauthn-verifier
```

Expected artifact:

- `/Users/user/SuperFranky/latch/reference/g2c/target/wasm32v1-none/release/g2c_webauthn_verifier.wasm`

Use:

- deploy this contract once
- pass its deployed address into the factory constructor as `webauthn_verifier`

## Deployment Order

Use local Soroban first.
The developer can use Stellar CLI or an existing deploy script, but the order and arguments should stay exactly like this.

### CLI skeleton

These commands are templates.
Replace `local` and `alice` with the network and source account the developer is actually using.

Install Latch smart-account Wasm:

```bash
stellar contract install \
  --wasm /Users/user/SuperFranky/latch-contracts/latch-smart-account/target/wasm32v1-none/release/smart_account.wasm \
  --source alice \
  --network local
```

Deploy singleton contracts:

```bash
stellar contract deploy \
  --wasm /Users/user/SuperFranky/latch/reference/g2c/target/wasm32v1-none/release/g2c_webauthn_verifier.wasm \
  --source alice \
  --network local
```

```bash
stellar contract deploy \
  --wasm /Users/user/SuperFranky/latch-contracts/latch-account-factory/target/wasm32v1-none/release/dummy_singleton.wasm \
  --source alice \
  --network local
```

Deploy the factory with constructor args:

```bash
stellar contract deploy \
  --wasm /Users/user/SuperFranky/latch-contracts/latch-account-factory/target/wasm32v1-none/release/factory_contract.wasm \
  --source alice \
  --network local \
  -- \
  --smart-account-wasm-hash <SMART_ACCOUNT_WASM_HASH> \
  --ed25519-verifier <DUMMY_ED25519_VERIFIER_ADDRESS> \
  --secp256k1-verifier <DUMMY_SECP256K1_VERIFIER_ADDRESS> \
  --webauthn-verifier <WEBAUTHN_VERIFIER_ADDRESS> \
  --threshold-policy <DUMMY_THRESHOLD_POLICY_ADDRESS>
```

### Step 1. Install Latch smart-account Wasm

Install:

- `smart_account.wasm`

Capture:

- `SMART_ACCOUNT_WASM_HASH`

Expected result:

- a valid Wasm hash that the factory can use in `deploy_v2`

### Step 2. Deploy singleton contracts

Deploy these contract instances:

- one real `g2c_webauthn_verifier`
- one `dummy_singleton` for `ed25519_verifier`
- one `dummy_singleton` for `secp256k1_verifier`
- one `dummy_singleton` for `threshold_policy`

Capture:

- `WEBAUTHN_VERIFIER_ADDRESS`
- `DUMMY_ED25519_VERIFIER_ADDRESS`
- `DUMMY_SECP256K1_VERIFIER_ADDRESS`
- `DUMMY_THRESHOLD_POLICY_ADDRESS`

Expected result:

- all four addresses are executable contracts
- the factory constructor will reject fake or undeployed addresses, so this step must be real

### Step 3. Deploy the factory

Deploy `factory_contract.wasm` with constructor args in this exact order:

```text
smart_account_wasm_hash: BytesN<32>
ed25519_verifier: Address
secp256k1_verifier: Address
webauthn_verifier: Address
threshold_policy: Address
```

For this spike, use:

```text
smart_account_wasm_hash = SMART_ACCOUNT_WASM_HASH
ed25519_verifier = DUMMY_ED25519_VERIFIER_ADDRESS
secp256k1_verifier = DUMMY_SECP256K1_VERIFIER_ADDRESS
webauthn_verifier = WEBAUTHN_VERIFIER_ADDRESS
threshold_policy = DUMMY_THRESHOLD_POLICY_ADDRESS
```

Expected result:

- factory deploy succeeds
- `get_verifier(WebAuthn)` returns the real WebAuthn verifier address
- `get_verifier(Ed25519)` and `get_verifier(Secp256k1)` return dummy singleton addresses
- `get_threshold_policy()` returns the dummy threshold policy address

## Factory Input Types the Web Client Must Build

The web client should build these contract-level types.

### Signer kinds

```rust
enum SignerKind {
    Ed25519,
    Secp256k1,
    WebAuthn,
}
```

### External signer

```rust
struct ExternalSignerInit {
    signer_kind: SignerKind,
    key_data: Bytes,
}
```

### Account signer

```rust
enum AccountSignerInit {
    Delegated(Address),
    External(ExternalSignerInit),
}
```

### Account init params

```rust
struct AccountInitParams {
    signers: Vec<AccountSignerInit>,
    threshold: Option<u32>,
    account_salt: BytesN<32>,
}
```

## Spike Flow A: Existing Stellar User with a G-Address

### Purpose

Prove that an existing Stellar account holder can create a Latch smart account without using a verifier-backed external wallet path.

### Required input

- one valid Stellar account address represented as Soroban `Address`
- one random `account_salt` of exactly 32 bytes

### Params to send

Conceptual shape:

```rust
AccountInitParams {
    signers: vec![
        AccountSignerInit::Delegated(g_address)
    ],
    threshold: None,
    account_salt: random_32_bytes,
}
```

TypeScript-friendly shape:

```ts
const params = {
  signers: [
    {
      tag: "Delegated",
      values: [gAddress],
    },
  ],
  threshold: null,
  account_salt: random32ByteSalt,
};
```

### Calls to make

1. Call `get_account_address(params)`
2. Call `get_account_address(params)` again
3. Call `create_account(params)`
4. Call `create_account(params)` again
5. Repeat with a different `account_salt`

### Expected results

The developer should prove all of these:

- the first and second `get_account_address` calls return the same address
- the first `create_account` returns exactly that same precomputed address
- the second `create_account` returns the same address again and does not create a second account
- changing only `account_salt` changes the derived account address
- the returned account address is an executable contract after creation

### Negative checks

The developer should also show:

- zero signers is rejected
- `threshold = Some(2)` with one delegated signer is rejected

## Spike Flow B: Passkey User with WebAuthn

### Purpose

Prove that a browser passkey can be used to create a Latch smart account through the factory using a real verifier contract.

### WebAuthn key format

The current verifier and factory expect:

- first 65 bytes: uncompressed P-256 public key
- remaining bytes: credential ID

So:

```text
key_data = p256_uncompressed_pubkey_65_bytes || credential_id_bytes
```

Factory validation rules that must be satisfied:

- total length must be greater than 65 bytes
- first byte must be `0x04`

### Required input

- a real browser passkey registration or existing passkey
- extracted uncompressed P-256 public key
- extracted credential ID
- one random `account_salt` of exactly 32 bytes

### Params to send

Conceptual shape:

```rust
AccountInitParams {
    signers: vec![
        AccountSignerInit::External(ExternalSignerInit {
            signer_kind: SignerKind::WebAuthn,
            key_data,
        })
    ],
    threshold: None,
    account_salt: random_32_bytes,
}
```

TypeScript-friendly shape:

```ts
const params = {
  signers: [
    {
      tag: "External",
      values: [
        {
          signer_kind: "WebAuthn",
          key_data: encodedKeyData,
        },
      ],
    },
  ],
  threshold: null,
  account_salt: random32ByteSalt,
};
```

### Calls to make

1. Register or load a passkey in the browser
2. Extract and encode `key_data`
3. Call `get_account_address(params)`
4. Call `get_account_address(params)` again
5. Call `create_account(params)`
6. Call `create_account(params)` again
7. Repeat with a different `account_salt`

### Expected results

The developer should prove all of these:

- passkey registration or lookup succeeds in the browser
- `key_data` is encoded as `65-byte uncompressed pubkey || credential ID`
- the first and second `get_account_address` calls return the same address
- the first `create_account` returns exactly that same precomputed address
- the second `create_account` returns the same address again and does not create a second account
- changing only `account_salt` changes the derived account address
- the returned account address is an executable contract after creation

### Negative checks

The developer should also show:

- WebAuthn `key_data` shorter than 66 bytes is rejected
- WebAuthn `key_data` with a first byte other than `0x04` is rejected

## Important Scope Limit

For this spike, keep WebAuthn account creation single-signer only.

Do not attempt any of these yet:

- delegated + WebAuthn multisig
- WebAuthn + Ed25519 multisig
- WebAuthn + Secp256k1 multisig

Reason:

- the current spike uses a dummy threshold-policy contract for the policy slot
- multisig account creation should wait until a real threshold-policy contract is wired in

## Why Dummy Singletons Are Acceptable Here

Dummy singletons are acceptable only because:

- delegated single-signer flow does not need any verifier contract
- single-signer WebAuthn flow only needs the real `webauthn_verifier`
- single-signer flows do not install the threshold policy

Dummy singletons are not acceptable for:

- real Ed25519 account creation
- real Secp256k1 account creation
- any multisig flow that needs threshold-policy installation

## Deliverable

The web developer should deliver one small local-first test surface with two flows:

- `Existing Stellar User`
- `Passkey User`

Minimum actions:

- `Generate Salt`
- `Get Account Address`
- `Create Account`

Minimum debug output:

- chosen onboarding mode
- signer summary
- encoded `account_salt`
- encoded `key_data` for WebAuthn
- precomputed account address
- returned account address
- whether the created address is executable

## Final Pass Criteria

This spike is complete when all of the following are true:

- the developer can deploy the exact contract set above
- the factory constructor is wired with the correct Wasm hash and singleton addresses
- delegated G-address onboarding works end to end
- WebAuthn onboarding works end to end with a real verifier
- idempotency is proven for both flows
- `account_salt` multiplicity is proven for both flows
- the developer documents any client-side encoding details needed for `Address`, `Bytes`, and `BytesN<32>`

## What This Does Not Prove Yet

This spike does not yet prove:

- final Latch Ed25519 verifier
- final Latch Secp256k1 verifier
- final threshold-policy integration
- final multi-verifier production architecture

Those belong to the separate engineering spike.
