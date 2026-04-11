# Latch Contracts v1 Architecture Plan

## Summary

Build `latch-contracts` as the production Soroban workspace for Latch’s auth layer, starting with the account-creation foundation but keeping the full wallet architecture intact.

This first milestone will include:
- A production `smart-account` contract based on OpenZeppelin’s Soroban smart-account model
- A shared `factory` contract for deterministic account creation
- Three shared verifier contracts: `ed25519`, `secp256k1`, and `webauthn`
- Single-signer and multi-signer account creation flows
- Full-wallet default authorization on account creation

This milestone will **not** include the bridge proxy contract yet, but the factory must be bridge-ready by exposing deterministic address derivation and idempotent creation.

## Implementation Changes

### 1. Workspace shape

Replace the placeholder workspace with these contracts:
- `smart-account`
- `factory`
- `verifiers/ed25519`
- `verifiers/secp256k1`
- `verifiers/webauthn`

Do not add the bridge contract in this milestone.
Do not keep the current demo-only “counter-scoped initialize” model as the production contract shape.

### 2. Smart account contract

Use OZ’s Soroban smart-account framework as the core model:
- Implement `CustomAccountInterface`
- Implement `SmartAccount`
- Implement `ExecutionEntryPoint`

Account behavior:
- Constructor takes `signers: Vec<Signer>` and `policies: Map<Address, Val>`
- Constructor creates exactly one initial `ContextRuleType::Default` rule named `"default"`
- Initial rule gives full wallet control to the provided signers/policies
- All rule/signer/policy mutation methods require `current_contract_address().require_auth()`
- `execute(target, target_fn, target_args)` is the generic wallet execution entry point

Auth model:
- Store external signers as `Signer::External(verifier_address, key_data)`
- Support only external signers in milestone 1
- Do not introduce custom Latch auth logic outside OZ’s `do_check_auth`
- Keep the account stateless beyond OZ rule/policy storage and any attached policy state

### 3. Verifier contracts

Build all three as stateless shared verifier contracts implementing OZ’s `Verifier` trait.

`ed25519-verifier`
- Reuse the current Phantom-compatible message scheme
- Verify `Stellar Smart Account Auth:\n<hex(payload_hash)>`
- Input shape remains equivalent to the current demo’s `prefixed_message + signature`

`secp256k1-verifier`
- Verify EIP-191 / `personal_sign` style signatures from Ethereum wallets
- Use the same human-readable payload message format as Ed25519 for UX consistency
- Recover/validate against the supplied secp256k1 public-key/address key data format chosen by the verifier implementation
- Keep verifier-specific encoding isolated to the verifier contract and SDK packaging layer

`webauthn-verifier`
- Base this on the local `g2c` reference shape
- Accept WebAuthn assertion data and verify a P-256 signature against the auth payload challenge
- Keep it shared and stateless, not account-specific

### 4. Factory contract

The factory is the starting point and primary milestone deliverable.

Factory responsibilities:
- Deterministically derive a C-address before deployment
- Idempotently create an account if it does not exist
- Return the existing address if already deployed
- Resolve and, if needed, lazy-deploy shared verifier singletons
- Build the account constructor arguments from user-facing account-init params
- Install threshold policy automatically for multi-signer accounts

Factory storage/config:
- Store immutable WASM hashes for:
  - `smart-account`
  - `ed25519-verifier`
  - `secp256k1-verifier`
  - `webauthn-verifier`
  - threshold policy contract if policy is deployed as a contract artifact in this workspace
- Treat verifier deployments as singleton contracts owned by deployment determinism, not by mutable registry state
- Avoid owner/admin mutation in v1; if hashes change, deploy a new factory version

Factory deployment model:
- Use deterministic deployment with `e.deployer().with_current_contract(salt)`
- Compute a canonical salt from account-init params, not from caller address
- Salt input must include:
  - signer kinds
  - canonical verifier selection
  - signer key data
  - threshold config when present
- Canonicalize signer list before hashing so account address is stable regardless of input ordering

Factory API:
- `get_account_address(params) -> Address`
- `create_account(params) -> Address`

`params` must support both:
- Single-signer onboarding
- Multi-signer-at-birth creation

Recommended factory input shape:
- `Vec<ExternalSignerInit>` where each item contains `signer_kind` and `key_data`
- `Option<u32>` threshold

Factory rules:
- `signers.len() >= 1`
- threshold defaults to `1`
- if `signers.len() == 1`, threshold must be `1` and no threshold policy is installed
- if `signers.len() > 1`, threshold is required or defaulted explicitly by the factory, and the threshold policy is installed automatically
- reject duplicate canonical signers
- reject invalid thresholds (`0` or `> signers.len()`)

Verifier deployment behavior:
- Each verifier has a deterministic singleton address derived from the factory contract
- On `create_account`, factory ensures required verifier singleton(s) exist
- Lazy deployment happens only for verifier kinds actually referenced in params

### 5. Policy handling in milestone 1

Milestone 1 supports multisig-at-birth via one threshold policy only:
- Use OZ simple threshold policy for initial multisig accounts
- Do not add custom Latch spending-limit or session-policy contracts in this milestone
- Keep the account and factory interfaces compatible with adding those later through standard `add_policy` flows

This keeps milestone 1 focused on deployability and signer coverage without overloading the first build with policy state machines.

## Public APIs / Interfaces

### Contracts

`smart-account`
- `__constructor(signers, policies)`
- OZ `SmartAccount` surface
- `execute(target, target_fn, target_args)`

`factory`
- `get_account_address(params) -> Address`
- `create_account(params) -> Address`

### New shared init types

Define shared contract-level init types for the factory:
- `SignerKind`
  - `Ed25519`
  - `Secp256k1`
  - `WebAuthn`
- `ExternalSignerInit`
  - `signer_kind`
  - `key_data`
- `AccountInitParams`
  - `signers: Vec<ExternalSignerInit>`
  - `threshold: Option<u32>`

SDKs and frontend should treat the factory’s generic API as the source of truth.
Convenience flows like “create Phantom account” or “create MetaMask account” should be SDK wrappers, not separate on-chain entrypoints.

## Test Plan

### Factory
- Deterministic address is stable for the same canonical params
- Signer ordering does not change derived address
- Different signer kinds or key data produce different addresses
- `create_account` returns the same address when called repeatedly with the same params
- Account is actually deployed at the precomputed address
- Required verifier singleton is deployed once and reused
- Single-signer creation installs no threshold policy
- Multi-signer creation installs threshold policy with correct threshold
- Invalid threshold and duplicate signers are rejected

### Smart account
- Constructor creates one `Default` context rule with expected signers/policies
- Full-wallet default rule authorizes arbitrary contract execution through `execute`
- Rule mutation methods require account auth
- Single-signer auth works for each verifier kind
- Multi-signer auth works when threshold is met and fails when it is not

### Verifiers
- Ed25519 accepts valid Phantom-style signatures and rejects wrong prefix / wrong payload / wrong key
- secp256k1 accepts valid MetaMask-style signatures and rejects wrong message / wrong key / malformed sig
- WebAuthn accepts valid assertions and rejects invalid challenge / malformed client data / wrong key

### End-to-end
- Create Ed25519 account via factory, then authorize a contract call
- Create secp256k1 account via factory, then authorize a contract call
- Create WebAuthn account via factory, then authorize a contract call
- Create multi-signer account with mixed verifier kinds and verify threshold enforcement

## Assumptions and Defaults

- Milestone 1 includes factory + smart account + all three verifier contracts, but not the bridge proxy
- New accounts are created with a full-wallet `Default` context rule, not a limited bootstrap rule
- Factory supports both single-signer and multi-signer account creation in v1
- Multisig-at-birth uses OZ simple-threshold policy only
- No custom spending-limit/session/recovery policies are built in this milestone
- Factory configuration is immutable per deployed factory version; upgrades happen by deploying a new factory, not by mutating the existing one
- Verifiers are shared singleton contracts lazily deployed by the factory
- Account creation must be atomic via constructor args; do not use deploy-then-initialize for production `latch-contracts`
