# Latch Smart Account

A programmable wallet contract for Soroban. Replaces static private-key authorization with flexible, rule-based multi-signer authorization. Deployed by the Latch Account Factory — one instance per user.

Built on the [OpenZeppelin Stellar Contracts](https://github.com/OpenZeppelin/stellar-contracts) smart account framework.

## Table of Contents

- [What It Is](#what-it-is)
- [How It Fits In the System](#how-it-fits-in-the-system)
- [Public Interface](#public-interface)
- [Key Concepts](#key-concepts)
  - [Context Rules](#context-rules)
  - [Signers](#signers)
  - [Policies](#policies)
  - [Self-Auth Protection](#self-auth-protection)
- [Authorization Flow](#authorization-flow)
- [Security Properties](#security-properties)
- [Non-Goals](#non-goals)
- [Development](#development)
- [Testing](#testing)

---

## What It Is

### For everyone

A Latch Smart Account is a programmable wallet that lives on-chain. Unlike a normal Stellar account — where one private key controls everything — a Latch Smart Account can be controlled by multiple signers of different types: an existing Stellar wallet, a MetaMask wallet, a Face ID passkey, or any combination. The rules for who can authorize what are stored inside the contract and enforced by the Stellar network itself.

### For developers

`LatchSmartAccount` is a Soroban contract that implements three interfaces from the OpenZeppelin Stellar Contracts library:

| Interface | Role |
|---|---|
| `CustomAccountInterface` | Makes the contract a first-class Stellar account — the network calls `__check_auth` to validate signatures |
| `SmartAccount` | Provides context rule management: CRUD for named signer/policy sets |
| `ExecutionEntryPoint` | Exposes an `execute` function so the account can call other contracts with its own authorization |

The contract delegates all authorization logic (`__check_auth`) and all rule management to the OpenZeppelin `stellar-accounts` library. The Latch layer is thin by design: constructor setup and a `batch_add_signer` helper.

### For auditors

The contract is a minimal shim over the OpenZeppelin `stellar-accounts` library. The attack surface introduced by this contract is:

1. The `__constructor`: creates exactly one context rule; validates nothing itself (validation is the factory's job upstream)
2. `batch_add_signer`: calls `smart_account::batch_add_signer` after requiring self-auth
3. `__check_auth`: passes through to `smart_account::do_check_auth` with no pre-processing

All state management, authorization checking, and policy enforcement live in the upstream `stellar-accounts` library at the pinned git revision in `Cargo.toml`. The critical trust boundary is self-auth: every mutation function requires `e.current_contract_address().require_auth()`, meaning the account's own signers must authorize any change to the account's configuration.

---

## How It Fits In the System

```
  ┌───────────────────────────────────────────────────────────────────────┐
  │                        Latch Contracts System                         │
  │                                                                       │
  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐               │
  │  │ ed25519-     │  │ secp256k1-   │  │ webauthn-    │               │
  │  │ verifier     │  │ verifier     │  │ verifier     │               │
  │  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘               │
  │         └─────────────────┴─────────────────┘                        │
  │                           │ addresses passed at construction          │
  │                 ┌─────────▼─────────┐                                │
  │  caller ───────▶│  Account Factory  │                                │
  │                 └─────────┬─────────┘                                │
  │                   deploy_v2│ (one per user)                           │
  │                 ┌─────────▼─────────┐                                │
  │                 │  LatchSmartAccount│ ◀── this contract              │
  │                 │                   │                                │
  │                 │  Context Rules    │                                │
  │                 │  ├ "default"      │──▶ Signer::Delegated → native auth
  │                 │  │  signers       │──▶ Signer::External  → verifier.verify()
  │                 │  │  policies      │──▶ Policy contract   → enforce()
  │                 │  └ ...more rules  │                                │
  │                 └───────────────────┘                                │
  └───────────────────────────────────────────────────────────────────────┘
```

The factory deploys this contract once per user and calls `__constructor` in the same transaction. The account is fully configured — with signers and policies — at the moment it lands on-chain. There is no separate initialization step.

---

## Public Interface

### Constructor

```rust
fn __constructor(env: &Env, signers: Vec<Signer>, policies: Map<Address, Val>)
```

Called once by the factory at deployment. Creates a single context rule:

| Field | Value |
|---|---|
| Type | `ContextRuleType::Default` (applies to all authorization contexts) |
| Name | `"default"` |
| Signers | The `signers` argument from the factory |
| Policies | The `policies` argument from the factory |
| Valid until | `None` (no expiry) |

The factory is responsible for validating signers and policies before calling `deploy_v2`. The constructor trusts its inputs.

---

### `batch_add_signer`

```rust
fn batch_add_signer(env: &Env, context_rule_id: u32, signers: Vec<Signer>)
```

Adds multiple signers to an existing context rule in a single call. Requires self-auth — the account's current signers must authorize this.

---

### Inherited from `SmartAccount`

These functions are provided by the OpenZeppelin library and exposed on the contract via `#[contractimpl(contracttrait)]`:

| Function | Description | Auth required |
|---|---|---|
| `add_context_rule(type, name, valid_until, signers, policies)` | Creates a new named context rule | Self |
| `remove_context_rule(id)` | Removes a context rule | Self |
| `add_signer(context_rule_id, signer)` | Adds one signer to a rule | Self |
| `remove_signer(context_rule_id, signer_id)` | Removes a signer from a rule | Self |
| `add_policy(context_rule_id, policy_address, install_params)` | Attaches a policy contract to a rule | Self |
| `remove_policy(context_rule_id, policy_address)` | Detaches a policy from a rule | Self |
| `get_context_rule(id)` | Returns a context rule by ID | None |
| `get_context_rules_count()` | Returns the number of context rules | None |

---

### Inherited from `ExecutionEntryPoint`

| Function | Description | Auth required |
|---|---|---|
| `execute(contract, function, args)` | Calls another contract on behalf of this account | Self |

---

### `__check_auth` (called by the Stellar runtime, not by users)

```rust
fn __check_auth(
    env: Env,
    signature_payload: Hash<32>,
    signatures: AuthPayload,
    auth_contexts: Vec<Context>,
) -> Result<(), SmartAccountError>
```

The Stellar network calls this function automatically when something in a transaction requires authorization from this account's address. It is never called directly by users or clients.

Delegates entirely to `smart_account::do_check_auth`, which:
1. Matches each `Context` (the thing being authorized) against the account's context rules
2. Verifies the provided signatures against the `signature_payload`
3. Enforces all attached policies

---

## Key Concepts

### Context Rules

A context rule is a named set of signers and policies that governs authorization for a specific scope of actions.

| Field | Type | Description |
|---|---|---|
| `id` | `u32` | Auto-assigned numeric identifier |
| `name` | `String` | Human-readable label (e.g. `"default"`, `"defi-allowance"`) |
| `context_type` | `ContextRuleType` | Which transactions this rule applies to |
| `signers` | `Vec<Signer>` | Who can sign for this rule |
| `policies` | `Vec<Address>` | Which policy contracts enforce additional constraints |
| `valid_until` | `Option<u64>` | Optional ledger expiry for time-limited rules |

**Context rule types:**

| Type | Applies when |
|---|---|
| `ContextRuleType::Default` | No more specific rule matches — acts as a catch-all |
| `ContextRuleType::CallContract(address)` | Authorizing a call to a specific contract address |

Every account starts with exactly one `Default` rule named `"default"`. Additional rules with narrower scopes can be added by the account's own signers after deployment.

---

### Signers

Two signer families are supported:

| Family | Shape | Auth mechanism |
|---|---|---|
| `Signer::Delegated(Address)` | An existing Stellar `G...` account address | Native Stellar account authorization |
| `Signer::External(verifier, key_data)` | A public key verified by an external contract | `verifier.verify(key_data, payload, signature)` |

External signer kinds (determined by which verifier address is referenced):

| Kind | Key format | Use case |
|---|---|---|
| Ed25519 | 32-byte raw public key | Phantom, standard Stellar wallets |
| Secp256k1 | 65-byte uncompressed key (`0x04` prefix) | MetaMask, Rabby, EVM wallets |
| WebAuthn | 65-byte P-256 key + credential ID (`0x04` prefix) | Face ID, Touch ID, Windows Hello, YubiKey |

---

### Policies

A policy is an external contract that enforces additional constraints on authorization. It is called by `do_check_auth` after signatures are verified.

The `Policy` interface requires three functions:

| Function | Called when |
|---|---|
| `enforce(context, signers, rule, account)` | During `__check_auth` — must not panic if the transaction should be allowed |
| `install(params, rule, account)` | When `add_policy` is called — for any setup the policy needs |
| `uninstall(rule, account)` | When `remove_policy` is called — for cleanup |

The Latch system uses the OpenZeppelin `SimpleThresholdPolicy` for multisig accounts. It is deployed as a singleton shared across all accounts and enforces M-of-N signature requirements.

---

### Self-Auth Protection

Every function that mutates the account requires `e.current_contract_address().require_auth()`. This means:

- To change your signers, your current signers must sign the transaction
- To change your policies, your current signers must sign the transaction
- To call other contracts via `execute`, your current signers must sign the transaction

No external address — not the factory, not the Latch backend, not any admin key — can unilaterally modify a deployed account. The account is sovereign from the moment it is deployed.

---

## Authorization Flow

When a transaction that requires this account's authorization is submitted to the network:

```
Transaction submitted
        │
        ▼
Stellar runtime calls __check_auth(payload, signatures, contexts)
        │
        ▼
do_check_auth iterates over auth_contexts
        │
        ├─ For each context, find the matching context rule
        │    └─ Default rule matches if no specific rule applies
        │
        ├─ Verify signatures over payload
        │    ├─ Delegated signers → native Stellar account check
        │    └─ External signers → verifier.verify(key_data, payload, signature)
        │
        └─ Run each policy attached to the matched rule
             └─ Policy.enforce(...) — must not panic if the transaction is allowed
```

---

## Security Properties

**No external admin.** There is no owner key, no upgrade proxy, no multisig admin. The only addresses that can change the account are the account's own registered signers, acting through `__check_auth`.

**Self-auth is enforced on every mutation.** `batch_add_signer`, `add_context_rule`, `add_signer`, `remove_signer`, `add_policy`, `remove_policy`, and `execute` all require self-auth. There is no bypass.

**Authorization logic is in the library, not in this contract.** `do_check_auth` is an upstream OpenZeppelin function at a pinned revision. This contract introduces no custom auth logic.

**No state is held about other accounts.** This contract's storage contains only its own context rules, signers, and policies. It cannot read or write the state of other deployed accounts.

**Verifiers are stateless.** Verifier contracts hold no per-user state. A compromised verifier cannot retroactively modify what past signatures were accepted.

### Risks to Review

- **Threshold drift:** If signers are removed after deployment without updating the threshold policy, the threshold can become unreachable, permanently locking the account. The `SmartAccount` library does not enforce threshold consistency on signer removal. Callers should update the threshold policy before removing signers.
- **Context rule expiry:** A `valid_until` expiry silently stops a rule from matching after that ledger. If the default rule expires, the account cannot authorize any transaction. Clients should not set expiry on the default rule.
- **Policy trust:** Policy contracts are referenced by address. A policy at a given address is trusted to correctly implement the `Policy` interface. Adding a malicious or buggy policy can block or compromise authorization for that rule's scope.

---

## Non-Goals

This contract does not handle:

- Signature cryptography (that is the verifier contracts' job)
- Signer type validation (that is the factory's job)
- Recovery flows
- Session keys or temporary delegations
- Spending limits or allowances
- Contract upgrades
- Bridge or funding logic
- Fee abstraction

These belong in separate Latch workspaces or in policy/verifier contracts.

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
cd latch-smart-account
stellar contract build
```

### Run Tests

```bash
cargo test
```

---

## Testing

The test suite covers the following scenarios:

| Test | What it verifies |
|---|---|
| `constructor_creates_one_default_rule_named_default` | Constructor creates exactly one `Default` rule named `"default"` with the provided signers |
| `execute_forwards_calls` | `execute` correctly calls a target contract function with provided arguments |
| `execute_requires_self_auth` | `execute` panics when called without the account's authorization |
| `add_context_rule_succeeds_with_self_auth` | A new `CallContract` rule can be added when self-auth is present |
| `add_context_rule_requires_self_auth` | Adding a context rule panics without self-auth |
| `add_signer_and_policy_succeed_with_self_auth` | Signers and policies can be added to an existing rule with self-auth |
| `add_signer_requires_self_auth` | Adding a signer panics without self-auth |
| `add_policy_requires_self_auth` | Adding a policy panics without self-auth |

Tests use two mock contracts:
- `MockTargetContract` — a simple get/set contract for testing `execute`
- `MockPolicyContract` — a no-op `Policy` implementation for testing policy attachment

---

## Dependencies

| Dependency | Version | Role |
|---|---|---|
| `soroban-sdk` | `25.0.2` | Soroban contract runtime |
| `stellar-accounts` | OZ git `187ad25` | Smart account framework: context rules, auth checking, policy interface |
