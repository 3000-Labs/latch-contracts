# Engineering Spike: Prove the Final Latch Account Architecture

## Goal

Prove that the final Latch-native smart-account architecture is viable before we fully commit to production implementation.

This spike is for the core engineering path, not the web-dev integration path.

It should prove three things:

1. the final Latch smart-account implementation is sound
2. the final production verifier workspace layout is clean and sustainable
3. the multi-verifier production architecture works the way we expect

## Why This Spike Exists

Right now, we have:

- a real factory workspace under `/Users/user/SuperFranky/latch-contracts/latch-account-factory`
- a real Ed25519 demo path under `/Users/user/SuperFranky/latch/latch-demo`
- a real WebAuthn reference path under `/Users/user/SuperFranky/latch/reference/g2c`

But we do not yet have the final Latch-native production contract set:

- `latch-smart-account`
- `latch-verifiers/ed25519`
- `latch-verifiers/secp256k1`
- `latch-verifiers/webauthn`

This spike exists to prove that those workspaces can be built as a coherent production system, not just as stitched-together references.

## Core Questions to Prove

### 1. Final smart-account implementation

Can we implement a Latch-native smart account that:

- uses the constructor shape required by the factory
- creates the default full-wallet context rule on construction
- supports `ExecutionEntryPoint`
- uses OZ `do_check_auth`
- restricts mutation methods through self-auth

### 2. Final verifier workspace layout

Can we structure the verifier contracts in a way that is clear and production-ready?

Target layout:

- `/Users/user/SuperFranky/latch-contracts/latch-smart-account`
- `/Users/user/SuperFranky/latch-contracts/latch-verifiers/ed25519-verifier`
- `/Users/user/SuperFranky/latch-contracts/latch-verifiers/secp256k1-verifier`
- `/Users/user/SuperFranky/latch-contracts/latch-verifiers/webauthn-verifier`

The proof here is architectural as much as functional:

- each verifier is isolated
- each verifier has one responsibility
- each verifier matches the `Signer::External(verifier, key_data)` model cleanly
- the factory can reference all of them without special casing account behavior

### 3. Multi-verifier production architecture

Can one production smart account support:

- one Ed25519 signer
- one WebAuthn signer
- one Secp256k1 signer
- mixed multi-signer configurations across verifier kinds

That is the real proof that the architecture is not single-wallet-specific.

## Proposed Scope

This spike should not attempt to finish every production contract completely.

Instead, it should prove the architecture through a minimum viable production slice:

- one Latch-native smart-account contract
- one Latch-native Ed25519 verifier
- one Latch-native WebAuthn verifier
- one mixed-signer account deployment path through the factory
- one clear workspace layout for adding Secp256k1 next

Secp256k1 can remain partially implemented if needed, as long as:

- the workspace exists
- the interface is frozen
- the signer format is fixed
- the factory integration surface is validated

## Minimum Proof Plan

### Phase 1: Latch-native smart account

Create a new workspace:

- `/Users/user/SuperFranky/latch-contracts/latch-smart-account`

Implement:

- `__constructor(signers, policies)`
- default context rule creation
- `CustomAccountInterface`
- `SmartAccount`
- `ExecutionEntryPoint`
- self-auth protection on rule/signer/policy mutations

Success criteria:

- deployable from the current factory
- constructor initializes exactly one default rule named `default`
- `execute` works for an authorized call

### Phase 2: Latch-native verifier layout

Create verifier workspaces:

- `/Users/user/SuperFranky/latch-contracts/latch-verifiers/ed25519-verifier`
- `/Users/user/SuperFranky/latch-contracts/latch-verifiers/webauthn-verifier`
- `/Users/user/SuperFranky/latch-contracts/latch-verifiers/secp256k1-verifier`

Initial proof targets:

- `ed25519-verifier` based on the current demo verifier
- `webauthn-verifier` based on the `g2c` verifier
- `secp256k1-verifier` at minimum has frozen contract interface and tests for key-shape assumptions

Success criteria:

- each verifier compiles in its own workspace
- each verifier implements OZ `Verifier`
- each verifier has isolated tests
- no verifier depends on account-specific logic

### Phase 3: Multi-verifier proof

Use the current factory with the new Latch-native smart-account Wasm and verifier deployments.

Prove these account configurations:

1. single-signer Ed25519 account
2. single-signer WebAuthn account
3. mixed 2-of-2 account with Ed25519 + WebAuthn

If Secp256k1 is ready enough, add:

4. single-signer Secp256k1 account

Success criteria:

- factory can derive and create each account deterministically
- factory maps signer kinds to the correct verifier addresses
- mixed signer kinds can coexist in one account
- threshold policy installation still works in mixed multi-signer creation

## What Counts as Proof

This spike is successful if it produces all of the following:

1. A real `latch-smart-account` workspace that the factory can deploy.
2. Real `ed25519` and `webauthn` verifier workspaces under `latch-contracts`.
3. A frozen workspace layout for the final verifier family.
4. End-to-end tests showing:
   - single-signer Ed25519 account creation
   - single-signer WebAuthn account creation
   - mixed-signers multisig account creation
5. A short engineering note documenting:
   - what was proven
   - what remains open
   - whether Secp256k1 is still blocked on verifier details

## Explicit Non-Goals

This spike does not need to finish:

- production frontend UX
- bridge proxy integration
- recovery flows
- session policies
- spending-limit policies
- audit hardening

This spike is about proving the core contract architecture only.

## Risks to Watch

Focus carefully on these:

- constructor compatibility between factory and final smart account
- exact `key_data` expectations per verifier
- auth payload formatting differences across signer types
- keeping verifiers stateless and reusable
- preventing account-specific assumptions from leaking into verifier crates

## Deliverable

At the end of the spike, there should be a clear answer to:

- can the final Latch-native smart account replace the temporary reference account?
- can the verifier family live cleanly under `latch-contracts` as separate production workspaces?
- does the multi-verifier architecture actually work under one factory/account model?

If the answer is yes, we can move from references to production implementation with much less risk.
