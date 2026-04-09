# Latch Smart Account

This workspace contains the first Latch-native smart account contract.

Its job is to be the production account primitive that the Latch factory deploys. It is constructor-compatible with the current factory and intentionally keeps the logic generic:

- one `__constructor(signers, policies)` entrypoint
- one default full-wallet context rule named `default`
- OpenZeppelin `do_check_auth`
- generic `ExecutionEntryPoint`
- self-auth protection for rule, signer, and policy mutations

## Why It Exists

We used two references to get here:

- `g2c` for the constructor-compatible smart-account shape
- `latch-demo` for the signer model and Latch mental model

This workspace replaces the need to hand a reference smart-account contract to integrators. The goal is for the web dev and the factory to target a Latch-owned account contract surface from here forward.

## Contract Shape

The contract exposes:

```rust
__constructor(signers: Vec<Signer>, policies: Map<Address, Val>)
```

On construction it creates exactly one context rule:

- type: `ContextRuleType::Default`
- name: `default`
- valid until: `None`
- signers: constructor input
- policies: constructor input

## What It Does Not Do Yet

This workspace does not include:

- verifier implementations
- bridge logic
- recovery flows
- session keys
- spending-limit policies

Those belong in separate Latch workspaces.

## Layout

```text
latch-smart-account/
├── Cargo.toml
├── README.md
└── contracts/
    └── smart-account/
        ├── Cargo.toml
        └── src/
            ├── lib.rs
            └── test.rs
```

## Fit With The Factory

The current factory in `/Users/user/SuperFranky/latch-contracts/latch-account-factory` deploys account Wasm using the constructor above. That is why this workspace uses constructor-based setup instead of the older deploy-then-initialize prototype shape.
