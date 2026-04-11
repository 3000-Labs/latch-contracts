# Account Migration: G-Address to Smart Account

## The Problem

Existing Latch users have G-addresses — classic Stellar accounts backed by an Ed25519 keypair
stored on their device. Their assets (XLM, USDC, other tokens) live on the classic ledger under
that G-address.

When a user moves to a Latch smart account (C-address), three things need to be resolved:

1. **Identity** — what signing key carries over
2. **Assets** — what is on the G-address and how it moves
3. **The G-address itself** — what happens to it after migration

This document defines what the migration problem actually is and what needs to be built.

---

## What Carries Over Automatically

### The keypair stays on the device

The user's Ed25519 keypair does not change. The same keypair that controlled their G-address
becomes the signing key for their smart account via `Signer::External(ed25519_verifier, pub_key)`.

| | Before | After |
|--|--|--|
| Device stores | Ed25519 keypair | Same Ed25519 keypair |
| Signs | Classic Stellar tx XDR | Auth payload hash (prefixed) |
| Controls | G-address | Smart account via `__check_auth` |

No key rotation, no new seed phrase. The UX experience of "sign with your device" is identical.

---

## What Does Not Carry Over

### Assets live on the G-address

Assets on a G-address are held in the classic Stellar ledger:
- Native XLM balance
- Trustline balances (USDC, USDT, and any other assets the user has opted into)

A smart account (C-address) holds balances differently:
- XLM received by a contract is tracked by the Soroban host
- Token balances are held inside SAC (Stellar Asset Contract) storage per account

**These do not automatically move.** Deployment of the smart account does not touch the
G-address at all. The user's XLM and tokens stay on the G-address until explicitly transferred.

### The G-address does not disappear

The G-address remains a live account on the ledger with its base reserve locked in XLM
(minimum 1 XLM). It does not get deleted or migrated automatically. The user must explicitly
drain and close it if they want to reclaim that reserve.

---

## Migration Paths

### Path A: Ed25519 signer (same keypair, new account)

The smart account is created with the user's existing Ed25519 public key as the sole signer.

```
Factory.create_account({
    signers: [{ signer_kind: Ed25519, key_data: existing_pub_key }],
    threshold: None,
    account_salt: sha256(pub_key + version)
})
```

Then assets are moved:
1. XLM — classic `payment` op from G-address to C-address
2. Tokens — `token::transfer` call on each SAC from G-address to C-address
3. Reserve reclaim — merge G-account into another address to recover the base reserve XLM
   (optional but recommended for UX completion)

### Path B: Delegated signer (G-address as bootstrap signer)

Create the smart account with `Signer::Delegated(g_address)` first, transfer assets, then
rotate to the Ed25519 external signer and remove the delegated signer.

This path is lower friction at creation time (no verifier, no prefixed signing) but requires
a second operation to finish the key rotation. It should only be considered if Path A creates
UX friction during onboarding.

---

## What Needs to Be Built

### 1. Migration detection

Before showing any migration UI, the app needs to know:

- Does this user have an existing G-address with a non-zero balance?
- What assets does the G-address hold and what are their approximate values?
- Is a smart account already deployed for this keypair?

This is a read-only query against Stellar RPC. No contracts required.

**Inputs:** Ed25519 public key from device  
**Outputs:** G-address balance, trustline list, whether C-address already exists

---

### 2. Smart account deployment (if not already deployed)

The factory already handles this. If the smart account does not exist yet, call `create_account`
with the user's Ed25519 key. This is already built.

What is not yet built:

- Client-side check: "does a smart account already exist for this key?" before calling
  `create_account` (can use `get_account_address` + RPC existence check)
- Handling the case where the user has an account from an older `account_salt` version

---

### 3. Asset transfer: XLM

Send native XLM from the G-address to the C-address via a classic payment operation.

```
Payment {
    destination: smart_account_c_address,
    asset: native,
    amount: g_address_balance - fee_buffer
}
```

The C-address can receive native XLM directly. No special contract invocation needed.

**Open question:** The C-address needs a minimum ledger entry to exist before it can receive
XLM from a classic account. Confirm whether `create_account` (factory deployment) satisfies
this or whether a separate funding step is needed.

---

### 4. Asset transfer: SAC tokens

Each trustline asset must be transferred via its SAC token contract.

```
token_contract.transfer(
    from: g_address,        // classic signer
    to: smart_account,      // C-address
    amount: full_balance
)
```

This is a Soroban invocation authorized by the G-address keypair. The G-address must sign this
as the `from` account.

Tasks:
- Enumerate all trustline assets on the G-address
- Resolve the SAC contract address for each asset
- Build one transfer invocation per asset
- Let the user sign all of them (can batch in a single transaction envelope)

**Open question:** Some assets may not have a deployed SAC yet. Determine behavior — skip,
warn, or surface to user.

---

### 5. G-address close (optional)

After all assets are moved, the G-address can be merged to recover the base reserve.

```
AccountMerge {
    destination: smart_account_c_address  // or another address
}
```

This operation:
- Sends the remaining XLM balance (the reserve) to the destination
- Deletes the G-address from the ledger
- Cannot be reversed

This is optional but should be offered in the migration UI as the final step.

---

### 6. Migration transaction bundling

Ideally the migration happens in as few user-signing steps as possible. Target:

- One signature to authorize the smart account deployment (if not yet deployed)
- One signature to authorize the asset sweep (XLM + all tokens)
- One optional signature to merge the G-address

The asset sweep can be batched into a single transaction if the total number of operations
stays within ledger limits. Investigate whether XLM payment + N SAC transfers + optional merge
fit in one envelope or need to be split.

---

### 7. Migration UX state machine

Track migration state per user so the UI can resume if interrupted:

| State | Description |
|--|--|
| `not_started` | G-address has assets, no smart account deployed |
| `account_deployed` | Smart account exists, assets still on G-address |
| `assets_moved` | Assets transferred, G-address has only reserve left |
| `complete` | G-address merged or user chose to keep it |

State can be derived entirely from on-chain reads. No backend state required.

---

## What This Does Not Cover

- **Bridge proxy** — handles incoming CEX withdrawals to the smart account going forward, not
  the one-time migration of existing assets. Separate concern.
- **Recovery flows** — if the user loses device access, how to recover the smart account.
  Not part of migration.
- **Multi-signer accounts** — migration is scoped to single-signer (one Ed25519 key) accounts
  for now. Multisig migration is a separate problem.
- **Non-Ed25519 keypairs** — Stellar supports multisig G-addresses with multiple signers.
  Out of scope here; assume single-keypair G-addresses only.

---

## Open Questions

1. Does the C-address need to be funded with XLM before it can receive a classic payment?
   If so, who funds it and how much?

2. If a user has an asset with no deployed SAC, do we skip it silently, warn them, or block
   the migration?

3. Should the G-address merge destination be the smart account itself, or should the user
   choose? Merging into the smart account keeps everything under one identity. Merging into
   another address is cleaner for the G-address ledger footprint but requires an extra address.

4. What is the minimum XLM balance the smart account needs to hold as a Soroban ledger entry
   reserve? This sets a floor on how much XLM must be transferred before the G-address can
   be closed.

5. When the factory deploys a new smart account, is the `account_salt` fixed (derived from
   pubkey) or user-controlled? If fixed, two accounts using the same keypair with different
   salts could coexist. Define the canonical salt for the migration path.

---

## Success Criteria

Migration is complete when:

1. A smart account exists at the C-address derived from the user's Ed25519 public key.
2. All XLM (minus fees) has moved from the G-address to the smart account.
3. All SAC token balances have moved from the G-address to the smart account.
4. The user can execute a transaction from the smart account using the same device key they
   used to control the G-address.
5. (Optional) The G-address has been merged and removed from the ledger.
