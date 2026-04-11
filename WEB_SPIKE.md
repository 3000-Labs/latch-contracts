# Web Spike: Factory + Smart Account Integration

## Status

The Ed25519 (Phantom) path is **fully working on testnet** as of 2026-04-11.
The factory, smart account, auth flow, and demo UI are all deployed and proven.

The next developer task is the **WebAuthn path** — passkey-based account creation
and auth through the same factory and smart account.

---

## What Is Deployed (Testnet)

| Contract | Address | WASM Hash |
|---|---|---|
| Ed25519 Phantom Verifier | `CBFSXM22BNS4L6OVDGF4TMXVE5GQTXJCUODJCW5N2Q7LWHW4I33ZSB5A` | `272ad675...` |
| Smart Account (WASM only) | — | `c00f972c...` |
| Factory | `CC6C6KYZSRX6UHHXIWJCC3JC6PS5R62BEX6NIXL777DYTH6EAPYZXAGG` | `c4f286f2...` |
| Counter (test target) | `CBRCNPTZ7YPP5BCGF42QSUWPYZQW6OJDPNQ4HDEYO7VI5Z6AVWWNEZ2U` | — |

WebAuthn and Secp256k1 verifiers are stubs — not production contracts.

---

## What the Factory Expects

### `create_account(params)` and `get_account_address(params)`

Both take a single `AccountInitParams` argument encoded as an ScVal map:

```
{
  account_salt: Bytes,       // 32-byte SHA256 hash (deterministic, derived from pubkey + version)
  signers: Vec<SignerInit>,  // list of signers
  threshold: Void,           // null for single-signer; threshold policy not yet used
}
```

Where each `SignerInit` is:

```
{
  key_data: Bytes,                   // raw key bytes
  signer_kind: Vec<Symbol("Ed25519")>  // Soroban enum variant
}
```

### Salt derivation (must match server-side)

```typescript
const SMART_ACCOUNT_VERSION = "factory-v2";
const salt = sha256(publicKeyHex + SMART_ACCOUNT_VERSION);
```

The version string ensures fresh accounts. If you change it, you get a new address.

---

## Working Implementation Reference

All of this is wired up in `latch/`. Read these routes before writing anything new.

### Account creation
`latch/app/api/smart-account/factory/route.ts`
- `GET ?pubkey=<64-char-hex>` — checks if account is deployed (reads ledger entry)
- `POST { publicKeyHex }` — deploys account via factory, returns `smartAccountAddress`

### Transaction build
`latch/app/api/transaction/build/route.ts`

Builds a simulated transaction against the counter contract and returns:
- `txXdr` — the unsigned transaction
- `authEntryXdr` — the auth entry requiring smart account signature
- `authPayloadHash` — the **OZ-bound** auth digest the wallet must sign

**Critical**: `authPayloadHash` is NOT just `hash(preimage)`. OZ re-hashes before
calling verify:

```typescript
// payloadHash = hash(HashIdPreimageSorobanAuthorization XDR)
const contextRuleIdsXdr = xdr.ScVal.scvVec([xdr.ScVal.scvU32(0)]).toXDR();
const authDigest = hash(Buffer.concat([payloadHash, contextRuleIdsXdr]));
// authPayloadHash = authDigest.toString("hex")
```

The wallet signs `"Stellar Smart Account Auth:\n" + authPayloadHash`.
The on-chain verifier receives `authDigest` bytes and reconstructs the same message.

### Transaction submit
`latch/app/api/transaction/submit/route.ts`

Accepts:
- `txXdr`, `authEntryXdr` — from build route
- `authSignatureHex` — raw 64-byte Ed25519 signature from Phantom (hex-encoded)
- `publicKeyHex` — Phantom's 32-byte pubkey (hex-encoded)

Builds the `AuthPayload` map and enforcing-mode simulates, then submits.

**sig_data format**: raw `Bytes(64)` — NOT an XDR-encoded struct.
The production verifier reconstructs the prefix internally from the hash.

### Demo UI
`latch/app/demo/page.tsx` — working end-to-end Phantom demo.

---

## Review of Developer PR

**PR #2 (kcmikee, `feat: add Stellar demo page`)** added `app/demo-stellar/page.tsx`.

That page:
- Uses `@creit.tech/stellar-wallets-kit` (Freighter, Lobstr, Albedo, xBull)
- Connects a standard G-address wallet
- Calls `counter.increment(publicKey)` directly — no smart account, no factory, no verifier

This is useful exploratory work for understanding native Stellar wallet connectivity
and the `StellarWalletsKit` API. It does **not** implement the spike requirements.
The spike was about factory-based smart account creation, not standard wallet signing.

That PR needs to be reviewed and either:
1. Merged as a separate "native Stellar wallet" reference page (keep it, rename it clearly)
2. Superseded by the factory-based demo

---

## Next Task: WebAuthn Path

This is what the developer should implement next.

### What WebAuthn means here

Instead of Phantom (Ed25519, external key), the user creates a passkey (P-256/secp256r1)
on their device. The smart account is created the same way through the factory — the only
difference is the signer kind and verifier address.

The WebAuthn verifier contract is **not yet built**. The factory currently has a stub
at `CBYYKKTEBQTJFBOVSUGXFALDTRRS6HC3QSNCKONOOGOMSJOHBTQU7LSI`.

### WebAuthn spike tasks

#### 1. Passkey creation (client-side)
Create a passkey using the browser's WebAuthn API:
```typescript
const credential = await navigator.credentials.create({
  publicKey: {
    challenge: crypto.getRandomValues(new Uint8Array(32)),
    rp: { name: "Latch", id: window.location.hostname },
    user: { id: new Uint8Array(16), name: "user", displayName: "User" },
    pubKeyCredParams: [{ type: "public-key", alg: -7 }], // ES256 = P-256
    authenticatorSelection: { requireResidentKey: true, userVerification: "required" },
  },
});
```

Extract the P-256 public key from `credential.response.getPublicKey()`.
The `key_data` for WebAuthn is the raw 64-byte uncompressed public key (x || y)
OR a credential-id-prefixed format — depends on what the verifier spec defines.

See: `latch-contracts/latch-verifiers/webauthn-verifier-spec.md`

#### 2. Account creation via factory
Same flow as Ed25519 but with:
```typescript
{
  key_data: Bytes(<webauthn_pubkey>),
  signer_kind: Vec<Symbol("WebAuthn")>
}
```

The factory will map `WebAuthn` to the webauthn_verifier address.

#### 3. Auth signing (WebAuthn assertion)
Instead of Phantom's `signMessage`, use:
```typescript
const assertion = await navigator.credentials.get({
  publicKey: {
    challenge: Buffer.from(authPayloadHash, "hex"),
    rpId: window.location.hostname,
    userVerification: "required",
  },
});
```

The `sig_data` for WebAuthn is more complex than Ed25519. The verifier needs:
- the signature bytes
- `authenticatorData`
- `clientDataJSON`

This is covered in `latch-contracts/latch-verifiers/webauthn-verifier-spec.md`.
The verifier contract needs to be built before this path can be tested on-chain.

### What the developer can prove before the verifier is built

Even without a working WebAuthn verifier on-chain, the developer can prove:
1. Passkey creation works in the browser
2. The correct P-256 public key is extracted
3. `create_account` via factory works with `signer_kind: WebAuthn`
   (it will deploy but auth will fail until the real verifier is deployed)
4. `get_account_address` is deterministic for WebAuthn params

---

## Environment

All testnet. No local Soroban environment needed.

```
NEXT_PUBLIC_RPC_URL=https://soroban-testnet.stellar.org
NEXT_PUBLIC_NETWORK_PASSPHRASE=Test SDF Network ; September 2015
NEXT_PUBLIC_FACTORY_ADDRESS=CC6C6KYZSRX6UHHXIWJCC3JC6PS5R62BEX6NIXL777DYTH6EAPYZXAGG
NEXT_PUBLIC_VERIFIER_ADDRESS=CBFSXM22BNS4L6OVDGF4TMXVE5GQTXJCUODJCW5N2Q7LWHW4I33ZSB5A
NEXT_PUBLIC_SMART_ACCOUNT_WASM_HASH=c00f972cb8ed5eba151f4cd6e97519db679a7a31cc657838449b405fb9cf53c4
```

---

## Success Criteria for WebAuthn Spike

1. Browser creates a passkey and extracts a P-256 public key.
2. `create_account` succeeds with a `WebAuthn` signer via factory.
3. `get_account_address` returns the same address for the same passkey.
4. A passkey assertion is obtained using the OZ-bound `authDigest` as the challenge.
5. The signed assertion bytes are assembled into the correct `sig_data` shape
   as specified in `webauthn-verifier-spec.md`.
6. Once the WebAuthn verifier contract is deployed, a counter increment succeeds.

Steps 1–4 are achievable now. Steps 5–6 wait on the verifier contract.
