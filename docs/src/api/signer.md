# sorocharge-signer

The shared engine. Builds, signs, and verifies a `SorobanAuthorizationEntry` for a single
SEP-41 `transfer(from, to, amount)`, across every CAP-71 credential shape. Knows nothing
about x402, MPP, or HTTP.

## Types

### `Address`

```rust
pub type Address = stellar_xdr::ScAddress;
```

A direct alias, not a wrapper — the network's own address encoding is already the right
shape.

### `ChargeParams`

```rust
pub struct ChargeParams {
    pub asset_contract: Address,  // the SEP-41 SAC contract address
    pub amount: i128,             // base units — never a float
    pub payer: Address,
    pub recipient: Address,
    pub valid_until_ledger: u32,  // a ledger number — never wall-clock time
}
```

### `CredentialKind`

```rust
pub enum CredentialKind {
    Legacy,
    AddressV2,
    Delegated { signers: Vec<Address> },
}
```

Mirrors `SorobanCredentialsType` except for `SOROBAN_CREDENTIALS_SOURCE_ACCOUNT`, which has
no signature to build or verify — every charge here is authorized by an explicit
`Address`, never implicitly by the transaction's source account.

### `UnsignedEntry` / `SignedEntry`

Opaque wrappers around a `SorobanAuthorizationEntry`, before and after it carries a
signature. Both expose `as_xdr() -> &SorobanAuthorizationEntry` for serializing to XDR or
attaching to an `InvokeHostFunction` operation. `SignedEntry` additionally has
`from_xdr(SorobanAuthorizationEntry) -> Self`, for wrapping an entry that already carries a
signature — the shape a facilitator or server receives over the wire, as opposed to one
this process signed itself.

### `Signer`

```rust
pub trait Signer: Send + Sync {
    fn sign_preimage(&self, preimage: &[u8]) -> Result<[u8; 64], SorochargeError>;
    fn address(&self) -> Address;
}
```

The only abstraction you implement. `sign_preimage` signs a 32-byte digest and returns a
raw 64-byte ed25519 signature; `address` names the `Ed25519` account (`G...`) it signs for
— a contract address here is an error at sign time. `Send + Sync` so a `Signer` can be held
across an `.await` inside an async HTTP handler.

## Functions

### `build_charge_entry`

```rust
pub fn build_charge_entry(
    params: &ChargeParams,
    credential: CredentialKind,
) -> Result<UnsignedEntry, SorochargeError>;
```

Builds the unsigned entry. The nonce is generated internally with a fresh source of
randomness on every call — it exists to make each authorization unique, not to encode
caller state, so it isn't a parameter. For `Delegated`, the signers are sorted by their
XDR-encoded address bytes ascending and checked for duplicates, per CAP-71-01.

### `sign_entry`

```rust
pub fn sign_entry(
    entry: UnsignedEntry,
    signer: &dyn Signer,
    network_passphrase: &str,
) -> Result<SignedEntry, SorochargeError>;
```

Reconstructs the correct `HashIdPreimage` for the entry's actual credential type — the
legacy, non-address-bound preimage for `Legacy`, the CAP-71 address-bound preimage for
`AddressV2` and `Delegated` — signs its sha256 digest, and writes the resulting
`{public_key, signature}` vector onto whichever credential node (top-level address, or one
delegate) matches `signer.address()`. `network_passphrase` is required because the signing
payload is network-bound: `sha256(network_passphrase)` is baked into what gets signed, so
there is no default network to silently assume.

A `Delegated` entry needing more than one signer's signature needs one `sign_entry` call
per signer, each targeting its own address — accumulating multiple delegates' signatures
across separate calls is out of scope for this function's single-shot
`UnsignedEntry -> SignedEntry` shape.

### `verify_entry`

```rust
pub fn verify_entry(
    entry: &SignedEntry,
    expected: &ChargeParams,
    current_ledger: u32,
    network_passphrase: &str,
) -> Result<(), SorochargeError>;
```

Fails closed, in this order:

1. **`ExpiredEntry`** — `valid_until_ledger` has already passed `current_ledger`.
2. **`ExpirationExceedsAllowance`** — the entry's own expiration is later than
   `expected.valid_until_ledger`. Not expired, but valid for longer than the caller said
   it would accept.
3. **`UnexpectedInvocationShape`** — not a single, bare `transfer(from, to, amount)` call.
4. **`AssetMismatch`**
5. **`PayerMismatch`** — the authorizing address (which must also be the invocation's
   `from`) doesn't match `expected.payer`.
6. **`AmountMismatch`**
7. **`RecipientMismatch`**
8. **`InvalidSignature`** — no signable node carries a valid ed25519 signature over the
   reconstructed preimage. For `Delegated`, this proves at least one attached signature is
   genuine; it cannot know the target account's own multisig/threshold policy.

### `verify_transfer_effects`

```rust
pub fn verify_transfer_effects(
    events: &[String],           // base64 DiagnosticEvent XDR, from a simulation
    asset_contract: &Address,
    payer: &Address,
    recipient: &Address,
    amount: i128,
) -> Result<(), SorochargeError>;
```

Checks a simulation's events show **exactly** the expected SEP-41 transfer — no second
transfer, no transfer to someone else, no mint/burn/clawback, no balance event from a
different contract. The transfer shape checked (`[transfer, from, to]` topics, `i128`
data) is the live Stellar host's actual output, verified against a real testnet
transaction — not the CAP text, which the host doesn't always match exactly.

## Errors

`SorochargeError` — every variant is named for one specific, actionable failure; no bare
`String`, no catch-all:

| Variant | Meaning |
|---|---|
| `InvalidAddress { strkey }` | A strkey failed to decode into an `ScAddress`. |
| `UnsupportedCredentialType` | The XDR credential shape matches no variant this library signs or verifies. |
| `EmptyDelegateSigners` | `Delegated` was constructed with zero signers. |
| `DuplicateDelegateSigner` | The same delegate address appeared more than once. |
| `ExpiredEntry { valid_until_ledger, current_ledger }` | Already expired. |
| `ExpirationExceedsAllowance { signature_expiration_ledger, allowed_until_ledger }` | Valid longer than the caller allowed. |
| `UnexpectedInvocationShape` | Not a bare SEP-41 transfer. |
| `AssetMismatch` / `PayerMismatch` / `AmountMismatch` / `RecipientMismatch` | Field doesn't match. |
| `InvalidSignature` | No genuine signature found. |
| `NoMatchingCredentialNode` | A signer's address matches no node in the entry being signed. |
| `SimulationEventsMalformed { reason }` | An event didn't decode, or lacks expected topics/data. |
| `UnexpectedBalanceChange { reason }` | The simulation moved something other than the expected payment. |
| `ExpectedTransferMissing` | The simulation doesn't show the expected transfer at all. |
| `SigningFailed { reason }` | The `Signer` implementation returned an error, or isn't an `Ed25519` account. |
| `XdrEncodingFailed { reason }` | A value didn't fit its XDR-constrained shape. |
