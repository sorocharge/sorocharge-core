# Three crates, one engine

```
sorocharge-signer   the shared engine: build/sign/verify a SEP-41 transfer
                     authorization entry, for every CAP-71 credential shape
sorocharge-x402      x402 protocol v2, "exact" scheme, on Stellar
sorocharge-mpp       MPP's "stellar" payment method, "charge" intent
```

`sorocharge-x402` and `sorocharge-mpp` depend on `sorocharge-signer`. `sorocharge-signer`
depends on neither of them, and knows nothing about either protocol's wire format. That
boundary is enforced by what each crate's public API actually exposes, not just by
convention: if you find yourself wanting to import `sorocharge-x402` from
`sorocharge-signer`, the abstraction boundary is wrong.

## Why one engine, not two

x402 and MPP look different on the wire — one is a bespoke set of HTTP headers, the other
is a formal IETF-style authentication scheme — but both resolve to the same underlying
operation: a payer signs a `SorobanAuthorizationEntry` authorizing a SEP-41
`transfer(from, to, amount)`, and a payee (directly, or via a fee-sponsoring
facilitator/server) submits it to the network. Building that signing logic twice would mean
auditing it twice, and any fix to one copy drifting from the other.

`sorocharge-signer` is also the only crate with a correctness proof behind it: every
function that produces XDR — `build_charge_entry`, `sign_entry` — is diffed byte-for-byte
in CI against fixtures generated from a pinned `@stellar/stellar-sdk` version. See
[Developer setup](../guides/developer-setup.md) for how that works. `sorocharge-x402` and
`sorocharge-mpp` inherit that proof by construction: they don't re-implement signing, they
call into the crate that's already been checked against the reference implementation.

## What belongs where

| Concern | Lives in |
|---|---|
| Building the unsigned `SorobanAuthorizationEntry` | `sorocharge-signer` |
| Reconstructing the `HashIdPreimage` and signing it | `sorocharge-signer` |
| Verifying asset/payer/amount/recipient/expiry/signature | `sorocharge-signer` |
| Checking a simulation shows only the expected balance change | `sorocharge-signer` |
| x402's `PAYMENT-REQUIRED`/`PAYMENT-SIGNATURE`/`PAYMENT-RESPONSE` headers | `sorocharge-x402` |
| x402's facilitator safety checks (fee-sponsor can't be tricked) | `sorocharge-x402` |
| MPP's `WWW-Authenticate: Payment` challenge and credential encoding | `sorocharge-mpp` |
| MPP's pull/push mode settlement | `sorocharge-mpp` |
| Wrapping the signed entry in a `TransactionEnvelope` with the right source account | `sorocharge-x402` / `sorocharge-mpp` (independently — see below) |

The last row is deliberate duplication, not an oversight. Building the actual
`invokeHostFunction` operation and `Transaction` envelope is protocol-adapter work: x402
always places the entry on an all-zeros placeholder source account (the facilitator always
sponsors fees), while MPP has to build two different shapes depending on `feePayer` — a
placeholder source for the sponsored case, or a fully-signed, real-sequence-number
transaction for the unsponsored case. Sharing that construction would have meant
`sorocharge-signer` growing branches for protocol-specific transaction shapes it has no
business knowing about, so each adapter builds its own small version instead.

## Non-goals

Neither protocol crate can emit a `Delegated` (`AddressWithDelegates`) credential, even
though `sorocharge-signer` supports it. x402's `exact` scheme on Stellar explicitly forbids
it; MPP's spec never mentions it. `sorocharge-signer` keeps the capability because it's a
real CAP-71 credential type a future protocol adapter (or a direct caller) might need — the
two shipped adapters simply don't use it.
