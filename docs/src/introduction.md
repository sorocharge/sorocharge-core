# Introduction

HTTP has had a `402 Payment Required` status code since 1999 and no agreed meaning for
it. Two protocols now give it one: **[x402](https://github.com/x402-foundation/x402)**,
built around a `GET` → `402` → signed payment → retry flow, and
**[MPP](https://paymentauth.org/)**'s `draft-stellar-charge-00`, built on a formal
`WWW-Authenticate: Payment` HTTP authentication scheme. Both exist because AI agents and
automated services need to pay for API access without a human present to click "approve."

`sorocharge-core` implements both protocols on Stellar, sharing one signing engine
underneath instead of building two separate ones. That sharing is not just an
implementation convenience: both protocols reduce to the same primitive — a signed Soroban
authorization for a SEP-41 `transfer(from, to, amount)` call — and differ only in how that
authorization gets from payer to payee over HTTP.

## What this is

Three Rust crates:

- **`sorocharge-signer`** builds, signs, and verifies a `SorobanAuthorizationEntry` for a
  SEP-41 transfer, across every CAP-71 credential shape: legacy `SorobanAddressCredentials`,
  CAP-71 V2 (`AddressV2`), and delegated signers (`AddressWithDelegates`). It knows nothing
  about HTTP, x402, or MPP.
- **`sorocharge-x402`** implements the payer client and facilitator sides of x402 protocol
  v2's `exact` scheme on Stellar.
- **`sorocharge-mpp`** implements the payer client and server sides of MPP's
  `draft-stellar-charge-00` `"stellar"`/`"charge"` method, in both its pull (sponsored and
  unsponsored) and push settlement modes.

Every function in `sorocharge-signer` that produces XDR is diffed byte-for-byte in CI
against fixtures generated from a pinned `@stellar/stellar-sdk` version — not just checked
for "looks plausible," but matched against what the reference SDK actually produces for
the same inputs. See [Developer setup](guides/developer-setup.md) for how to reproduce
that yourself.

## What this is not

- **Not MPP session/channel mode.** That mode signs a raw ed25519 signature over a
  `one-way-channel` contract's `prepare_commitment` output — a different primitive
  entirely, with no `SorobanAuthorizationEntry` involved. It does not exist anywhere in
  this repository.
- **Not a general-purpose Soroban contract client.** Everything here is scoped to one
  operation: build, sign, and verify a SEP-41 transfer authorization.
- **Not a key manager.** Every function that signs takes a `Signer` the caller already
  controls. No key storage, no HSM integration, no wallet.
- **Not an HTTP server.** `sorocharge-x402`'s `Facilitator` and `sorocharge-mpp`'s
  `MppServer` are plain functions over already-deserialized request types — wiring them to
  real `/verify`, `/settle`, or `WWW-Authenticate` HTTP handling is the embedding
  application's job, using whatever web framework it already runs.

## Where to go next

- New to the protocols? Start with [x402 protocol mechanics](architecture/x402.md) or
  [MPP protocol mechanics](architecture/mpp.md).
- Integrating as a payer or a payee? Jump straight to the [guides](guides/x402-client.md).
- Looking for exact function signatures? See the [API reference](api/signer.md).
