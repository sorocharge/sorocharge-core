# Running an x402 facilitator

This is the facilitator side: you sponsor transaction fees and settle payments on behalf
of a resource server. `Facilitator` is a set of plain async functions, not a bound HTTP
server — you wire `/verify`, `/settle`, and `/supported` to whatever framework you already
run. See
[`examples/resource_server_x402.rs`](https://github.com/sorocharge/sorocharge-core/blob/main/crates/sorocharge-x402/examples/resource_server_x402.rs)
for a complete reference implementation using `axum`.

## Set up

```rust
use sorocharge_x402::{Facilitator, FacilitatorConfig};

let facilitator = Facilitator::new(
    &rpc,                                     // &stellar_rpc_client::Client
    &facilitator_signer,                      // your fee-sponsoring key, impl Signer
    "Test SDF Network ; September 2015".to_string(),
    FacilitatorConfig::default(),
);
```

`FacilitatorConfig` has two fields, both stroop amounts: `max_transaction_fee_stroops`
(default `50_000`) is a safety ceiling on the settlement-time simulation-derived fee — a
circuit breaker against fee-exhaustion attacks, not a protocol constant, since the spec
doesn't mandate a specific number. `inclusion_buffer_stroops` (default `100`, the spec's
required minimum) is added on top of the simulated resource fee.

## Verify, then settle

```rust
let verify_response = facilitator.verify(&verify_request).await?;
if !verify_response.is_valid {
    // respond 402 with verify_response.invalid_reason
}

let settlement = facilitator.settle(&settle_request).await?;
if !settlement.success {
    // respond 402 with settlement.error_reason — "settlement-failed", not
    // "verification-failed": the credential was valid but the on-chain
    // submission didn't go through
}
```

`verify` and `settle` share the same validation path internally — `settle` does not trust
a prior `verify` call, and re-checks everything itself, per the spec's "`/settle` MUST
perform full verification independently."

## What gets checked

Both calls run, in order: protocol fields (`x402Version`, `scheme`, matching `network`),
transaction structure (exactly one `invokeHostFunction`, a bare `transfer(from, to,
amount)`, no sub-invocations), the credential type (legacy or `AddressV2` only — never
`AddressWithDelegates`), the facilitator-safety checks (your own address can't appear as
source, operation source, `from`, or in any authorization entry), signature and expiry
verification via `sorocharge_signer::verify_entry`, and a re-simulation checked with
`sorocharge_signer::verify_transfer_effects` to confirm it moves *only* the expected
balance.

`settle` additionally rebuilds the transaction with your account as source, derives a
fresh fee from a settlement-time simulation (capped by `max_transaction_fee_stroops`),
signs it, submits via `sendTransaction`, and polls until `SUCCESS` or `FAILED`.

## Advertise what you support

```rust
let supported = facilitator.supported();
```

Returns a `SupportedResponse` naming the `exact` scheme on whichever network you
configured, and your own address as a signer — wire this to a `/supported` route if your
resource servers (or anyone else) need to discover it.
