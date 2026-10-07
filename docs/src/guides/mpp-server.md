# Running an MPP server

This is the server side: you issue `"stellar"`/`"charge"` challenges and settle whatever
credentials come back. Like `Facilitator`, `MppServer` is plain functions, not a bound HTTP
server — see
[`examples/resource_server_mpp.rs`](https://github.com/sorocharge/sorocharge-core/blob/main/crates/sorocharge-mpp/examples/resource_server_mpp.rs)
for a complete reference implementation.

## What `MppServer` deliberately doesn't own

`draft-stellar-charge-00` scopes itself to "the Stellar-specific `methodDetails`, payload,
and verification procedures for the `stellar` payment method" — challenge storage, HMAC
challenge-binding, and replay protection belong to the generic base
`draft-httpauth-payment-01` scheme, which isn't Stellar-specific and isn't this crate's
job. Concretely:

- **You track which `ChargeRequest` a challenge id was issued for.** `settle_credential`
  takes the original `ChargeRequest` as a parameter — it doesn't remember what it issued.
- **You track consumed push-mode transaction hashes.** `settle_credential` takes an
  `already_consumed: bool` you compute from your own store before calling it, and you mark
  the hash consumed yourself after a successful return.

## Issue a challenge

```rust
use chrono::{Duration, Utc};
use sorocharge_mpp::{ChargeRequest, MethodDetails, MppServer, MppServerConfig};

let server = MppServer::new(
    &rpc,
    &server_signer,                           // your fee-sponsoring key, for sponsored charges
    "Test SDF Network ; September 2015".to_string(),
    MppServerConfig::default(),
);

let charge = ChargeRequest {
    amount: "1000000".to_string(),
    currency: asset_contract.to_string(),
    recipient: server_signer.address().to_string(),
    description: Some("API access fee".to_string()),
    external_id: None,
    method_details: MethodDetails {
        network: "stellar:testnet".to_string(),
        fee_payer: true,
    },
};
let expires = Utc::now() + Duration::minutes(5);
let header = server.build_challenge_header(&challenge_id, &realm, &charge, expires)?;

// store (challenge_id -> (charge, expires)) yourself, then:
// respond 402 with `WWW-Authenticate: {header}`
```

## Settle a credential

```rust
let already_consumed = /* only relevant for push mode: your own hash-store lookup */;

let receipt = server
    .settle_credential(&credential, &stored_charge, Utc::now(), already_consumed)
    .await?;

// respond 200 with `Payment-Receipt: {base64url(receipt)}`
```

`settle_credential` branches on `credential.payload`:

- **Pull mode**: decodes the transaction, checks it's a bare SEP-41 transfer using the
  legacy credential type (the only type this spec permits), checks the authorization
  entry's expiration doesn't exceed the challenge's allowance, verifies signature and
  amount/asset/recipient via `sorocharge_signer::verify_entry`, re-simulates and checks
  only the expected balance moves (`sorocharge_signer::verify_transfer_effects`), then —
  sponsored only — rebuilds with your account as source, signs, submits, and polls.
  Unsponsored transactions are submitted as received, unmodified.
- **Push mode**: fetches the transaction via `getTransaction`, checks its status is
  `SUCCESS` and the transfer shape matches, and refuses outright if the challenge specified
  `feePayer: true` (push mode can never be fee-sponsored).

## Errors

See the [API reference](../api/mpp.md#mpperror) for the full list, including
`PushModeForbidsFeePayer`, `ServerAddressConflict`, `HashAlreadyConsumed`, and the
distinction between `VerificationFailed` (the credential itself didn't check out) and
`SettlementFailed` (it checked out, but the on-chain submission didn't go through).
