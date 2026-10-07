# Paying with MPP

This is the payer side: you hold a Stellar account, and you want to pay for an MPP
`"stellar"`/`"charge"`-protected resource.

## Set up

Unlike `X402Client`, `MppClient` owns an RPC client reference — the unsponsored flow needs
your account's sequence number and a fee/resource-data simulation before it can build a
fully-signed transaction, and pushing those calls onto you would just move them one layer
up.

```rust
use std::time::Duration;
use sorocharge_mpp::MppClient;

let client = MppClient::new(&rpc, Duration::from_secs(30))?;
```

## Pay for a resource

```rust
let response = client
    .get_with_payment(
        "https://api.example.com/agent-endpoint",
        &signer,                                  // impl sorocharge_signer::Signer
        "Test SDF Network ; September 2015",
    )
    .await?;

assert_eq!(response.status(), 200);
```

`get_with_payment` decodes whichever `WWW-Authenticate: Payment` challenge comes back,
checks the method is `"stellar"` and the intent is `"charge"`, builds and signs a charge
entry, and retries in whichever header the challenge selected (`Authorization` by default,
or `Payment-Authorization` if the challenge asked for that). It always uses the legacy
credential type — this spec never mentions `AddressV2`.

## Sponsored vs. unsponsored

The server decides, via `methodDetails.feePayer` in the challenge — you don't choose.

- **Sponsored (`feePayer: true`)**: the client signs only the authorization entry, on an
  all-zeros placeholder transaction the server replaces at settlement.
- **Unsponsored (`feePayer: false` or absent)**: the client fetches its own account,
  simulates to derive a fee and fresh Soroban resource data, and signs the **entire**
  transaction — a real sequence number, a real fee, `timeBounds.maxTime` set to the
  challenge's `expires`.

Both paths produce a `type="transaction"` (pull-mode) credential. `MppClient` never builds
a `type="hash"` (push-mode) credential — that mode means broadcasting the transaction
yourself and presenting the hash, which is a workflow `MppClient` doesn't drive for you.

## The expiration margin

The authorization entry's expiration is set to **half** the spec's allowed ledger range
(`currentLedger + ceil(remaining_seconds / 5)`, then halved), not the full allowance. This
was found on live testnet: the server independently re-derives its own bound from its own
clock, and when ledgers close slower than the spec's 5-second assumption, a full-allowance
expiry set by the client can fail the server's check even though nothing was done wrong.
Halving it costs a shorter authorization window — which is also less exposure, not just a
workaround.

## Errors

See the [API reference](../api/mpp.md#mpperror) for the full list. As a payer you're most
likely to see: `MissingChallenge` / `InvalidChallenge` (no challenge, or one that doesn't
parse), `UnsupportedMethod` / `UnsupportedIntent` (not `"stellar"`/`"charge"` — you've
pointed this client at something else), `ChallengeExpired`, and anything from `Signing`.
