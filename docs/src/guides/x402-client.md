# Paying with x402

This is the payer side: you hold a Stellar account, and you want to pay for an
x402-protected resource.

## Implement `Signer`

`sorocharge-signer::Signer` is the only thing you implement yourself — it's how you
control where your private key actually lives:

```rust
use sorocharge_signer::{Address, Signer, SorochargeError};
use ed25519_dalek::{Signer as DalekSigner, SigningKey};
use stellar_xdr::{AccountId, PublicKey, ScAddress, Uint256};

struct KeypairSigner {
    signing_key: SigningKey,
    address: Address,
}

impl Signer for KeypairSigner {
    fn sign_preimage(&self, preimage: &[u8]) -> Result<[u8; 64], SorochargeError> {
        Ok(self.signing_key.sign(preimage).to_bytes())
    }

    fn address(&self) -> Address {
        self.address.clone()
    }
}
```

`address()` must return an `Ed25519` account address (`G...`) — `sign_entry` rejects a
contract address.

## Pay for a resource

```rust
use std::time::Duration;
use sorocharge_x402::X402Client;

let client = X402Client::new(Duration::from_secs(30))?;

// The authorization entry's expiration ledger needs a current ledger to be
// computed from. A getLatestLedger call, done once per payment.
let current_ledger = rpc.get_latest_ledger().await?.sequence;

let response = client
    .get_with_payment(
        "https://api.example.com/premium-data",
        &signer,
        "Test SDF Network ; September 2015",
        current_ledger,
    )
    .await?;

assert_eq!(response.status(), 200);
let body = response.text().await?;
```

`get_with_payment` does the whole flow: `GET`, decode the `402`'s `PAYMENT-REQUIRED`
challenge, pick the `exact`-on-Stellar entry matching your network, build and sign a
charge entry, wrap it in a transaction, and retry with `PAYMENT-SIGNATURE` attached. A
`200` on the first `GET` (already paid, or free) is returned as-is without any of that.

## What you don't control

You don't choose the asset, amount, or recipient — the resource server does, via the
`402` challenge, and you have no say beyond paying or not paying. If you need to check the
terms before paying (e.g. reject anything over a budget), you'd need to drop to a lower
level than `get_with_payment` — decode the challenge yourself and decide before building
the entry. `get_with_payment` always pays whatever the server asks.

## Errors

Every failure is a distinct `X402Error` variant — see the
[API reference](../api/x402.md#x402error) for the full list. The ones you're most likely
to see as a payer: `UnexpectedStatus` (the server returned something other than `402` or
`200`), `MissingPaymentRequiredHeader` / `InvalidPaymentRequired` (a malformed or absent
challenge), `NoAcceptablePaymentRequirements` (none of the server's `accepts[]` match your
network), and anything from `Signing` (your `Signer` or the underlying
`sorocharge-signer` call failed).
