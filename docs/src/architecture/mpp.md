# MPP protocol mechanics

`sorocharge-mpp` implements [MPP](https://paymentauth.org/)'s `draft-stellar-charge-00` —
the `"stellar"` payment method for the `"charge"` intent, layered on the base
`draft-httpauth-payment-01` "Payment" HTTP authentication scheme. Only the charge-intent
mode is implemented. MPP's session/channel mode is a different signing primitive entirely
(a raw ed25519 signature over a `one-way-channel` contract's `prepare_commitment` output,
not a `SorobanAuthorizationEntry`) and does not exist anywhere in this crate.

## The flow

```
Client                                            Server                 Stellar Network
   │  GET /resource                                   │                        │
   ├──────────────────────────────────────────────────>                       │
   │  402 Payment Required                             │                        │
   │  WWW-Authenticate: Payment id=.., request=..       │                        │
   <──────────────────────────────────────────────────┤                        │
   │  (build + sign a charge entry)                     │                        │
   │  GET /resource                                     │                        │
   │  Authorization: Payment <base64url credential>     │                        │
   ├──────────────────────────────────────────────────>│  verify + submit        │
   │                                                     ├───────────────────────>│
   │  200 OK                                            │                        │
   │  Payment-Receipt: <base64url receipt>               │                        │
   <──────────────────────────────────────────────────┤                        │
```

Unlike x402, this is a genuine HTTP authentication scheme with `WWW-Authenticate` challenge
and `Authorization` credential headers — not a bespoke header pair — and it's `MppServer`'s
job (plain async functions again, not a bound HTTP route) to issue the challenge and settle
the credential.

## Pull mode vs. push mode

| | Pull mode (`type="transaction"`, default) | Push mode (`type="hash"`, fallback) |
|---|---|---|
| Who submits | The server | The client, directly to the network |
| `payload` carries | Base64 XDR of a transaction | A 64-character hex transaction hash |
| Fee sponsorship | Available (`feePayer: true`) | Never available |
| Server's job | Verify, (maybe rebuild,) submit, poll | Fetch via `getTransaction`, verify shape |

### Pull mode, sponsored (`feePayer: true`)

The client signs **only the authorization entry**, using the legacy credential type — this
spec never mentions CAP-71 at all, unlike x402, and permits nothing but
`sorobanCredentialsAddress`. The transaction's source account is the all-zeros account; the
server replaces it, the sequence number, and the fee at settlement, exactly as in x402.

### Pull mode, unsponsored (`feePayer: false` or absent)

The client builds a **fully signed, network-ready transaction**: a real sequence number
(from the payer's own account), a real fee (derived from a simulation), and
`timeBounds.maxTime` set to the challenge's `expires`. The server submits it unmodified.

### Push mode (`type="hash"`)

The client has already broadcast the transaction itself. The server fetches it via
`getTransaction`, checks its status is `SUCCESS`, and checks the same transfer shape pull
mode does. The spec requires servers to maintain a set of consumed transaction hashes, so a
settled push-mode transaction can't be presented again on a fresh challenge —
`MppServer::settle_credential` takes an `already_consumed` flag for exactly this, since the
replay set itself is the caller's to own (see
[Running an MPP server](../guides/mpp-server.md)).

## Ledger expiration

Both the client and the server derive a ledger expiration from the challenge's `expires`
timestamp: `currentLedger + ceil(remaining_seconds / 5)`. The client actually uses **half**
that allowance — a margin discovered on live testnet, where ledgers closing slower than the
spec's 5-second assumption made a fully-allowance-sized expiry fail the server's own bound
check. See [`sorocharge-mpp/src/client.rs`](https://github.com/sorocharge/sorocharge-core/blob/main/crates/sorocharge-mpp/src/client.rs)
for the exact reasoning.

## Server safety

The sponsored flow's facilitator-safety checks mirror x402's: the server's own address must
not appear as the `from` argument or in any authorization entry, the transaction source must
be the all-zeros account, and a re-simulation must show only the expected transfer
(`sorocharge_signer::verify_transfer_effects`).
