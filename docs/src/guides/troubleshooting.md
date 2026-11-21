# Troubleshooting errors

Every failure this workspace can produce has its own named error variant — no catch-all
`Other(String)` — so the variant itself tells you which check failed. The
[API reference](../api/signer.md) says what each variant *is*; this page says what it
usually *means* in practice and what to check first when you see it.

## Read the error before the message

- The variant is the useful part. `PayerMismatch` tells you a specific comparison failed;
  the `Display` text is just a human-readable rendering of the same fact.
- Protocol errors wrap engine errors: `X402Error::Signing(inner)` and
  `MppError::Signing(inner)` carry a `SorochargeError`. **Look up the inner variant in the
  signer table below first** — that is where the actual failed check lives.
- Several variants only fire during settlement (the `RpcFailed`, `SettlementFailed`,
  `FeeExceedsCeiling` family). If verification passed and the flow still failed, jump to the
  protocol crate's table rather than re-checking the signed entry.
- Amounts are always integer base units (`i128`), never decimals. A "wrong amount" is
  almost always a decimals-scale or string-conversion problem, not a rounding problem.

## `sorocharge-signer` errors

### Addresses and credentials

| Variant | What this usually means | What to check first |
|---|---|---|
| `InvalidAddress { strkey }` | A string meant to be a Stellar address isn't a valid strkey — wrong prefix, truncated, copied with whitespace, or an address for a different network than expected. | The exact string in the error. `G...` is an account, `C...` is a contract, and both are case-sensitive. Check no role was swapped (asset contract vs recipient). |
| `UnsupportedCredentialType` | The entry's credential arm is one this library never builds or verifies — most often `SOROBAN_CREDENTIALS_SOURCE_ACCOUNT`, occasionally XDR from a newer protocol version than this build understands. | Where the entry came from and what built it. Use `Legacy`, `AddressV2`, or `Delegated`. x402's `exact` scheme forbids source-account credentials; MPP pull mode requires legacy `Address`. |
| `EmptyDelegateSigners` | A `Delegated` credential was built with zero signers, which can never satisfy `__check_auth`. | That the signers list gathered from config or the wire is non-empty before building the entry. |
| `DuplicateDelegateSigner` | The same delegate address appears twice. CAP-71 requires strictly ascending, unique delegate nodes, so the host would reject this entry. | For a duplicate that differs only in whitespace, or the same key listed under two config entries. Deduplicate full strkeys before building. |
| `NoMatchingCredentialNode` | You asked `sign_entry` to sign, but the signer's address is neither the credential's top-level address nor one of its delegates. | `signer.address()` against the entry's authorizing address and its `delegates` list. A common mistake is signing with the payer key for an entry authorized by a different account, or using a contract (`C...`) address as the signer. |

### Expiry

| Variant | What this usually means | What to check first |
|---|---|---|
| `ExpiredEntry { valid_until_ledger, current_ledger }` | The entry's `signature_expiration_ledger` has already passed the ledger number you supplied. | That both values are **ledger sequence numbers**, not timestamps, and that the client is fetching the current ledger rather than reusing a stale one. Add margin for ledger close time when choosing the expiry. |
| `ExpirationExceedsAllowance { signature_expiration_ledger, allowed_until_ledger }` | The entry isn't expired, but it is valid for longer than the payee said it would accept. This is a deliberate anti-overshoot check, not a clock bug. | The client's requested expiry against the server's `maxTimeoutSeconds` / challenge `expires`, and whether a retry reused an older challenge. The client should ask for no more than the server offered. |

### Invocation and charge fields

| Variant | What this usually means | What to check first |
|---|---|---|
| `UnexpectedInvocationShape` | The entry does not authorize exactly one bare SEP-41 `transfer(from, to, amount)` call. It could be another function, the wrong argument count or types, or a legitimate transfer with a smuggled sub-invocation. | Function name is exactly `transfer`; exactly three arguments (address, address, `i128`); `subInvocations` is empty. For x402/MPP, also check the transaction has exactly one `invokeHostFunction` operation. |
| `AssetMismatch` | A different token contract than the charge expected. | The **SAC contract ID** (`C...`) for the asset, not its issuer or asset code, on both sides — and that both sides target the same network. |
| `PayerMismatch` | The entry's authorizing address, its `transfer.from`, or both differ from the expected payer. | That the signing account's `G...` address is the payer the server expects; that the credential's top-level address and `transfer.from` are that same account; and that a fee-sponsoring account (facilitator/server) wasn't confused with the payer. |
| `AmountMismatch` | The amount differs from the expected charge. There is no tolerance: one base unit off fails. | Decimals scale on both sides (SEP-41 assets are commonly 7 decimals), string-to-`i128` conversion, and whether a fee was subtracted from the transfer amount instead of paid separately. |
| `AmountNonPositive` | A zero or negative amount reached a build or verify path. A SEP-41 transfer of zero is not a payment. | Parsing of `"0"` or signed input, and any arithmetic that subtracts a fee or allowance from the requested amount before building the entry. |
| `RecipientMismatch` | The entry pays a different destination than the charge expected. | `pay_to` / `recipient` on both sides. `C...` and `G...` are different recipients even for the same organization; check for an account-vs-contract mix-up. |

### Signatures

| Variant | What this usually means | What to check first |
|---|---|---|
| `InvalidSignature` | No signable node carries a genuine ed25519 signature over the reconstructed preimage. Either the signature is wrong, or it was made for a different payload. | The network passphrase is identical on both sides (it is hashed into the payload); the signing key matches the node's address (not just any funded key); the signer signed the **32-byte hash digest** this library reconstructs, not the raw preimage XDR. For `Delegated`, at least one attached node must be validly signed. |
| `SigningFailed { reason }` | Your `Signer` implementation itself failed, or was asked to sign for something that isn't an Ed25519 account (e.g. a contract address). | The `reason` text from your callback, key permissions/HSM availability, and that `Signer::address()` is the `G...` account that owns the key. |

### Simulation effects

| Variant | What this usually means | What to check first |
|---|---|---|
| `SimulationEventsMalformed { reason }` | The simulation returned events that couldn't be decoded, or a balance event is missing the topics/data a SEP-41 transfer must carry. | That the events are base64 `DiagnosticEvent` XDR from a successful simulation, that the RPC client/protocol version matches the network, and that you're passing the transfer events — not an empty or filtered list. |
| `UnexpectedBalanceChange { reason }` | The simulation moved something other than exactly the expected payment — a second transfer, a different destination, a mint/burn/clawback, or a balance change from another contract. | That the authorization entry contains exactly one transfer, that fees are paid outside the asset being transferred, and that the asset contract's own behaviour matches what you expect. This error is a refusal to settle, not a warning. |
| `ExpectedTransferMissing` | The simulation succeeded but never shows the expected transfer at all. | That the transaction actually invokes the expected SEP-41 contract with the expected arguments, and that the simulation result (not an unrelated cached run) is the one being checked. |

### Encoding and configuration

| Variant | What this usually means | What to check first |
|---|---|---|
| `XdrEncodingFailed { reason }` | A value couldn't fit its XDR-constrained shape — an oversized vector/symbol, an amount or ledger outside its range, or malformed data being wrapped. | The `reason`, plus the amount's i128 range, address types, and collection sizes. This is usually a configuration or caller-input bug rather than a network failure; include the inputs when reporting it. |
| `UnsupportedNetwork { network }` | The network passphrase doesn't match any Stellar network this build knows (currently pubnet and testnet). Signing is network-bound, so an unknown passphrase can't be used. | That the passphrase is copied exactly, including punctuation (`Test SDF Network ; September 2015` / `Public Global Stellar Network ; September 2015`), not a CAIP-2 id or an empty/default value. |

## `sorocharge-x402` errors

| Variant | What this usually means | What to check first |
|---|---|---|
| `HttpRequestFailed { reason }` | The HTTP request never produced a usable response: DNS, TLS, connection refused, or the configured timeout. | The resource URL, `X402Client`'s request timeout, outbound connectivity/proxy, and whether the host is reachable at all. |
| `UnexpectedStatus { status }` | The resource answered with something other than `402` (payment required) or `200` (already paid / free). | The URL and any auth requirements. A `404` usually means the wrong path; a `5xx` means the resource itself failed — retrying the payment will not fix it. |
| `MissingPaymentRequiredHeader` | A `402` response arrived without the `PAYMENT-REQUIRED` header. | That the server actually implements x402 v2, and that no proxy stripped the custom header. Header names are case-insensitive, but the value must be present. |
| `InvalidPaymentRequired { reason }` | The header value is not base64-encoded `PaymentRequired` JSON, or the JSON doesn't match the spec's shape. | That the header wasn't truncated by a proxy or logging step, that it uses standard (not URL-safe) base64, and the server's `x402Version`. |
| `NoAcceptablePaymentRequirements` | None of the server's `accepts[]` entries matched this client: not scheme `exact`, not a supported Stellar network, or no price/asset the client can pay. | The server's `scheme` and `network` values against the client's `network_passphrase` — `stellar:testnet` and `stellar:pubnet` are the only mapped values today. |
| `UnsupportedNetwork { network }` | A CAIP-2 network identifier this crate has no mapping for. | That the passphrase is exactly the network's passphrase (`Test SDF Network ; September 2015` or `Public Global Stellar Network ; September 2015`) and that the server isn't advertising an unsupported network or a typo. |
| `Signing(SorochargeError)` | The shared engine failed while building or signing the charge entry. | The **inner** variant in the signer table above. This error adds no separate meaning of its own. |
| `XdrEncodingFailed { reason }` | Building the wrapping `TransactionEnvelope` failed, as opposed to building the auth entry. | The `reason`: fee, time bounds, memo, or operation fields that don't fit their XDR shape. |
| `InvalidPaymentPayload { reason }` | A `PAYMENT-SIGNATURE` header or `/verify`/`/settle` request body didn't parse as the expected `PaymentPayload` shape. | That the client echoes `accepted` back, that `payload.transaction` is a complete base64 envelope, and that client and facilitator agree on `x402Version`. |
| `XdrDecodingFailed { reason }` | The submitted transaction's base64 XDR couldn't be decoded. | That the value is a complete `TransactionEnvelope` (not just the operation or auth entry), and that it wasn't re-encoded or line-wrapped by an intermediary. |
| `UnexpectedTransactionShape { reason }` | The transaction is not a single bare SEP-41 transfer — wrong operation count, wrong function, wrong arguments, or a sub-invocation. | Exactly one `invokeHostFunction`, function `transfer`, three typed arguments, no sub-invocations. This is a security refusal, so do not retry the same payload. |
| `ForbiddenCredentialType` | The entry uses a credential type x402's Stellar `exact` scheme forbids: `sorobanCredentialsSourceAccount` or `sorobanCredentialsAddressWithDelegates`. | The client must sign with legacy `Address` credentials for this scheme. Delegated credentials belong to a flow x402 does not currently support. |
| `FacilitatorAddressConflict` | The facilitator's own account appears somewhere the safety checks forbid: transaction source, operation source, `from`, or an authorization entry. | Fee-sponsorship configuration. The facilitator may be the transaction source/fee payer, but must not be the transfer's `from` or an authorizing address. Treat a crafted payload that triggers this as hostile. |
| `RpcFailed { reason }` | A Stellar RPC call (simulate, send, get-transaction, get-ledger) failed. | The RPC URL, timeout, credentials, rate limits, and the `reason` — a `429` or `5xx` from the RPC host is different from a rejected transaction. |
| `FeeExceedsCeiling { fee_stroops, ceiling_stroops }` | The fee derived from settlement-time simulation is above `FacilitatorConfig::max_transaction_fee_stroops`. | The configured ceiling, current network fee levels, and the inclusion buffer. Raise the ceiling deliberately if congestion justifies it; don't disable the check. |
| `SettlementFailed { reason }` | Verification passed but the on-chain submission or confirmation failed. | The transaction hash, its `getTransaction` status and result code, and whether it expired or ran out of fee. Retrying should rebuild from a fresh simulation, not resubmit blindly. |

## `sorocharge-mpp` errors

| Variant | What this usually means | What to check first |
|---|---|---|
| `HttpRequestFailed { reason }` | The HTTP request itself failed (connection, TLS, timeout). | The resource URL, timeout, and outbound connectivity/proxy. |
| `UnexpectedStatus { status }` | The resource answered with neither `402` nor `200`. | The URL/auth requirements; a `5xx` means the resource is failing, not that the payment was rejected. |
| `MissingChallenge` | A `402` arrived without a `WWW-Authenticate: Payment` challenge. | That the server implements `draft-httpauth-payment-01`, and that no proxy stripped or rewrote the `WWW-Authenticate` header. |
| `InvalidChallenge { reason }` | The `Payment` auth-params didn't parse, or a required one (`id`, `realm`, `method`, `intent`, `request`) is missing. | Quote/escaping in the header, the `expires` timestamp format, and whether the server emits all required parameters. |
| `UnsupportedMethod { method }` | The challenge named a payment method other than `"stellar"`. | The server's configured payment method; this crate only implements the Stellar method. |
| `UnsupportedIntent { intent }` | The challenge named an intent other than `"charge"`. MPP session/channel mode is deliberately not implemented. | That the server is offering charge intent. Do not attempt session/channel mode with this crate. |
| `InvalidChargeRequest { reason }` | The challenge's `request` field didn't decode to a valid charge request. | That `request` is base64url-encoded (not standard base64), decodes to JSON, and contains `amount`, `currency`, `recipient`, and `methodDetails`. |
| `UnsupportedNetwork { network }` | The challenge's network identifier has no CAIP-2 mapping here. | That the server's network matches the client's `network_passphrase` (`stellar:testnet` / `stellar:pubnet`). |
| `ChallengeExpired` | The challenge's `expires` timestamp has passed. | Clock skew between client and server, retry latency, and whether a stale challenge was reused. Request a fresh challenge and sign again — do not extend or replay the old one. |
| `Signing(SorochargeError)` | The shared engine failed while building or signing the charge entry. | The **inner** variant in the signer table above. |
| `XdrEncodingFailed { reason }` | Building the transaction/envelope failed at the XDR layer. | The `reason`: fee, time bounds, sequence number, or operation shape that doesn't fit XDR. |
| `XdrDecodingFailed { reason }` | A transaction/envelope received over the wire couldn't be decoded. | That `payload.transaction` (or the `getTransaction` result) is a complete base64 envelope and wasn't truncated or re-encoded by an intermediary. |
| `InvalidCredential { reason }` | The credential JSON didn't match the expected shape. | That `challenge` is echoed back fully, `payload` is exactly one of `{transaction}` / `{hash}`, and base64url encoding is used where required. |
| `UnexpectedTransactionShape { reason }` | The transaction is not a single bare SEP-41 `transfer(from, to, amount)`. | One `invokeHostFunction`, function `transfer`, three arguments, no sub-invocations. This is a refusal — don't retry the same credential. |
| `ForbiddenCredentialType` | Pull mode requires legacy `sorobanCredentialsAddress`; a different credential type was used. | The client's `CredentialKind`. A delegated or V2 credential can't be settled under this draft. |
| `PushModeForbidsFeePayer` | A push-mode (`type="hash"`) credential was submitted against a challenge with `feePayer: true`. Push mode can never be fee-sponsored. | Either the server should set `feePayer: false` or the client should use pull mode with a sponsored transaction. Don't "fix" this by disabling the check. |
| `ServerAddressConflict` | The server's own account appears where the safety checks forbid it (transaction source, `from`, or an authorizing node). | Server/fee-sponsorship configuration, and treat a payload that deliberately triggers this as hostile. |
| `RpcFailed { reason }` | A Stellar RPC call failed. | RPC URL, timeout, rate limits, and the `reason`. Distinguish an RPC outage from an on-chain rejection. |
| `HashAlreadyConsumed` | The pushed transaction hash was already settled. This is replay protection working. | Your consumed-hash store and whether the same payment was retried. A retry must create a new transaction, never reuse the old hash. |
| `VerificationFailed { reason }` | The credential failed one of the spec's verification checks, but not a more specific one. | The `reason`, then the challenge/credential match: amount, currency, recipient, network, expiry, and that the credential belongs to this challenge id. |
| `SettlementFailed { reason }` | Verification passed but on-chain submission or confirmation failed. | The transaction hash, `getTransaction` status/result code, ledger expiry, and fee. Rebuild from a fresh simulation rather than resubmitting blindly. |

## Still stuck?

If the variant points at a field mismatch, log both sides of that one comparison — the
entry's decoded value and your expected `ChargeParams` — before changing anything. These
checks are intentionally exact, so the useful question is "which side is wrong?", not
"how do I make the check pass?". If the variant is a security refusal
(`FacilitatorAddressConflict`, `ServerAddressConflict`, `ForbiddenCredentialType`,
`UnexpectedTransactionShape`, `UnexpectedBalanceChange`), treat the payload as hostile
until proven otherwise.
