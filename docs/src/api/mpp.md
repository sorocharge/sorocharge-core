# sorocharge-mpp

MPP's `draft-stellar-charge-00`, the `"stellar"` payment method for the `"charge"` intent.
Wire shapes are copied verbatim from `tempoxyz/mpp-specs` (`draft-stellar-charge-00`,
`draft-payment-intent-charge-00`, `draft-httpauth-payment-01`).

## Client

```rust
impl<'a> MppClient<'a> {
    pub fn new(
        rpc: &'a stellar_rpc_client::Client,
        request_timeout: std::time::Duration,
    ) -> Result<Self, MppError>;

    pub async fn get_with_payment(
        &self,
        url: &str,
        signer: &dyn sorocharge_signer::Signer,
        network_passphrase: &str,
    ) -> Result<reqwest::Response, MppError>;
}
```

See [Paying with MPP](../guides/mpp-client.md).

## Server

```rust
impl<'a> MppServer<'a> {
    pub fn new(
        rpc: &'a stellar_rpc_client::Client,
        signer: &'a dyn sorocharge_signer::Signer,
        network_passphrase: String,
        config: MppServerConfig,
    ) -> Self;

    pub fn build_challenge_header(
        &self,
        id: &str,
        realm: &str,
        request: &ChargeRequest,
        expires: chrono::DateTime<chrono::Utc>,
    ) -> Result<String, MppError>;

    pub async fn settle_credential(
        &self,
        credential: &Credential,
        expected: &ChargeRequest,
        current_time: chrono::DateTime<chrono::Utc>,
        already_consumed: bool,
    ) -> Result<Receipt, MppError>;
}
```

```rust
pub struct MppServerConfig {
    pub max_transaction_fee_stroops: i64,  // default 50_000 — not spec-mandated, this
                                            // crate's own conservative choice
    pub inclusion_buffer_stroops: i64,     // default 100
}
```

See [Running an MPP server](../guides/mpp-server.md) for what `settle_credential`
deliberately doesn't own (challenge storage, replay protection) and why.

## Wire types

```rust
pub struct MethodDetails {
    pub network: String,   // "stellar:pubnet" | "stellar:testnet"
    pub fee_payer: bool,   // default false
}

pub struct ChargeRequest {
    pub amount: String,                  // decimal string, base units
    pub currency: String,                // SEP-41 SAC contract (C...)
    pub recipient: String,               // account (G...)
    pub description: Option<String>,
    pub external_id: Option<String>,
    pub method_details: MethodDetails,
}

pub struct Challenge {
    pub id: String,
    pub realm: String,
    pub method: String,                  // "stellar"
    pub intent: String,                  // "charge"
    pub request: String,                 // base64url-encoded ChargeRequest, still encoded
    pub description: Option<String>,
    pub opaque: Option<String>,
    pub digest: Option<String>,
    pub expires: Option<String>,         // RFC 3339
    pub header: Option<String>,          // "Payment-Authorization" if the challenge selected it
}

pub enum Payload {
    Transaction { transaction: String },  // base64 TransactionEnvelope — pull mode
    Hash { hash: String },                // 64-char hex tx hash — push mode
}

pub struct Credential {
    pub challenge: Challenge,
    pub payload: Payload,
    pub source: Option<String>,          // e.g. "did:pkh:stellar:testnet:G..."
}

pub struct Receipt {
    pub method: String,                  // "stellar"
    pub reference: String,               // settled tx hash
    pub status: String,                  // "success"
    pub timestamp: String,               // RFC 3339
    pub external_id: Option<String>,
}
```

### Headers

| Header | Direction | Content |
|---|---|---|
| `WWW-Authenticate` | Server → Client | `Payment id="...", realm="...", method="stellar", intent="charge", request="...", expires="..."` |
| `Authorization` (or `Payment-Authorization`) | Client → Server | `Payment <base64url Credential>` |
| `Payment-Receipt` | Server → Client | `<base64url Receipt>` |

## `MppError`

| Variant | Meaning |
|---|---|
| `HttpRequestFailed { reason }` | The HTTP request itself failed. |
| `UnexpectedStatus { status }` | Neither `402` nor `200`. |
| `MissingChallenge` | No `WWW-Authenticate: Payment` on a `402`. |
| `InvalidChallenge { reason }` | Auth-params didn't parse, or a required one is missing. |
| `UnsupportedMethod { method }` / `UnsupportedIntent { intent }` | Not `"stellar"` / `"charge"`. |
| `InvalidChargeRequest { reason }` | The `request` field didn't decode to a valid charge request. |
| `UnsupportedNetwork { network }` | No CAIP-2 mapping. |
| `ChallengeExpired` | Past the `expires` timestamp. |
| `Signing(SorochargeError)` | `sorocharge-signer` failed. |
| `XdrEncodingFailed { reason }` / `XdrDecodingFailed { reason }` | XDR (de)serialization failed. |
| `InvalidCredential { reason }` | The credential's JSON didn't match the expected shape. |
| `UnexpectedTransactionShape { reason }` | Not a bare SEP-41 transfer. |
| `ForbiddenCredentialType` | Anything other than legacy `sorobanCredentialsAddress` in pull mode. |
| `PushModeForbidsFeePayer` | A `type="hash"` credential against a `feePayer: true` challenge. |
| `ServerAddressConflict` | The server's own address appeared where the safety checks forbid it. |
| `RpcFailed { reason }` | A Stellar RPC call failed. |
| `HashAlreadyConsumed` | A push-mode hash was already settled once. |
| `VerificationFailed { reason }` | The credential failed a verification check. |
| `SettlementFailed { reason }` | Verified, but on-chain submission failed. |
