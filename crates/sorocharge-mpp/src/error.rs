use core::fmt;

use sorocharge_signer::SorochargeError;

/// Every failure `sorocharge-mpp` can produce, on either the client or
/// server side. Each variant names one specific, actionable failure — no
/// bare `String` or `anyhow::Error` at this boundary, and no catch-all.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum MppError {
    /// The underlying HTTP request itself failed.
    HttpRequestFailed {
        reason: String,
    },
    /// The resource responded with neither `402` nor `200`.
    UnexpectedStatus {
        status: u16,
    },
    /// A `402` response carried no `WWW-Authenticate: Payment` challenge.
    MissingChallenge,
    /// The `WWW-Authenticate` header's `Payment` auth-params did not parse,
    /// or omitted a required parameter (`id`, `realm`, `method`, `intent`,
    /// `request`).
    InvalidChallenge {
        reason: String,
    },
    /// The challenge named a payment method other than `"stellar"`.
    UnsupportedMethod {
        method: String,
    },
    /// The challenge named an intent other than `"charge"` (MPP
    /// session/channel mode, which uses a different signing primitive
    /// entirely, is explicitly out of scope for this crate).
    UnsupportedIntent {
        intent: String,
    },
    /// The charge request payload failed base64url/JSON decoding, JCS
    /// serialization, or semantic field parsing (`currency`, `amount`, or
    /// `recipient`).
    ///
    /// Returned by:
    /// - `decode_base64url_json` in `client.rs` when the challenge's `request`
    ///   parameter is not valid base64url or does not deserialize into `ChargeRequest`.
    /// - `MppClient` in `client.rs` and `MppServer` in `server.rs` when `currency`,
    ///   `amount`, or `recipient` in the charge request cannot be parsed into
    ///   their respective Stellar address / `i128` types.
    /// - `encode_base64url_jcs` in `header.rs` (via `MppServer::build_challenge_header`)
    ///   if RFC 8785 JCS serialization of the charge request fails.
    /// Audited for issue #294.
    InvalidChargeRequest {
        reason: String,
    },
    /// A network passphrase or CAIP-2 network identifier that this crate does
    /// not support or that does not match the configured Stellar network.
    ///
    /// Returned by:
    /// - `caip2_for_passphrase` in `network.rs` when the configured Stellar
    ///   network passphrase is neither mainnet nor testnet (mapped from
    ///   `SorochargeError::UnsupportedNetwork`).
    /// - `MppClient` in `client.rs` and `MppServer` in `server.rs` when the
    ///   challenge's `method_details.network` CAIP-2 identifier does not match
    ///   the expected CAIP-2 identifier for the active network passphrase.
    /// Audited for issue #295.
    UnsupportedNetwork {
        network: String,
    },
    /// The challenge has already passed its `expires` timestamp.
    ///
    /// Returned by `MppClient` in `client.rs` (when `expires_at <= Utc::now()`)
    /// and by `MppServer` in `server.rs` (when `current_time > expires_at`).
    /// Audited for issue #296; no mismatch found.
    ChallengeExpired,
    /// `sorocharge-signer` failed to build or sign the charge entry.
    Signing(SorochargeError),
    /// Building or parsing an XDR structure failed.
    XdrEncodingFailed {
        reason: String,
    },
    XdrDecodingFailed {
        reason: String,
    },
    /// The credential's JSON did not deserialize into the expected shape.
    InvalidCredential {
        reason: String,
    },
    /// The transaction does not authorize a single, bare SEP-41
    /// `transfer(from, to, amount)` call.
    ///
    /// Returned exclusively by `parse_payment_transaction` in `tx.rs` when the
    /// envelope is not `ENVELOPE_TYPE_TX` (v1), does not contain exactly one
    /// `InvokeHostFunction` operation invoking `transfer` with 3 arguments
    /// (`address, address, i128`), or does not carry a single matching
    /// `SorobanAuthorizationEntry` with no sub-invocations.
    /// Audited for issue #301; no mismatch found.
    UnexpectedTransactionShape {
        reason: String,
    },
    /// An authorization entry used a credential type the spec forbids for
    /// pull mode (anything other than `SorobanCredentials::Address`).
    ///
    /// Returned by `parse_payment_transaction` in `tx.rs` and `extract_auth_signer`
    /// in `server.rs` when `auth_entry.credentials` is not
    /// `SorobanCredentials::Address`. (In push mode, `settle_push_mode` in
    /// `server.rs` explicitly tolerates this variant because the transaction has
    /// already settled on-chain.)
    /// Audited for issue #302; no mismatch found.
    ForbiddenCredentialType,
    /// A push-mode (`type="hash"`) credential was submitted against a
    /// challenge that specified `feePayer: true`, which the spec forbids.
    ///
    /// Returned by `settle_push_mode` in `server.rs` when
    /// `expected.method_details.fee_payer` is `true`.
    /// Audited for issue #303; no mismatch found.
    PushModeForbidsFeePayer,
    /// The server's own address appeared as the transfer sender (`transfer.from`)
    /// or fee/auth payer (`params.payer`) in pull mode, which the server-side
    /// self-payment safety checks forbid.
    ///
    /// Returned by `settle_pull_mode` in `server.rs` when `transfer.from == server`
    /// or `params.payer == server`.
    /// Audited for issue #304; no mismatch found.
    ServerAddressConflict,
    /// A call to Stellar RPC failed at the transport or RPC response layer.
    ///
    /// Returned by `MppClient` in `client.rs` (`get_latest_ledger`, `get_account`,
    /// `simulate_transaction_envelope`) and `MppServer` in `server.rs`
    /// (`get_transaction`, `get_latest_ledger`, `simulate_transaction_envelope`,
    /// `get_account`) when a Stellar RPC request returns an error.
    /// Audited for issue #305; no mismatch found.
    RpcFailed {
        reason: String,
    },
    /// The pushed transaction hash has already been consumed (replay).
    ///
    /// Returned by `settle_push_mode` in `server.rs` when the caller's replay
    /// store indicates that the submitted transaction hash was previously consumed.
    /// Audited for issue #306; no mismatch found.
    HashAlreadyConsumed,
    /// A verification check failed: structural or signature validation of the
    /// credential, transfer parameters (recipient, amount, asset), time bounds,
    /// simulation effects, or server fee ceiling constraints.
    ///
    /// Call sites span `client.rs` and `server.rs`. All sites check conformance
    /// with the MPP specification or simulation outcomes, except for one
    /// deliberate fold-in: in sponsored pull mode, `server.rs` returns this
    /// variant if the simulated fee exceeds the server's configured
    /// `max_transaction_fee_stroops` ceiling, as no separate error variant exists.
    /// Audited for issue #307.
    VerificationFailed {
        reason: String,
    },
    /// Verification succeeded but on-chain settlement failed.
    ///
    /// Returned by `settle_pull_mode` in `server.rs` when RPC transaction
    /// submission or polling fails, or when the final on-chain transaction status
    /// is not `"SUCCESS"`. All call sites execute strictly after all verification
    /// checks have passed.
    /// Audited for issue #308; no mismatch found.
    SettlementFailed {
        reason: String,
    },
}

impl fmt::Display for MppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HttpRequestFailed { reason } => write!(f, "HTTP request failed: {reason}"),
            Self::UnexpectedStatus { status } => {
                write!(f, "unexpected HTTP status {status} (expected 402 or 200)")
            }
            Self::MissingChallenge => {
                write!(
                    f,
                    "402 response carried no WWW-Authenticate: Payment challenge"
                )
            }
            Self::InvalidChallenge { reason } => write!(f, "invalid challenge: {reason}"),
            Self::UnsupportedMethod { method } => write!(f, "unsupported method: {method}"),
            Self::UnsupportedIntent { intent } => write!(f, "unsupported intent: {intent}"),
            Self::InvalidChargeRequest { reason } => {
                write!(f, "invalid charge request: {reason}")
            }
            Self::UnsupportedNetwork { network } => write!(f, "unsupported network: {network}"),
            Self::ChallengeExpired => write!(f, "challenge has expired"),
            Self::Signing(e) => write!(f, "signing failed: {e}"),
            Self::XdrEncodingFailed { reason } => write!(f, "XDR encoding failed: {reason}"),
            Self::XdrDecodingFailed { reason } => write!(f, "XDR decoding failed: {reason}"),
            Self::InvalidCredential { reason } => write!(f, "invalid credential: {reason}"),
            Self::UnexpectedTransactionShape { reason } => {
                write!(f, "unexpected transaction shape: {reason}")
            }
            Self::ForbiddenCredentialType => write!(
                f,
                "authorization entry must use credential type sorobanCredentialsAddress only"
            ),
            Self::PushModeForbidsFeePayer => write!(
                f,
                "push mode (type=\"hash\") cannot be used when feePayer is true"
            ),
            Self::ServerAddressConflict => write!(
                f,
                "server's own address appears where the safety checks forbid it"
            ),
            Self::RpcFailed { reason } => write!(f, "Stellar RPC call failed: {reason}"),
            Self::HashAlreadyConsumed => write!(f, "transaction hash has already been consumed"),
            Self::VerificationFailed { reason } => write!(f, "verification failed: {reason}"),
            Self::SettlementFailed { reason } => write!(f, "settlement failed: {reason}"),
        }
    }
}

impl std::error::Error for MppError {}

impl From<SorochargeError> for MppError {
    fn from(e: SorochargeError) -> Self {
        Self::Signing(e)
    }
}
