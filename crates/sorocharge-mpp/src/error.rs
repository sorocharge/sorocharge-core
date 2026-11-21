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
    /// The challenge's `request` field did not base64url-decode to valid
    /// charge-request JSON.
    InvalidChargeRequest {
        reason: String,
    },
    /// A network identifier this crate does not have a CAIP-2 mapping for.
    UnsupportedNetwork {
        network: String,
    },
    /// The challenge has already passed its `expires` timestamp.
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
    UnexpectedTransactionShape {
        reason: String,
    },
    /// An authorization entry used a credential type the spec forbids for
    /// pull mode (anything other than legacy `sorobanCredentialsAddress`).
    ForbiddenCredentialType,
    /// A push-mode (`type="hash"`) credential was submitted against a
    /// challenge that specified `feePayer: true`, which the spec forbids.
    PushModeForbidsFeePayer,
    /// The server's own address appeared where the safety checks forbid it.
    ServerAddressConflict,
    /// A call to Stellar RPC failed.
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
