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
    /// **Audit (issue #306):** one call site — `settle_push_mode` in
    /// `server.rs`, guarded by the `already_consumed` flag the caller
    /// derives from its own replay store. That site returns this variant
    /// exactly when the hash was previously seen, which is precisely "the
    /// pushed transaction hash has already been consumed (replay)."
    /// No mismatch found; audit is clean.
    HashAlreadyConsumed,
    /// A verification check failed: the credential's signature and structural
    /// validation, transfer-amount and recipient checks, timeBounds and
    /// sponsorship constraints, or (for sponsored pull mode) the fee-ceiling
    /// check that guards against submitting a resource-fee above the
    /// operator-configured limit.
    ///
    /// **Audit (issue #307):** call sites span `server.rs` and `client.rs`.
    /// All but one match the original "credential failed a spec verification
    /// check" framing directly — invalid credential shape, mismatched
    /// transfer fields, failed `verify_entry`, failed `verify_transfer_effects`,
    /// invalid timeBounds, or a simulation error.
    ///
    /// One deliberate fold-in: `server.rs` returns this variant when the
    /// sponsored-mode resource fee exceeds `max_transaction_fee_stroops`.
    /// That check is not about the credential itself, but it occurs in the
    /// same pre-settlement verification pass and there is no more specific
    /// variant for it in `MppError`. It is documented here rather than
    /// silently left as an apparent mismatch.
    VerificationFailed {
        reason: String,
    },
    /// Verification succeeded but on-chain settlement failed.
    ///
    /// **Audit (issue #308):** three call sites, all inside
    /// `settle_pull_mode` in `server.rs`, all in the sponsored path or the
    /// unsponsored path after all verification checks have passed:
    /// (1) `send_transaction_polling` returns an error (RPC-level failure),
    /// (2) the same for the unsponsored envelope, and
    /// (3) the polled transaction's final status field is not `"SUCCESS"`.
    /// Every site fires only after the credential has been accepted and
    /// settlement was attempted, which matches "Verification succeeded but
    /// on-chain settlement failed." No mismatch found; audit is clean.
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
