use core::fmt;

use sorocharge_signer::SorochargeError;

/// Every failure `sorocharge-mpp` can produce, on either the client or
/// server side. Each variant names one specific, actionable failure — no
/// bare `String` or `anyhow::Error` at this boundary, and no catch-all.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum MppError {
    /// The underlying HTTP request itself failed.
    ///
    /// Audited return sites, all in `client.rs`: `retry_get`, when every
    /// attempt of the initial `GET` fails at the transport level (`reason`
    /// names the last attempt), and the paid retry in `get_with_payment`,
    /// when that request fails to send. Both match this description. One
    /// deliberate fold-in: `MppClient::new` also returns this variant when
    /// the `reqwest` client fails to build, because no request can be made
    /// without it and the caller's remedy (check the HTTP/TLS environment)
    /// is the same.
    HttpRequestFailed {
        reason: String,
    },
    /// The resource responded with neither `402` nor `200`.
    ///
    /// Audited return sites, all in `get_with_payment` in `client.rs`:
    /// - The initial request, when its status is neither `200` nor `402`
    ///   (5xx after retries, or any other status). Matches this description.
    /// - The paid retry, when its status is anything other than `200`. This
    ///   is a deliberate fold-in: a second `402` there means the server
    ///   rejected the credential, and it is reported with that status
    ///   rather than restarting the payment flow, so the client never pays
    ///   twice for one request.
    UnexpectedStatus {
        status: u16,
    },
    /// A `402` response carried no `WWW-Authenticate: Payment` challenge.
    ///
    /// Audited: the only return site is `get_with_payment` in `client.rs`,
    /// when a `402` response has no `WWW-Authenticate` header at all. That
    /// matches this description. A `WWW-Authenticate` header that is present
    /// but does not use the `Payment` scheme is reported as
    /// [`MppError::InvalidChallenge`] by the header parser, not here.
    MissingChallenge,
    /// The `WWW-Authenticate` header's `Payment` auth-params did not parse,
    /// or omitted a required parameter (`id`, `realm`, `method`, `intent`,
    /// `request`).
    ///
    /// Audited return sites:
    /// - `header::parse_payment_auth_params`: the header does not start with
    ///   the `Payment` scheme, or an auth-param has no `=`. Matches.
    /// - `get_with_payment` in `client.rs`: the header value is not valid
    ///   visible ASCII, or `id` (missing or empty), `realm`, `method`,
    ///   `intent` or `request` is missing. Matches.
    /// - `settle_credential` in `server.rs`: the credential's echoed
    ///   challenge `request` does not decode, or does not equal the
    ///   challenge the server issued. A deliberate fold-in: the echoed
    ///   challenge is the same challenge, coming back from the client, and
    ///   an unusable or altered copy is rejected the same way.
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
    ///
    /// Audited across `client.rs` and `server.rs`; every call site strictly checks
    /// whether the current timestamp has passed the challenge's `expires` field.
    /// No mismatch found.
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
    ///
    /// Audited for issue #302; no mismatch found. Returned by
    /// `parse_payment_transaction` in `tx.rs` and by the defensive
    /// `legacy_credential_fields` re-check in `server.rs`'s pull-mode path.
    /// `parse_payment_transaction` is shared with push mode, but
    /// `settle_push_mode` deliberately maps this variant to
    /// [`VerificationFailed`](Self::VerificationFailed) — a push-mode
    /// transaction has already settled on-chain, so the pull-mode signing
    /// restriction is not re-litigated there — and so callers only ever
    /// receive this variant from pull mode.
    ForbiddenCredentialType,
    /// A push-mode (`type="hash"`) credential was submitted against a
    /// challenge that specified `feePayer: true`, which the spec forbids.
    ///
    /// Audited for issue #303; no mismatch found. Returned only by
    /// `settle_push_mode` in `server.rs`, as its first check — before the
    /// replay store or RPC is consulted.
    PushModeForbidsFeePayer,
    /// In sponsored pull mode (`feePayer: true`), the server's own address
    /// appeared as the payer: either as the SEP-41 transfer's `from`
    /// argument, or as the address on the authorization entry's credential.
    /// Either would have the server pay the charge to itself out of its own
    /// balance while also sponsoring the fee.
    ///
    /// Audited for issue #304; no mismatch found. Both call sites are in
    /// `settle_pull_mode` in `server.rs`, inside the `feePayer: true`
    /// branch. A sponsored transaction whose *source account* is not the
    /// all-zeros placeholder is a different check and returns
    /// [`VerificationFailed`](Self::VerificationFailed), not this variant.
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
                "server's own address appears as the payer of a sponsored transaction"
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
