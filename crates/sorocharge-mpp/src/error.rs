use core::fmt;

use sorocharge_signer::SorochargeError;

/// Every failure `sorocharge-mpp` can produce, on either the client or
/// server side. Each variant names one specific, actionable failure — no
/// bare `String` or `anyhow::Error` at this boundary, and no catch-all.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum MppError {
    /// The underlying HTTP request itself failed.
    HttpRequestFailed { reason: String },
    /// The resource responded with neither `402` nor `200`.
    UnexpectedStatus { status: u16 },
    /// A `402` response carried no `WWW-Authenticate: Payment` challenge.
    MissingChallenge,
    /// The `WWW-Authenticate` header's `Payment` auth-params did not parse,
    /// or omitted a required parameter (`id`, `realm`, `method`, `intent`,
    /// `request`).
    InvalidChallenge { reason: String },
    /// The challenge named a payment method other than `"stellar"`.
    UnsupportedMethod { method: String },
    /// The challenge named an intent other than `"charge"` (MPP
    /// session/channel mode, which uses a different signing primitive
    /// entirely, is explicitly out of scope for this crate).
    UnsupportedIntent { intent: String },
    /// The challenge's `request` field did not base64url-decode to valid
    /// charge-request JSON.
    InvalidChargeRequest { reason: String },
    /// A network identifier this crate does not have a CAIP-2 mapping for.
    UnsupportedNetwork { network: String },
    /// The challenge has already passed its `expires` timestamp.
    ChallengeExpired,
    /// `sorocharge-signer` returned an error that this crate passes through
    /// unchanged, via `From<SorochargeError>` or the fallback arm in
    /// `network::caip2_for_passphrase`.
    ///
    /// Returned when:
    /// - building the charge authorization entry (`build_charge_entry`) fails
    ///   in `MppClient::get_with_payment`;
    /// - signing that entry (`sign_entry`) fails in the same method;
    /// - the [`Signer`](sorocharge_signer::Signer) fails to sign the outer
    ///   transaction hash, in `sign_transaction`. That runs for the
    ///   client's unsponsored (`feePayer: false`) transaction and for the
    ///   server's sponsored settlement transaction;
    /// - `sorocharge_signer::caip2_for_passphrase` returns any error other
    ///   than `UnsupportedNetwork`. That is a defensive fallback that cannot
    ///   currently trigger, since `UnsupportedNetwork` is the only error
    ///   that function produces.
    ///
    /// Signing and building failures are folded together because
    /// `SorochargeError` already distinguishes them; match on the inner
    /// error to tell them apart.
    Signing(SorochargeError),
    /// Building or serializing an XDR structure failed. Parsing and
    /// base64-decoding XDR is reported as [`MppError::XdrDecodingFailed`]
    /// instead.
    ///
    /// Returned when:
    /// - a transaction-building helper cannot fit a value into its
    ///   XDR-bounded container (the `transfer` symbol, its arguments, the
    ///   auth entries, the operations list, the signature bytes or the
    ///   signatures list);
    /// - the transaction hash cannot be computed while signing;
    /// - a finished transaction envelope cannot be serialized to base64 XDR,
    ///   in `MppClient::get_with_payment`.
    ///
    /// It is also returned for two conditions that are not XDR failures but
    /// have no more specific variant: a signer or payer address that is not
    /// an Ed25519 account (`sign_transaction`; `MppClient::get_with_payment`,
    /// both on the unsponsored path and in a final check that applies to
    /// every payment; and the server's own signer in sponsored
    /// settlement). These are deliberate fold-ins: such an address has no
    /// Ed25519 key to put in the transaction source or signature hint, so it
    /// cannot be encoded as a transaction.
    XdrEncodingFailed { reason: String },
    /// Base64-decoding or parsing an XDR structure failed. Building or
    /// serializing XDR is reported as [`MppError::XdrEncodingFailed`]
    /// instead.
    ///
    /// Returned when:
    /// - the credential's `Payload::Transaction` string is not a valid
    ///   base64 `TransactionEnvelope`, in `MppServer::settle_credential`
    ///   (pull mode);
    /// - the `transaction_data` returned by an RPC simulation is not a valid
    ///   base64 `SorobanTransactionData`, in `MppClient::get_with_payment`
    ///   (unsponsored flow) and in the server's sponsored settlement.
    ///
    /// The first case is untrusted input from the payer; the other two are
    /// RPC responses. Malformed JSON, base64url or challenge parameters are
    /// reported as [`MppError::InvalidChallenge`] or
    /// [`MppError::InvalidChargeRequest`], not this variant, and a
    /// structurally valid envelope of the wrong shape is
    /// [`MppError::UnexpectedTransactionShape`].
    XdrDecodingFailed { reason: String },
    /// A push-mode (`Payload::Hash`) credential's transaction hash is not a
    /// 64-character hex string encoding 32 bytes.
    ///
    /// This is the only place the crate returns this variant
    /// (`MppServer::settle_credential`, push mode, before the hash is looked
    /// up over RPC). This crate never deserializes a credential's JSON
    /// itself: the caller parses the `Credential`, and a malformed
    /// `Payload::Transaction` is reported as
    /// [`MppError::XdrDecodingFailed`] or
    /// [`MppError::UnexpectedTransactionShape`] instead.
    InvalidCredential { reason: String },
    /// The transaction does not authorize a single, bare SEP-41
    /// `transfer(from, to, amount)` call.
    UnexpectedTransactionShape { reason: String },
    /// An authorization entry used a credential type the spec forbids for
    /// pull mode (anything other than legacy `sorobanCredentialsAddress`).
    ForbiddenCredentialType,
    /// A push-mode (`type="hash"`) credential was submitted against a
    /// challenge that specified `feePayer: true`, which the spec forbids.
    PushModeForbidsFeePayer,
    /// The server's own address appeared where the safety checks forbid it.
    ServerAddressConflict,
    /// A call to Stellar RPC failed.
    RpcFailed { reason: String },
    /// The pushed transaction hash has already been consumed (replay).
    HashAlreadyConsumed,
    /// The credential failed one of the spec's verification checks.
    VerificationFailed { reason: String },
    /// Verification succeeded but on-chain settlement failed.
    SettlementFailed { reason: String },
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
