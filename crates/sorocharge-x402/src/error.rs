use core::fmt;

use sorocharge_signer::SorochargeError;

/// Every failure `sorocharge-x402` can produce, on either the client or the
/// facilitator side. Each variant names one specific, actionable failure —
/// no bare `String` or `anyhow::Error` at this boundary, and no catch-all.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum X402Error {
    /// An HTTP request to the resource server was attempted and failed at
    /// the transport level (connection, TLS, timeout) — no HTTP response
    /// was received. Returned for the initial unpaid `GET` (after its
    /// bounded retries are exhausted) and for the payment-bearing retry.
    ///
    /// A failure on the payment-bearing retry means the signed credential
    /// may already have reached the server; see
    /// [`X402Error::UnexpectedStatusAfterPayment`] for why a caller must not
    /// blindly re-sign and resend.
    HttpRequestFailed { reason: String },
    /// The HTTP client itself could not be constructed (for example, the
    /// TLS backend failed to initialise). No request was ever attempted.
    ///
    /// Distinct from [`X402Error::HttpRequestFailed`] because it is a local,
    /// non-transient configuration failure: retrying the same call will not
    /// succeed, whereas a failed request may.
    HttpClientBuildFailed { reason: String },
    /// The initial, unpaid request to the resource responded with neither
    /// `402` (payment required) nor `200` (already paid / free), which this
    /// client does not know how to continue from. No payment credential has
    /// been built or sent when this is returned.
    UnexpectedStatus { status: u16 },
    /// The payment-bearing retry (the request carrying `PAYMENT-SIGNATURE`)
    /// responded with something other than `200`. A `402` here means the
    /// server rejected the credential; any other status (e.g. a `5xx`) is
    /// ambiguous.
    ///
    /// Distinct from [`X402Error::UnexpectedStatus`] because a signed
    /// credential *has* been sent: the server may have settled it before
    /// failing. A caller must not blindly re-sign and resend on this error
    /// without first confirming on-chain whether the payment settled.
    UnexpectedStatusAfterPayment { status: u16 },
    /// A `402` response carried no `PAYMENT-REQUIRED` header.
    MissingPaymentRequiredHeader,
    /// The server's payment terms in the `PAYMENT-REQUIRED` header were
    /// malformed. Specifically, one of:
    ///
    /// - the header value was not visible ASCII (so it cannot be base64);
    /// - it did not base64-decode;
    /// - the decoded bytes were not valid `PaymentRequired` JSON;
    /// - the `accepts[]` entry selected for this network had an `asset` or
    ///   `payTo` that is not a valid Stellar address, or an `amount` that is
    ///   not a positive `i128` base-unit integer.
    ///
    /// The last case is a deliberate fold-in rather than its own variant:
    /// the JSON decoded, but the terms it carries are equally unusable, and
    /// the caller's only correct action is identical in every case — do not
    /// pay, the server's challenge is broken. `reason` names which check
    /// failed for diagnostics.
    InvalidPaymentRequired { reason: String },
    /// None of the server's `accepts[]` entries name the `exact` scheme on
    /// a Stellar network this client supports (`stellar:pubnet` /
    /// `stellar:testnet`, matched against the network passphrase given).
    ///
    /// Audited: the only return site is `X402Client`'s requirement selection
    /// in `client.rs`, when no `accepts[]` entry has `scheme == "exact"` and
    /// a `network` equal to the CAIP-2 identifier of the given passphrase.
    /// That matches this description exactly; no mismatch found.
    NoAcceptablePaymentRequirements,
    /// A network identifier this crate does not have a CAIP-2 mapping for.
    ///
    /// Audited return sites:
    /// - `network::caip2_for_passphrase` (reached from `client.rs` and
    ///   `facilitator.rs`), when the passphrase is neither mainnet's nor
    ///   testnet's; `network` is that passphrase. Matches this description.
    /// - The facilitator's request validation in `facilitator.rs`, when
    ///   `paymentRequirements.network` is not the CAIP-2 identifier of the
    ///   facilitator's own configured network; `network` is the requested
    ///   identifier. This is a deliberate fold-in: a well-formed identifier
    ///   such as `stellar:testnet` sent to a mainnet facilitator is reported
    ///   here too, because in both cases this facilitator cannot settle on
    ///   the requested network and the caller's correct action is the same.
    UnsupportedNetwork { network: String },
    /// `sorocharge-signer` failed to build or sign the charge entry.
    ///
    /// Audited return sites:
    /// - `?` on `build_charge_entry` / `sign_entry` in `client.rs`, via the
    ///   `From<SorochargeError>` impl below. Matches this description.
    /// - `?` on `Signer::sign_preimage` in `tx::sign_transaction`, used by
    ///   the facilitator to sign the settlement transaction rather than a
    ///   charge entry. A deliberate fold-in: it is the same signer interface
    ///   failing, so it is reported the same way.
    /// - `network::caip2_for_passphrase`, for any `SorochargeError` from
    ///   `sorocharge_signer::caip2_for_passphrase` other than
    ///   `UnsupportedNetwork` (which maps to [`X402Error::UnsupportedNetwork`]).
    ///   That function returns no other variant today, so this arm is
    ///   unreachable in practice and only keeps the mapping total.
    Signing(SorochargeError),
    /// Building the wrapping `TransactionEnvelope` failed (a value did not
    /// fit its XDR-constrained shape).
    ///
    /// Audited return sites: every bounded-XDR conversion in `tx.rs` (the
    /// `transfer` symbol, transfer args, auth entries, operations, signature
    /// bytes and the signatures vector), the transaction hash in
    /// `tx::sign_transaction`, and the base64 XDR encoding of the payment
    /// envelope in `client.rs` — all match this description. One deliberate
    /// fold-in: `tx::sign_transaction` also returns this variant when the
    /// facilitator's signer address is not an Ed25519 account, because the
    /// envelope's `DecoratedSignature` hint cannot be built from any other
    /// address shape.
    XdrEncodingFailed { reason: String },
    /// The `PAYMENT-SIGNATURE` (or `/verify` / `/settle` request) payload's
    /// JSON did not deserialize into the expected shape.
    InvalidPaymentPayload { reason: String },
    /// The submitted transaction's XDR failed to decode.
    XdrDecodingFailed { reason: String },
    /// The transaction does not authorize a single, bare SEP-41
    /// `transfer(from, to, amount)` call — wrong operation count, wrong
    /// function, wrong argument count/types, or a smuggled sub-invocation.
    UnexpectedTransactionShape { reason: String },
    /// An authorization entry used a credential type the `exact` scheme on
    /// Stellar forbids (`sorobanCredentialsSourceAccount` or
    /// `sorobanCredentialsAddressWithDelegates`).
    ForbiddenCredentialType,
    /// The facilitator's own address appeared where the spec's safety
    /// checks forbid it (transaction source, operation source, `from`
    /// argument, or an authorization entry) — a sign of an attempt to trick
    /// the fee-sponsoring facilitator into an unintended transfer.
    FacilitatorAddressConflict,
    /// A call to Stellar RPC (simulate, send, get-transaction, get-ledger)
    /// failed.
    RpcFailed { reason: String },
    /// The settlement-time simulation-derived fee exceeded the configured
    /// safety ceiling.
    FeeExceedsCeiling {
        fee_stroops: i64,
        ceiling_stroops: i64,
    },
    /// Verification succeeded but on-chain settlement failed.
    SettlementFailed { reason: String },
}

impl fmt::Display for X402Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HttpRequestFailed { reason } => write!(f, "HTTP request failed: {reason}"),
            Self::HttpClientBuildFailed { reason } => {
                write!(f, "failed to build HTTP client: {reason}")
            }
            Self::UnexpectedStatus { status } => {
                write!(f, "unexpected HTTP status {status} (expected 402 or 200)")
            }
            Self::UnexpectedStatusAfterPayment { status } => write!(
                f,
                "unexpected HTTP status {status} on the payment-bearing retry (expected 200); \
                 the credential was sent and may have settled"
            ),
            Self::MissingPaymentRequiredHeader => {
                write!(f, "402 response is missing the PAYMENT-REQUIRED header")
            }
            Self::InvalidPaymentRequired { reason } => {
                write!(f, "invalid PAYMENT-REQUIRED header: {reason}")
            }
            Self::NoAcceptablePaymentRequirements => write!(
                f,
                "no accepts[] entry names the exact scheme on a supported Stellar network"
            ),
            Self::UnsupportedNetwork { network } => {
                write!(f, "unsupported network: {network}")
            }
            Self::Signing(e) => write!(f, "signing failed: {e}"),
            Self::XdrEncodingFailed { reason } => write!(f, "XDR encoding failed: {reason}"),
            Self::InvalidPaymentPayload { reason } => {
                write!(f, "invalid payment payload: {reason}")
            }
            Self::XdrDecodingFailed { reason } => write!(f, "XDR decoding failed: {reason}"),
            Self::UnexpectedTransactionShape { reason } => {
                write!(f, "unexpected transaction shape: {reason}")
            }
            Self::ForbiddenCredentialType => write!(
                f,
                "authorization entry uses a credential type the exact scheme on Stellar forbids"
            ),
            Self::FacilitatorAddressConflict => write!(
                f,
                "facilitator's own address appears where the safety checks forbid it"
            ),
            Self::RpcFailed { reason } => write!(f, "Stellar RPC call failed: {reason}"),
            Self::FeeExceedsCeiling {
                fee_stroops,
                ceiling_stroops,
            } => write!(
                f,
                "settlement fee {fee_stroops} stroops exceeds ceiling {ceiling_stroops} stroops"
            ),
            Self::SettlementFailed { reason } => write!(f, "settlement failed: {reason}"),
        }
    }
}

impl std::error::Error for X402Error {}

impl From<SorochargeError> for X402Error {
    fn from(e: SorochargeError) -> Self {
        Self::Signing(e)
    }
}
