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
    NoAcceptablePaymentRequirements,
    /// A network identifier this crate does not have a CAIP-2 mapping for.
    UnsupportedNetwork { network: String },
    /// `sorocharge-signer` failed to build or sign the charge entry.
    Signing(SorochargeError),
    /// Building the wrapping `TransactionEnvelope` failed (a value did not
    /// fit its XDR-constrained shape).
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
    ///
    /// Audited: all four return sites are in the facilitator's request
    /// validation in `facilitator.rs` (shared by `verify` and `settle`), one
    /// per location listed above — the operation's source account, the
    /// transaction's source account, the transfer's `from` argument, and the
    /// authorization entry's credential address. Each matches this
    /// description exactly; no mismatch found.
    FacilitatorAddressConflict,
    /// A call to Stellar RPC (simulate, send, get-transaction, get-ledger)
    /// failed.
    ///
    /// Audited return sites, all in `facilitator.rs`: `getLatestLedger` and
    /// `simulateTransaction` during request validation, and `getAccount`
    /// (the facilitator's sequence number) and `simulateTransaction` during
    /// `settle`. Each wraps a failed RPC call, matching this description.
    /// Note that a failed `sendTransaction` or `getTransaction` poll is not
    /// reported here: once verification has passed, `settle` reports those
    /// as [`X402Error::SettlementFailed`] instead.
    RpcFailed { reason: String },
    /// The settlement-time simulation-derived fee exceeded the configured
    /// safety ceiling.
    ///
    /// Audited: the only return site is `settle` in `facilitator.rs`, when
    /// the settlement simulation's `min_resource_fee` plus
    /// `FacilitatorConfig::inclusion_buffer_stroops` exceeds
    /// `FacilitatorConfig::max_transaction_fee_stroops`. This matches the
    /// description exactly; no mismatch found.
    FeeExceedsCeiling {
        fee_stroops: i64,
        ceiling_stroops: i64,
    },
    /// Verification succeeded but on-chain settlement failed.
    ///
    /// Audited: the only return site is `settle` in `facilitator.rs`, when
    /// `send_transaction_polling` (submission via `sendTransaction`, then
    /// polling `getTransaction`) returns an error after every verification
    /// check has passed. This matches the description; no mismatch found.
    /// A transaction that is submitted but ends in a status other than
    /// `SUCCESS` does not return this variant: `settle` returns `Ok` with a
    /// `SettlementResponse` whose `success` is `false` and whose
    /// `error_reason` carries that status, per the x402 `/settle` response
    /// shape.
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
