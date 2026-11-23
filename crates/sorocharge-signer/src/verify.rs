use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use stellar_xdr::{
    AccountId, PublicKey, ScAddress, ScSymbol, ScVal, SorobanAuthorizedFunction,
    SorobanAuthorizedInvocation, SorobanCredentials, Uint256,
};

use crate::entry::{Address, ChargeParams};
use crate::error::SorochargeError;
use crate::sign::{signing_payload, SignedEntry};

struct TransferArgs {
    asset_contract: Address,
    from: Address,
    to: Address,
    amount: i128,
}

/// Pulls the `(contract, from, to, amount)` a SEP-41 `transfer` invocation
/// authorizes out of `invocation`, rejecting anything else: sub-invocations
/// (which could authorize side effects beyond the stated transfer), a
/// different function, or a different argument shape.
fn extract_transfer_args(
    invocation: &SorobanAuthorizedInvocation,
) -> Result<TransferArgs, SorochargeError> {
    if !invocation.sub_invocations.is_empty() {
        return Err(SorochargeError::UnexpectedInvocationShape);
    }
    let SorobanAuthorizedFunction::ContractFn(invoke) = &invocation.function else {
        return Err(SorochargeError::UnexpectedInvocationShape);
    };
    let expected_name: ScSymbol = "transfer"
        .try_into()
        .map(ScSymbol)
        .map_err(|_| SorochargeError::UnexpectedInvocationShape)?;
    if invoke.function_name != expected_name {
        return Err(SorochargeError::UnexpectedInvocationShape);
    }
    let [ScVal::Address(from), ScVal::Address(to), ScVal::I128(amount_parts)] =
        invoke.args.as_slice()
    else {
        return Err(SorochargeError::UnexpectedInvocationShape);
    };
    let amount = (i128::from(amount_parts.hi) << 64) | i128::from(amount_parts.lo);

    Ok(TransferArgs {
        asset_contract: invoke.contract_address.clone(),
        from: from.clone(),
        to: to.clone(),
        amount,
    })
}

/// The address a `SorobanAuthorizationEntry`'s credential authorizes for,
/// alongside every node whose signature could satisfy it: just itself for
/// `Address`/`AddressV2`, or itself plus each delegate for
/// `AddressWithDelegates`.
fn authorizing_address_and_signable_nodes(
    credentials: &SorobanCredentials,
) -> Result<(Address, Vec<(Address, ScVal)>), SorochargeError> {
    match credentials {
        SorobanCredentials::Address(c) => Ok((
            c.address.clone(),
            vec![(c.address.clone(), c.signature.clone())],
        )),
        SorobanCredentials::AddressV2(c) => Ok((
            c.address.clone(),
            vec![(c.address.clone(), c.signature.clone())],
        )),
        SorobanCredentials::AddressWithDelegates(c) => {
            let mut nodes = vec![(
                c.address_credentials.address.clone(),
                c.address_credentials.signature.clone(),
            )];
            nodes.extend(
                c.delegates
                    .iter()
                    .map(|d| (d.address.clone(), d.signature.clone())),
            );
            Ok((c.address_credentials.address.clone(), nodes))
        }
        SorobanCredentials::SourceAccount => Err(SorochargeError::UnsupportedCredentialType),
    }
}

/// Extracts a raw `(public_key, signature)` byte pair from the standard
/// Stellar account signature shape (`ScVal::Vec([ScVal::Map({public_key,
/// signature})])`), or `None` for anything else — the unsigned placeholder
/// (`ScVal::Vec([])` or `ScVal::Void`), a custom `signatureScVal` shape this
/// library doesn't interpret, or malformed data. `None` just means "this
/// node contributes no verifiable signature," not a hard error: a
/// `Delegated` entry with several nodes should still succeed if any other
/// node is validly signed.
fn extract_account_signature(scval: &ScVal) -> Option<([u8; 32], [u8; 64])> {
    let ScVal::Vec(Some(vec)) = scval else {
        return None;
    };
    let [ScVal::Map(Some(map))] = vec.0.as_slice() else {
        return None;
    };
    let mut public_key: Option<[u8; 32]> = None;
    let mut signature: Option<[u8; 64]> = None;
    for entry in map.0.iter() {
        let ScVal::Symbol(key) = &entry.key else {
            continue;
        };
        let ScVal::Bytes(val) = &entry.val else {
            continue;
        };
        let bytes: &[u8] = &val.0;
        if key.0.to_utf8_string_lossy() == "public_key" {
            public_key = bytes.try_into().ok();
        } else if key.0.to_utf8_string_lossy() == "signature" {
            signature = bytes.try_into().ok();
        }
    }
    Some((public_key?, signature?))
}

/// Checks `scval` carries a genuine ed25519 signature over `payload` **made
/// by `address`'s own key** — not just a genuine signature by *some* key.
/// The embedded `public_key` field in the signature SCVal is caller-supplied
/// data, not a verified fact; skipping the comparison against `address`'s
/// actual `AccountId` would let anyone attach a valid signature from an
/// unrelated keypair while the entry still claims `address` as the
/// authorizing account.
fn is_valid_ed25519_signature(address: &Address, payload: &[u8; 32], scval: &ScVal) -> bool {
    let ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(account_key)))) =
        address
    else {
        return false;
    };
    let Some((public_key_bytes, signature_bytes)) = extract_account_signature(scval) else {
        return false;
    };
    if public_key_bytes != *account_key {
        return false;
    }
    let Ok(verifying_key) = VerifyingKey::from_bytes(&public_key_bytes) else {
        return false;
    };
    verifying_key
        .verify(payload, &Signature::from_bytes(&signature_bytes))
        .is_ok()
}

/// Verifies a signed charge entry against the charge it's expected to
/// authorize, failing closed on the first mismatch, checked in this order:
///
/// 1. [`SorochargeError::AmountNonPositive`] — `expected.amount` is zero or
///    negative, which is never a valid charge regardless of the entry.
/// 2. [`SorochargeError::ExpiredEntry`] — `valid_until_ledger` has passed
///    `current_ledger`.
/// 3. [`SorochargeError::ExpirationExceedsAllowance`] — the entry's own
///    `signature_expiration_ledger` is later than `expected.valid_until_ledger`.
///    Checking only "not yet expired" (the previous check) bounds how late
///    is too late; it never bounded how *long-lived* an authorization the
///    caller is willing to accept. Without this, a payer could attach an
///    authorization valid for far longer than the payee asked for, and
///    verify_entry would pass it as long as it hadn't expired yet — found
///    reviewing a downstream binding that needed to read this field and
///    found nothing enforced it.
/// 4. [`SorochargeError::UnexpectedInvocationShape`] — the entry doesn't
///    authorize a single, bare SEP-41 `transfer(from, to, amount)` call.
/// 5. [`SorochargeError::AssetMismatch`] — the asset contract differs.
/// 6. [`SorochargeError::PayerMismatch`] — the authorizing address (the
///    credential's address, which must also be the invocation's `from`)
///    differs from `expected.payer`. This check is not in the CLAUDE.md
///    section 5 checklist verbatim (which lists only asset/amount/recipient
///    alongside expiry and signature), but omitting it would let any signed
///    entry pass as long as its invocation happened to name the right
///    asset/amount/recipient, regardless of whose key actually signed it —
///    added per this project's brief to resolve spec ambiguity toward the
///    more conservative reading.
/// 6. [`SorochargeError::AmountNonPositive`] — the caller's
///    `expected.amount` is zero or negative, so no signed entry could ever
///    legitimately match it; this precondition is checked before the amount
///    diff so the caller's own invalid expectation is reported as such
///    rather than surfacing as [`SorochargeError::AmountMismatch`].
/// 7. [`SorochargeError::AmountMismatch`] — the amount differs.
/// 8. [`SorochargeError::RecipientMismatch`] — the recipient differs.
/// 9. [`SorochargeError::InvalidSignature`] — no signable node (the
///    top-level address, or, for `Delegated`, any delegate) carries a valid
///    ed25519 signature over the reconstructed `HashIdPreimage`. A
///    `Delegated` entry's account-contract-specific signing *policy*
///    (how many delegates must sign, or which) is unknowable here — this
///    only proves at least one attached signature is genuine.
///
/// # Errors
///
/// Returns [`SorochargeError::UnsupportedCredentialType`] for
/// `SOROBAN_CREDENTIALS_SOURCE_ACCOUNT`, which this library never signs and
/// so never expects to verify either.
///
/// # Examples
///
/// ```
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use ed25519_dalek::{Signer as DalekSigner, SigningKey};
/// use sorocharge_signer::{
///     build_charge_entry, parse_address, sign_entry, verify_entry, Address, ChargeParams,
///     CredentialKind, SorochargeError, Signer,
/// };
/// use stellar_xdr::{AccountId, PublicKey, ScAddress, Uint256};
///
/// struct LocalSigner(SigningKey);
///
/// impl Signer for LocalSigner {
///     fn sign_preimage(&self, preimage: &[u8]) -> Result<[u8; 64], SorochargeError> {
///         Ok(self.0.sign(preimage).to_bytes())
///     }
///
///     fn address(&self) -> Address {
///         ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(
///             self.0.verifying_key().to_bytes(),
///         ))))
///     }
/// }
///
/// let signer = LocalSigner(SigningKey::from_bytes(&[0x11; 32]));
/// let params = ChargeParams {
///     asset_contract: parse_address("CAZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGGJH")?,
///     amount: 1_500_000,
///     payer: signer.address(),
///     recipient: parse_address("GCQJVJPUPJTVTABP7FK7RXBNFIKKLSM5EO7JP6DECJ77SOBUKWSPB64N")?,
///     valid_until_ledger: 100_000,
/// };
///
/// let unsigned = build_charge_entry(&params, CredentialKind::AddressV2)?;
/// let signed = sign_entry(unsigned, &signer, "Test SDF Network ; September 2015")?;
/// verify_entry(
///     &signed,
///     &params,
///     99_999,
///     "Test SDF Network ; September 2015",
/// )?;
/// # Ok(())
/// # }
/// ```
pub fn verify_entry(
    entry: &SignedEntry,
    expected: &ChargeParams,
    current_ledger: u32,
    network_passphrase: &str,
) -> Result<(), SorochargeError> {
    // A non-positive `expected.amount` is never a valid charge, independent
    // of the entry being verified. Rejecting it first fails closed before any
    // attacker-supplied XDR is decoded or compared.
    if expected.amount <= 0 {
        return Err(SorochargeError::AmountNonPositive);
    }

    let xdr_entry = entry.as_xdr();
    let (authorizing_address, signable_nodes) =
        authorizing_address_and_signable_nodes(&xdr_entry.credentials)?;

    let (_, signature_expiration_ledger, _) =
        crate::sign::credential_preimage_fields(&xdr_entry.credentials)?;
    if signature_expiration_ledger <= current_ledger {
        return Err(SorochargeError::ExpiredEntry {
            valid_until_ledger: signature_expiration_ledger,
            current_ledger,
        });
    }
    if signature_expiration_ledger > expected.valid_until_ledger {
        return Err(SorochargeError::ExpirationExceedsAllowance {
            signature_expiration_ledger,
            allowed_until_ledger: expected.valid_until_ledger,
        });
    }

    let transfer = extract_transfer_args(&xdr_entry.root_invocation)?;

    if transfer.asset_contract != expected.asset_contract {
        return Err(SorochargeError::AssetMismatch);
    }
    if authorizing_address != expected.payer || transfer.from != expected.payer {
        return Err(SorochargeError::PayerMismatch);
    }
    // A non-positive amount is semantically invalid for a SEP-41 transfer
    // whichever side it appears on, so it is reported distinctly — and
    // before the equality check below, which would otherwise mask it with
    // AmountMismatch whenever only one side is non-positive.
    if transfer.amount <= 0 || expected.amount <= 0 {
        return Err(SorochargeError::AmountNonPositive);
    }
    if transfer.amount != expected.amount {
        return Err(SorochargeError::AmountMismatch);
    }
    if transfer.to != expected.recipient {
        return Err(SorochargeError::RecipientMismatch);
    }

    let payload = signing_payload(
        &xdr_entry.credentials,
        &xdr_entry.root_invocation,
        network_passphrase,
    )?;
    let has_valid_signature = signable_nodes
        .iter()
        .any(|(address, signature)| is_valid_ed25519_signature(address, &payload, signature));
    if !has_valid_signature {
        return Err(SorochargeError::InvalidSignature);
    }

    Ok(())
}

/// Verifies a Delegated entry's signatures against the account's actual
/// threshold policy.
///
/// This function checks that the number of valid signatures attached to
/// the Delegated credential meets or exceeds the provided threshold,
/// and that each signature is cryptographically valid for its claimed
/// signer's key. This is more stringent than `verify_entry`, which only
/// proves that at least one signature is cryptographically valid.
///
/// # Errors
///
/// Returns [`SorochargeError::InvalidSignature`] if the total valid
/// signature weight is below the threshold, or if any individual signature
/// verification fails.
///
/// Returns [`SorochargeError::ExpiredEntry`] or
/// [`SorochargeError::ExpirationExceedsAllowance`] for an entry that has
/// already expired or that outlives `expected.valid_until_ledger` — the
/// same expiry bounds `verify_entry` enforces, checked before any
/// signature work.
///
/// # Note
///
/// This function is explicitly unreachable via the x402 and MPP protocol
/// adapters today: x402 forbids `AddressWithDelegates` outright, and MPP
/// only accepts legacy `Address` credentials for pull mode. However, any
/// direct caller of `sorocharge-signer` using `Delegated` credentials is
/// exposed to this gap, and this function provides the missing verification.
///
/// # Examples
///
/// ```
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use ed25519_dalek::{Signer as DalekSigner, SigningKey};
/// use sorocharge_signer::{
///     build_charge_entry, parse_address, sign_entry, verify_delegated_threshold,
///     Address, ChargeParams, CredentialKind, SorochargeError, Signer,
/// };
/// use stellar_xdr::{AccountId, PublicKey, ScAddress, Uint256};
///
/// struct LocalSigner(SigningKey);
///
/// impl Signer for LocalSigner {
///     fn sign_preimage(&self, preimage: &[u8]) -> Result<[u8; 64], SorochargeError> {
///         Ok(self.0.sign(preimage).to_bytes())
///     }
///     fn address(&self) -> Address {
///         ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(
///             self.0.verifying_key().to_bytes(),
///         ))))
///     }
/// }
///
/// let delegate = LocalSigner(SigningKey::from_bytes(&[0x11; 32]));
/// let params = ChargeParams {
///     asset_contract: parse_address("CAZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGGJH")?,
///     amount: 1_000,
///     payer: parse_address("GDIEVMRSOQV3JKZ2CNUL2RQV4TTNAISKW4NAC25PQUQKGMWJO6DTOAE7")?,
///     recipient: parse_address("GCQJVJPUPJTVTABP7FK7RXBNFIKKLSM5EO7JP6DECJ77SOBUKWSPB64N")?,
///     valid_until_ledger: 100_000,
/// };
///
/// // A single delegate with threshold=1: one valid signature satisfies the policy.
/// let unsigned = build_charge_entry(
///     &params,
///     CredentialKind::Delegated {
///         signers: vec![delegate.address()],
///     },
/// )?;
/// let network = "Test SDF Network ; September 2015";
/// let signed = sign_entry(unsigned, &delegate, network)?;
///
/// let weights = vec![(delegate.address(), 1u32)];
/// verify_delegated_threshold(&signed, &params, 99_999, network, &weights, 1)?;
/// # Ok(())
/// # }
/// ```
pub fn verify_delegated_threshold(
    entry: &SignedEntry,
    expected: &ChargeParams,
    current_ledger: u32,
    network_passphrase: &str,
    signers_with_weights: &[(Address, u32)],
    threshold: u32,
) -> Result<(), SorochargeError> {
    let xdr_entry = entry.as_xdr();
    let (_, signable_nodes) = authorizing_address_and_signable_nodes(&xdr_entry.credentials)?;

    let (_, signature_expiration_ledger, _) =
        crate::sign::credential_preimage_fields(&xdr_entry.credentials)?;
    if signature_expiration_ledger <= current_ledger {
        return Err(SorochargeError::ExpiredEntry {
            valid_until_ledger: signature_expiration_ledger,
            current_ledger,
        });
    }
    if signature_expiration_ledger > expected.valid_until_ledger {
        return Err(SorochargeError::ExpirationExceedsAllowance {
            signature_expiration_ledger,
            allowed_until_ledger: expected.valid_until_ledger,
        });
    }

    let payload = signing_payload(
        &xdr_entry.credentials,
        &xdr_entry.root_invocation,
        network_passphrase,
    )?;

    // Count each delegate's weight at most once. `SignedEntry::from_xdr`
    // performs no validation, so a maliciously crafted entry could list the
    // same delegate address more than once in `signable_nodes` (the
    // duplicate-signer check in `build_delegated_credentials` only applies
    // to entries this library itself built) — without deduplicating here,
    // one genuine signature could be counted twice and inflate the total
    // past `threshold`.
    let mut counted: std::collections::HashSet<Address> = std::collections::HashSet::new();
    let mut valid_weight: u32 = 0;
    for (address, signature) in &signable_nodes {
        if !counted.insert(address.clone()) {
            continue;
        }
        let Some((pk_bytes, sig_bytes)) = extract_account_signature(signature) else {
            continue;
        };
        let Some((_, weight)) = signers_with_weights
            .iter()
            .find(|(addr, _)| addr == address)
        else {
            continue;
        };
        let Ok(verifying_key) = VerifyingKey::from_bytes(&pk_bytes) else {
            continue;
        };
        if verifying_key
            .verify(&payload, &Signature::from_bytes(&sig_bytes))
            .is_ok()
        {
            valid_weight += weight;
        }
    }

    if valid_weight < threshold {
        return Err(SorochargeError::InvalidSignature);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign::build_account_signature_scval;
    use serde::Deserialize;
    use stellar_xdr::{Limits, ReadXdr, SorobanAuthorizationEntry};

    /// A fixture signed by the pinned `@stellar/stellar-sdk`'s own
    /// `authorizeEntry`, reused here to prove `verify_entry` accepts real
    /// reference-SDK output, not just entries this library produced itself.
    #[derive(Deserialize)]
    struct SignedFixture {
        asset_contract: String,
        payer: String,
        recipient: String,
        amount: String,
        valid_until_ledger: u32,
        network_passphrase: String,
        signed_entry_xdr_base64: String,
    }

    fn load_signed_fixture(name: &str) -> SignedFixture {
        let path = format!(
            "{}/../../tests/golden_vectors/fixtures/{name}.json",
            env!("CARGO_MANIFEST_DIR")
        );
        let contents = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("failed to read fixture {path}: {e}"));
        serde_json::from_str(&contents)
            .unwrap_or_else(|e| panic!("failed to parse fixture {path}: {e}"))
    }

    struct Fixture {
        signed: SignedEntry,
        expected: ChargeParams,
        network_passphrase: String,
        valid_until_ledger: u32,
    }

    fn load() -> Fixture {
        let fixture = load_signed_fixture("legacy_transfer_signed");
        let xdr_entry = SorobanAuthorizationEntry::from_xdr_base64(
            &fixture.signed_entry_xdr_base64,
            Limits::none(),
        )
        .expect("fixture XDR should decode");
        Fixture {
            signed: SignedEntry(xdr_entry),
            expected: ChargeParams {
                asset_contract: fixture.asset_contract.parse().unwrap(),
                amount: fixture.amount.parse().unwrap(),
                payer: fixture.payer.parse().unwrap(),
                recipient: fixture.recipient.parse().unwrap(),
                valid_until_ledger: fixture.valid_until_ledger,
            },
            network_passphrase: fixture.network_passphrase,
            valid_until_ledger: fixture.valid_until_ledger,
        }
    }

    #[test]
    fn accepts_a_valid_entry_signed_by_the_reference_sdk() {
        let f = load();
        let result = verify_entry(
            &f.signed,
            &f.expected,
            f.valid_until_ledger - 1,
            &f.network_passphrase,
        );
        assert_eq!(result, Ok(()));
    }

    /// The Delegated counterpart to `accepts_a_valid_entry_signed_by_the_reference_sdk`:
    /// `delegated_transfer_signed.json` carries a genuine signature on *both*
    /// delegate nodes, produced by the pinned SDK's `authorizeEntry` with
    /// `forAddress` targeting each node in turn. This exercises the most
    /// structurally complex credential kind against real reference output,
    /// not just an entry this library signed for itself.
    #[test]
    fn accepts_a_delegated_entry_signed_by_the_reference_sdk() {
        let fixture = load_signed_fixture("delegated_transfer_signed");
        let xdr_entry = SorobanAuthorizationEntry::from_xdr_base64(
            &fixture.signed_entry_xdr_base64,
            Limits::none(),
        )
        .expect("fixture XDR should decode");

        let SorobanCredentials::AddressWithDelegates(credentials) = &xdr_entry.credentials else {
            panic!("delegated fixture should carry AddressWithDelegates credentials");
        };
        assert_eq!(
            credentials.delegates.len(),
            2,
            "fixture should carry exactly the two delegate signers it was generated with"
        );

        let payload = signing_payload(
            &xdr_entry.credentials,
            &xdr_entry.root_invocation,
            &fixture.network_passphrase,
        )
        .expect("fixture payload should reconstruct");
        for delegate in credentials.delegates.iter() {
            assert!(
                is_valid_ed25519_signature(&delegate.address, &payload, &delegate.signature),
                "every delegate node in this fixture should carry a genuine reference-SDK signature"
            );
        }

        let expected = ChargeParams {
            asset_contract: fixture.asset_contract.parse().unwrap(),
            amount: fixture.amount.parse().unwrap(),
            payer: fixture.payer.parse().unwrap(),
            recipient: fixture.recipient.parse().unwrap(),
            valid_until_ledger: fixture.valid_until_ledger,
        };
        let result = verify_entry(
            &SignedEntry(xdr_entry),
            &expected,
            fixture.valid_until_ledger - 1,
            &fixture.network_passphrase,
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn rejects_an_expired_entry() {
        let f = load();
        let result = verify_entry(
            &f.signed,
            &f.expected,
            f.valid_until_ledger,
            &f.network_passphrase,
        );
        assert_eq!(
            result,
            Err(SorochargeError::ExpiredEntry {
                valid_until_ledger: f.valid_until_ledger,
                current_ledger: f.valid_until_ledger,
            })
        );
    }

    #[test]
    fn rejects_an_entry_valid_longer_than_the_caller_allows() {
        let f = load();
        let mut expected = f.expected;
        expected.valid_until_ledger = f.valid_until_ledger - 1;
        let result = verify_entry(
            &f.signed,
            &expected,
            f.valid_until_ledger - 2,
            &f.network_passphrase,
        );
        assert_eq!(
            result,
            Err(SorochargeError::ExpirationExceedsAllowance {
                signature_expiration_ledger: f.valid_until_ledger,
                allowed_until_ledger: f.valid_until_ledger - 1,
            })
        );
    }

    #[test]
    fn rejects_wrong_asset_contract() {
        let f = load();
        let mut expected = f.expected;
        expected.asset_contract =
            ScAddress::Contract(stellar_xdr::ContractId(stellar_xdr::Hash([0x99; 32])));
        let result = verify_entry(
            &f.signed,
            &expected,
            f.valid_until_ledger - 1,
            &f.network_passphrase,
        );
        assert_eq!(result, Err(SorochargeError::AssetMismatch));
    }

    #[test]
    fn rejects_wrong_payer() {
        let f = load();
        let mut expected = f.expected;
        expected.payer = "GCQJVJPUPJTVTABP7FK7RXBNFIKKLSM5EO7JP6DECJ77SOBUKWSPB64N"
            .parse()
            .unwrap();
        let result = verify_entry(
            &f.signed,
            &expected,
            f.valid_until_ledger - 1,
            &f.network_passphrase,
        );
        assert_eq!(result, Err(SorochargeError::PayerMismatch));
    }

    #[test]
    fn rejects_wrong_amount() {
        let f = load();
        let mut expected = f.expected;
        expected.amount += 1;
        let result = verify_entry(
            &f.signed,
            &expected,
            f.valid_until_ledger - 1,
            &f.network_passphrase,
        );
        assert_eq!(result, Err(SorochargeError::AmountMismatch));
    }

    #[test]
    fn rejects_non_positive_amount() {
        let f = load();
        // Test with amount = 0
        let mut expected_zero = f.expected.clone();
        expected_zero.amount = 0;
        let result = verify_entry(
            &f.signed,
            &expected_zero,
            f.valid_until_ledger - 1,
            &f.network_passphrase,
        );
        assert_eq!(
            result,
            Err(SorochargeError::AmountNonPositive),
            "verify_entry should reject amount == 0"
        );
        // Test with negative amount
        let mut expected_neg = f.expected.clone();
        expected_neg.amount = -1;
        let result = verify_entry(
            &f.signed,
            &expected_neg,
            f.valid_until_ledger - 1,
            &f.network_passphrase,
        );
        assert_eq!(
            result,
            Err(SorochargeError::AmountNonPositive),
            "verify_entry should reject amount < 0"
        );
    }

    #[test]
    fn rejects_wrong_recipient() {
        let f = load();
        let mut expected = f.expected;
        expected.recipient = ScAddress::Account(stellar_xdr::AccountId(
            stellar_xdr::PublicKey::PublicKeyTypeEd25519(stellar_xdr::Uint256([0x77; 32])),
        ));
        let result = verify_entry(
            &f.signed,
            &expected,
            f.valid_until_ledger - 1,
            &f.network_passphrase,
        );
        assert_eq!(result, Err(SorochargeError::RecipientMismatch));
    }

    /// Locks the documented check order: expiry is checked before the
    /// asset, amount, recipient, and signature, so an entry that is both
    /// expired *and* wrong on any of those must report `ExpiredEntry`. A
    /// refactor that moved the expiry check below the amount comparison
    /// would start returning `AmountMismatch` here and fail this test.
    #[test]
    fn reports_expiry_before_a_wrong_amount() {
        let f = load();
        let mut expected = f.expected.clone();
        expected.amount += 1;
        let result = verify_entry(
            &f.signed,
            &expected,
            f.valid_until_ledger,
            &f.network_passphrase,
        );
        assert_eq!(
            result,
            Err(SorochargeError::ExpiredEntry {
                valid_until_ledger: f.valid_until_ledger,
                current_ledger: f.valid_until_ledger,
            }),
            "expiry must be reported before the amount mismatch"
        );
    }

    /// Locks the asset check ahead of the payer, amount, and recipient
    /// checks: an entry whose asset, payer, amount, and recipient are all
    /// wrong must report `AssetMismatch` first. Reordering asset after any
    /// of those would fail this test.
    #[test]
    fn reports_asset_before_payer_amount_and_recipient() {
        let f = load();
        let mut expected = f.expected.clone();
        expected.asset_contract =
            ScAddress::Contract(stellar_xdr::ContractId(stellar_xdr::Hash([0x99; 32])));
        expected.payer = ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(
            [0x11; 32],
        ))));
        expected.amount += 1;
        expected.recipient = ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(
            Uint256([0x77; 32]),
        )));
        let result = verify_entry(
            &f.signed,
            &expected,
            f.valid_until_ledger - 1,
            &f.network_passphrase,
        );
        assert_eq!(
            result,
            Err(SorochargeError::AssetMismatch),
            "the asset check must run before payer, amount, and recipient"
        );
    }

    /// Locks the amount check ahead of the recipient and signature checks:
    /// an entry with a wrong amount *and* a wrong recipient must report
    /// `AmountMismatch`, not `RecipientMismatch`.
    #[test]
    fn reports_amount_before_recipient() {
        let f = load();
        let mut expected = f.expected.clone();
        expected.amount += 1;
        expected.recipient = ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(
            Uint256([0x77; 32]),
        )));
        let result = verify_entry(
            &f.signed,
            &expected,
            f.valid_until_ledger - 1,
            &f.network_passphrase,
        );
        assert_eq!(
            result,
            Err(SorochargeError::AmountMismatch),
            "the amount check must run before the recipient check"
        );
    }

    #[test]
    fn rejects_a_tampered_signature() {
        let f = load();
        let xdr_entry = f.signed.as_xdr().clone();
        let SorobanCredentials::Address(mut creds) = xdr_entry.credentials.clone() else {
            panic!("expected legacy Address credentials in this fixture");
        };
        let (public_key, mut signature) = extract_account_signature(&creds.signature)
            .expect("fixture signature should already be well-formed");
        signature[0] ^= 0xFF;
        creds.signature = build_account_signature_scval(public_key, signature).unwrap();
        let tampered = SignedEntry(SorobanAuthorizationEntry {
            credentials: SorobanCredentials::Address(creds),
            root_invocation: xdr_entry.root_invocation,
        });

        let result = verify_entry(
            &tampered,
            &f.expected,
            f.valid_until_ledger - 1,
            &f.network_passphrase,
        );
        assert_eq!(result, Err(SorochargeError::InvalidSignature));
    }

    #[test]
    fn rejects_a_genuine_signature_from_a_key_other_than_the_claimed_account() {
        use ed25519_dalek::{Signer as DalekSigner, SigningKey};

        let f = load();
        let xdr_entry = f.signed.as_xdr().clone();
        let SorobanCredentials::Address(mut creds) = xdr_entry.credentials.clone() else {
            panic!("expected legacy Address credentials in this fixture");
        };

        // Key B signs the exact same payload the fixture's real signature
        // (by key A, the claimed payer) covers — a cryptographically
        // genuine signature, just not one made by the account this entry
        // claims to be authorized by.
        let payload = signing_payload(
            &xdr_entry.credentials,
            &xdr_entry.root_invocation,
            &f.network_passphrase,
        )
        .expect("fixture payload should reconstruct");
        let other_signing_key = SigningKey::from_bytes(&[0x42u8; 32]);
        let other_signature = other_signing_key.sign(&payload).to_bytes();
        creds.signature = build_account_signature_scval(
            other_signing_key.verifying_key().to_bytes(),
            other_signature,
        )
        .unwrap();

        let forged = SignedEntry(SorobanAuthorizationEntry {
            credentials: SorobanCredentials::Address(creds),
            root_invocation: xdr_entry.root_invocation,
        });

        let result = verify_entry(
            &forged,
            &f.expected,
            f.valid_until_ledger - 1,
            &f.network_passphrase,
        );
        assert_eq!(result, Err(SorochargeError::InvalidSignature));
    }

    #[test]
    fn rejects_an_invocation_that_is_not_a_bare_transfer() {
        let f = load();
        let xdr_entry = f.signed.as_xdr().clone();
        let mut root_invocation = xdr_entry.root_invocation.clone();
        // Smuggle in a sub-invocation alongside the transfer.
        root_invocation.sub_invocations = vec![root_invocation.clone()].try_into().unwrap();
        let tampered = SignedEntry(SorobanAuthorizationEntry {
            credentials: xdr_entry.credentials,
            root_invocation,
        });

        let result = verify_entry(
            &tampered,
            &f.expected,
            f.valid_until_ledger - 1,
            &f.network_passphrase,
        );
        assert_eq!(result, Err(SorochargeError::UnexpectedInvocationShape));
    }

    mod delegated_threshold {
        use super::*;
        use crate::entry::{build_charge_entry_with_nonce, CredentialKind, UnsignedEntry};
        use crate::sign::sign_entry;
        use crate::Signer as SorochargeSigner;
        use ed25519_dalek::{Signer as DalekSigner, SigningKey};

        struct LocalSigner {
            seed: [u8; 32],
            address: Address,
        }

        impl SorochargeSigner for LocalSigner {
            fn sign_preimage(&self, preimage: &[u8]) -> Result<[u8; 64], SorochargeError> {
                Ok(SigningKey::from_bytes(&self.seed).sign(preimage).to_bytes())
            }

            fn address(&self) -> Address {
                self.address.clone()
            }
        }

        fn delegate(seed: u8) -> ([u8; 32], Address) {
            let seed_bytes = [seed; 32];
            let verifying_key = SigningKey::from_bytes(&seed_bytes).verifying_key();
            let address = ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(
                verifying_key.to_bytes(),
            ))));
            (seed_bytes, address)
        }

        fn charge_params(payer: Address, valid_until_ledger: u32) -> ChargeParams {
            ChargeParams {
                asset_contract: "CAZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGGJH"
                    .parse()
                    .unwrap(),
                amount: 1_000,
                payer,
                recipient: "GCQJVJPUPJTVTABP7FK7RXBNFIKKLSM5EO7JP6DECJ77SOBUKWSPB64N"
                    .parse()
                    .unwrap(),
                valid_until_ledger,
            }
        }

        /// Builds a Delegated entry over `all_delegates`, signed by only the
        /// delegates at `signing_indices` — one `sign_entry` call per
        /// signer, each folding its signature onto the previous result, the
        /// same way a real multi-signer flow accumulates signatures.
        fn build_signed_delegated(
            all_delegates: &[([u8; 32], Address)],
            signing_indices: &[usize],
            entry_valid_until_ledger: u32,
            expected_valid_until_ledger: u32,
            network_passphrase: &str,
        ) -> (SignedEntry, ChargeParams) {
            let signers: Vec<Address> = all_delegates.iter().map(|(_, a)| a.clone()).collect();
            let payer: Address = "GDIEVMRSOQV3JKZ2CNUL2RQV4TTNAISKW4NAC25PQUQKGMWJO6DTOAE7"
                .parse()
                .unwrap();
            let params = charge_params(payer, expected_valid_until_ledger);
            let mut entry_params = params.clone();
            entry_params.valid_until_ledger = entry_valid_until_ledger;

            let unsigned = build_charge_entry_with_nonce(
                &entry_params,
                CredentialKind::Delegated { signers },
                42,
            )
            .expect("build_charge_entry_with_nonce should succeed for Delegated credentials");

            let mut xdr_entry = unsigned.as_xdr().clone();
            for &i in signing_indices {
                let (seed, address) = all_delegates[i].clone();
                let local_signer = LocalSigner { seed, address };
                let signed =
                    sign_entry(UnsignedEntry(xdr_entry), &local_signer, network_passphrase)
                        .expect("sign_entry should succeed for a matching delegate address");
                xdr_entry = signed.as_xdr().clone();
            }
            (SignedEntry::from_xdr(xdr_entry), params)
        }

        const NETWORK: &str = "Test SDF Network ; September 2015";

        #[test]
        fn accepts_an_entry_meeting_the_threshold() {
            let delegates = [delegate(0x01), delegate(0x02), delegate(0x03)];
            let (signed, params) =
                build_signed_delegated(&delegates, &[0, 1], 1_000, 1_000, NETWORK);
            let weights: Vec<(Address, u32)> =
                delegates.iter().map(|(_, a)| (a.clone(), 1)).collect();

            let result = verify_delegated_threshold(&signed, &params, 500, NETWORK, &weights, 2);
            assert_eq!(result, Ok(()));
        }

        #[test]
        fn rejects_when_signed_weight_is_below_the_threshold() {
            let delegates = [delegate(0x01), delegate(0x02), delegate(0x03)];
            // Only one of three delegates signs; threshold needs two.
            let (signed, params) = build_signed_delegated(&delegates, &[0], 1_000, 1_000, NETWORK);
            let weights: Vec<(Address, u32)> =
                delegates.iter().map(|(_, a)| (a.clone(), 1)).collect();

            let result = verify_delegated_threshold(&signed, &params, 500, NETWORK, &weights, 2);
            assert_eq!(result, Err(SorochargeError::InvalidSignature));
        }

        #[test]
        fn rejects_an_expired_entry() {
            let delegates = [delegate(0x01), delegate(0x02)];
            let (signed, params) =
                build_signed_delegated(&delegates, &[0, 1], 1_000, 1_000, NETWORK);
            let weights: Vec<(Address, u32)> =
                delegates.iter().map(|(_, a)| (a.clone(), 1)).collect();

            // current_ledger == the entry's own expiration ledger: already expired.
            let result = verify_delegated_threshold(&signed, &params, 1_000, NETWORK, &weights, 2);
            assert_eq!(
                result,
                Err(SorochargeError::ExpiredEntry {
                    valid_until_ledger: 1_000,
                    current_ledger: 1_000,
                })
            );
        }

        #[test]
        fn rejects_an_entry_valid_longer_than_the_caller_allows() {
            let delegates = [delegate(0x01), delegate(0x02)];
            // The entry itself is valid until 1_000, but the caller only
            // allows up to 900.
            let (signed, params) = build_signed_delegated(&delegates, &[0, 1], 1_000, 900, NETWORK);
            let weights: Vec<(Address, u32)> =
                delegates.iter().map(|(_, a)| (a.clone(), 1)).collect();

            let result = verify_delegated_threshold(&signed, &params, 500, NETWORK, &weights, 2);
            assert_eq!(
                result,
                Err(SorochargeError::ExpirationExceedsAllowance {
                    signature_expiration_ledger: 1_000,
                    allowed_until_ledger: 900,
                })
            );
        }

        #[test]
        fn does_not_double_count_a_duplicated_delegate_node() {
            // Two delegates, weight 1 each, threshold 2 — a single signer's
            // weight must never be enough on its own.
            let delegates = [delegate(0x01), delegate(0x02)];
            let (signed, params) = build_signed_delegated(&delegates, &[0], 1_000, 1_000, NETWORK);
            let weights: Vec<(Address, u32)> =
                delegates.iter().map(|(_, a)| (a.clone(), 1)).collect();

            // Simulate a malformed/malicious entry — `SignedEntry::from_xdr`
            // performs no validation — where the single signing delegate's
            // node is listed twice in `delegates`, the way
            // `build_delegated_credentials`'s own duplicate check would
            // reject if this library had built the entry itself.
            let SorobanCredentials::AddressWithDelegates(mut creds) =
                signed.as_xdr().credentials.clone()
            else {
                panic!("expected AddressWithDelegates credentials");
            };
            let duplicate = creds.delegates.first().unwrap().clone();
            let mut delegate_vec: Vec<_> = creds.delegates.iter().cloned().collect();
            delegate_vec.push(duplicate);
            creds.delegates = delegate_vec.try_into().unwrap();
            let tampered = SignedEntry::from_xdr(SorobanAuthorizationEntry {
                credentials: SorobanCredentials::AddressWithDelegates(creds),
                root_invocation: signed.as_xdr().root_invocation.clone(),
            });

            let result = verify_delegated_threshold(&tampered, &params, 500, NETWORK, &weights, 2);
            assert_eq!(
                result,
                Err(SorochargeError::InvalidSignature),
                "one real signature listed twice must not be counted as two signers' worth of weight"
            );
        }
    }
}
