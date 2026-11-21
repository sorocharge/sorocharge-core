use stellar_xdr::{
    ContractEventBody, ContractEventType, ContractId, DiagnosticEvent, Limits, ReadXdr, ScAddress,
    ScVal,
};

use crate::entry::Address;
use crate::error::SorochargeError;

/// Event names that move a balance. Of these, only `transfer` and the two
/// issuer-side forms it degenerates into (`mint`, `burn`) can describe the
/// expected payment; the rest are reported as unexpected.
const BALANCE_EVENT_NAMES: [&str; 4] = ["transfer", "mint", "burn", "clawback"];

fn symbol_name(value: &ScVal) -> Option<String> {
    match value {
        ScVal::Symbol(sym) => Some(sym.0.to_utf8_string_lossy()),
        _ => None,
    }
}

fn i128_from_scval(value: &ScVal) -> Option<i128> {
    match value {
        ScVal::I128(parts) => Some((i128::from(parts.hi) << 64) | i128::from(parts.lo)),
        _ => None,
    }
}

/// Checks that a simulation's events describe exactly one balance change:
/// the expected SEP-41 transfer of `amount` from `payer` to `recipient` on
/// `asset_contract`.
///
/// A Stellar Asset Contract does not report every transfer as `transfer`: per
/// CAP-67, a transfer whose **sender** is the asset's own issuer is emitted as
/// `mint`, and one whose **recipient** is the issuer is emitted as `burn`, so
/// a legitimate payment to or from an issuer never produces a `transfer`
/// event at all. Both shapes are therefore accepted, but only as the expected
/// payment in disguise — a `mint` must name `recipient` as its `to` topic and
/// carry `amount`, a `burn` must name `payer` as its `from` topic and carry
/// `amount`. The host emits `mint` only when the sender is the issuer, so an
/// accepted `mint` is a payment the issuer genuinely made; likewise an
/// accepted `burn` is a payment genuinely made to it.
///
/// Any other balance-moving event fails the check — a transfer to a different
/// party, a second balance movement, a `mint`/`burn` naming anyone but the
/// expected counterparty, a clawback, or any balance event from a contract
/// other than the asset. The spec asks for exactly this ("any other balance
/// change MUST cause verification to fail"), and it matters most when the
/// fee-sponsoring server is the party that signs.
///
/// `events` are base64 `DiagnosticEvent` XDR, as returned by a simulation.
/// The shapes checked here are the ones the live Stellar host emits for a
/// Stellar Asset Contract — `[transfer, from, to]`, `[mint, to]` and
/// `[burn, from]` topics (each followed by the asset's SEP-11 identifier when
/// the contract is a SAC), with `i128` data. All three are verified against
/// real testnet transaction events in this crate's tests.
///
/// # Examples
///
/// ```rust
/// use serde::Deserialize;
///
/// #[derive(Deserialize)]
/// struct Fixture {
///     asset_contract: String,
///     payer: String,
///     recipient: String,
///     amount: String,
///     diagnostic_events_xdr_base64: Vec<String>,
/// }
///
/// let fixture: Fixture = serde_json::from_str(include_str!(
///     concat!(
///         env!("CARGO_MANIFEST_DIR"),
///         "/../../tests/golden_vectors/fixtures/sac_native_transfer_events.json"
///     )
/// ))
/// .unwrap();
///
/// let asset = fixture.asset_contract.parse().unwrap();
/// let payer = fixture.payer.parse().unwrap();
/// let recipient = fixture.recipient.parse().unwrap();
/// let amount = fixture.amount.parse().unwrap();
///
/// sorocharge_signer::verify_transfer_effects(
///     &fixture.diagnostic_events_xdr_base64,
///     &asset,
///     &payer,
///     &recipient,
///     amount,
/// )
/// .unwrap();
/// ```
///
/// # Errors
///
/// - [`SorochargeError::SimulationEventsMalformed`] if an event does not
///   decode, or a balance event lacks the expected topics or data.
/// - [`SorochargeError::UnexpectedBalanceChange`] for any extra or
///   out-of-place balance movement.
/// - [`SorochargeError::ExpectedTransferMissing`] if the expected transfer
///   does not appear.
pub fn verify_transfer_effects(
    events: &[String],
    asset_contract: &Address,
    payer: &Address,
    recipient: &Address,
    amount: i128,
) -> Result<(), SorochargeError> {
    let ScAddress::Contract(ContractId(asset_hash)) = asset_contract else {
        return Err(SorochargeError::UnexpectedBalanceChange {
            reason: "asset address is not a contract".to_string(),
        });
    };

    let mut effects: Vec<BalanceEffect> = Vec::new();
    for encoded in events {
        let event = DiagnosticEvent::from_xdr_base64(encoded, Limits::none()).map_err(|e| {
            SorochargeError::SimulationEventsMalformed {
                reason: format!("event does not decode: {e}"),
            }
        })?;
        if event.event.type_ != ContractEventType::Contract {
            continue;
        }
        let ContractEventBody::V0(body) = &event.event.body;
        let Some(name) = body.topics.first().and_then(symbol_name) else {
            continue;
        };
        if !BALANCE_EVENT_NAMES.contains(&name.as_str()) {
            continue;
        }

        let from_asset = matches!(&event.event.contract_id, Some(ContractId(h)) if h == asset_hash);
        if !from_asset {
            return Err(SorochargeError::UnexpectedBalanceChange {
                reason: format!("balance event \"{name}\" from a contract other than the asset"),
            });
        }
        let effect = match name.as_str() {
            "transfer" => {
                let (Some(ScVal::Address(from)), Some(ScVal::Address(to))) =
                    (body.topics.get(1), body.topics.get(2))
                else {
                    return Err(SorochargeError::SimulationEventsMalformed {
                        reason: "transfer event lacks from/to address topics".to_string(),
                    });
                };
                BalanceEffect::Transfer {
                    from: from.clone(),
                    to: to.clone(),
                    amount: event_amount(&name, &body.data)?,
                }
            }
            // `[mint, to, …]`: the host emits this only when the sender is the
            // asset's issuer, so the missing half of the movement is the payer.
            "mint" => {
                let Some(ScVal::Address(to)) = body.topics.get(1) else {
                    return Err(SorochargeError::SimulationEventsMalformed {
                        reason: "mint event lacks a `to` address topic".to_string(),
                    });
                };
                BalanceEffect::Mint {
                    to: to.clone(),
                    amount: event_amount(&name, &body.data)?,
                }
            }
            // `[burn, from, …]`: the host emits this only when the recipient
            // is the asset's issuer, so the missing half is the recipient.
            "burn" => {
                let Some(ScVal::Address(from)) = body.topics.get(1) else {
                    return Err(SorochargeError::SimulationEventsMalformed {
                        reason: "burn event lacks a `from` address topic".to_string(),
                    });
                };
                BalanceEffect::Burn {
                    from: from.clone(),
                    amount: event_amount(&name, &body.data)?,
                }
            }
            _ => {
                return Err(SorochargeError::UnexpectedBalanceChange {
                    reason: format!("\"{name}\" event in a payment"),
                });
            }
        };
        effects.push(effect);
    }

    if effects.is_empty() {
        return Err(SorochargeError::ExpectedTransferMissing);
    }
    if effects.len() > 1 {
        return Err(SorochargeError::UnexpectedBalanceChange {
            reason: format!("{} balance events, expected exactly one", effects.len()),
        });
    }
    let matches_expected = match &effects[0] {
        BalanceEffect::Transfer {
            from,
            to,
            amount: event_amount,
        } => from == payer && to == recipient && *event_amount == amount,
        BalanceEffect::Mint {
            to,
            amount: event_amount,
        } => to == recipient && *event_amount == amount,
        BalanceEffect::Burn {
            from,
            amount: event_amount,
        } => from == payer && *event_amount == amount,
    };
    if !matches_expected {
        return Err(SorochargeError::UnexpectedBalanceChange {
            reason: "the balance change differs from the expected payer, recipient, or amount"
                .to_string(),
        });
    }
    Ok(())
}

/// One balance movement found in a simulation's events.
///
/// A Stellar Asset Contract splits a transfer into three event shapes (per
/// CAP-67): `transfer` when neither side is the issuer, `mint` when the sender
/// is, and `burn` when the recipient is. Keeping the shapes distinct — rather
/// than flattening each into a `(from, to, amount)` triple — is what lets the
/// check below insist on the one counterparty the event actually names.
enum BalanceEffect {
    Transfer {
        from: Address,
        to: Address,
        amount: i128,
    },
    Mint {
        to: Address,
        amount: i128,
    },
    Burn {
        from: Address,
        amount: i128,
    },
}

/// Reads the movement's `i128` amount, naming the event and its own shape in
/// the error so a caller can tell which of the three shapes was malformed.
fn event_amount(name: &str, data: &ScVal) -> Result<i128, SorochargeError> {
    i128_from_scval(data).ok_or_else(|| SorochargeError::SimulationEventsMalformed {
        reason: format!("{name} event data is not an i128"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use stellar_xdr::{ContractEventBody as Body, ScSymbol, VecM, WriteXdr};

    #[derive(Deserialize)]
    struct Fixture {
        asset_contract: String,
        payer: String,
        recipient: String,
        amount: String,
        diagnostic_events_xdr_base64: Vec<String>,
    }

    fn load_named(file: &str) -> Fixture {
        let path = format!(
            "{}/../../tests/golden_vectors/fixtures/{file}",
            env!("CARGO_MANIFEST_DIR")
        );
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    }

    fn load() -> Fixture {
        load_named("sac_native_transfer_events.json")
    }

    /// The issuer side of a real testnet SAC transfer: the sender is the
    /// asset's issuer, so the host emits `mint` rather than `transfer`.
    fn load_issuer_mint() -> Fixture {
        load_named("sac_issuer_mint_events.json")
    }

    /// The other direction of the same real testnet transaction: the recipient
    /// is the asset's issuer, so the host emits `burn`.
    fn load_issuer_burn() -> Fixture {
        load_named("sac_issuer_burn_events.json")
    }

    /// An account address that appears in none of the fixtures.
    fn someone_else() -> Address {
        "GCQJVJPUPJTVTABP7FK7RXBNFIKKLSM5EO7JP6DECJ77SOBUKWSPB64N"
            .parse()
            .unwrap()
    }

    fn is_named_event(encoded: &str, name: &str) -> bool {
        let event = DiagnosticEvent::from_xdr_base64(encoded, Limits::none()).unwrap();
        let Body::V0(v0) = &event.event.body;
        event.event.type_ == ContractEventType::Contract
            && v0.topics.first().and_then(symbol_name).as_deref() == Some(name)
    }

    fn is_transfer_event(encoded: &str) -> bool {
        is_named_event(encoded, "transfer")
    }

    /// Rewrites the first contract-transfer event through `edit`, returning its encoding.
    fn edited_transfer(encoded: &str, edit: impl FnOnce(&mut DiagnosticEvent)) -> String {
        let mut event = DiagnosticEvent::from_xdr_base64(encoded, Limits::none()).unwrap();
        edit(&mut event);
        event.to_xdr_base64(Limits::none()).unwrap()
    }

    fn expected(f: &Fixture) -> (Address, Address, Address, i128) {
        (
            f.asset_contract.parse().unwrap(),
            f.payer.parse().unwrap(),
            f.recipient.parse().unwrap(),
            f.amount.parse().unwrap(),
        )
    }

    #[test]
    fn accepts_the_real_testnet_transfer() {
        let f = load();
        let (asset, payer, recipient, amount) = expected(&f);
        let result = verify_transfer_effects(
            &f.diagnostic_events_xdr_base64,
            &asset,
            &payer,
            &recipient,
            amount,
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn rejects_a_transfer_of_the_wrong_amount() {
        let f = load();
        let (asset, payer, recipient, amount) = expected(&f);
        let result = verify_transfer_effects(
            &f.diagnostic_events_xdr_base64,
            &asset,
            &payer,
            &recipient,
            amount + 1,
        );
        assert!(matches!(
            result,
            Err(SorochargeError::UnexpectedBalanceChange { .. })
        ));
    }

    #[test]
    fn rejects_a_transfer_to_someone_else() {
        let f = load();
        let (asset, payer, _recipient, amount) = expected(&f);
        let result = verify_transfer_effects(
            &f.diagnostic_events_xdr_base64,
            &asset,
            &payer,
            &someone_else(),
            amount,
        );
        assert!(matches!(
            result,
            Err(SorochargeError::UnexpectedBalanceChange { .. })
        ));
    }

    #[test]
    fn rejects_when_the_expected_transfer_is_absent() {
        let f = load();
        let (asset, payer, recipient, amount) = expected(&f);
        let without: Vec<String> = f
            .diagnostic_events_xdr_base64
            .iter()
            .filter(|e| !is_transfer_event(e))
            .cloned()
            .collect();
        let result = verify_transfer_effects(&without, &asset, &payer, &recipient, amount);
        assert_eq!(result, Err(SorochargeError::ExpectedTransferMissing));
    }

    /// A simulation that emitted nothing at all is the one missing-transfer
    /// input the fixture-based test above cannot construct: it must surface
    /// as `ExpectedTransferMissing`, not as a malformed or unexpected event.
    #[test]
    fn rejects_a_simulation_with_no_events_at_all() {
        let f = load();
        let (asset, payer, recipient, amount) = expected(&f);
        let result = verify_transfer_effects(&[], &asset, &payer, &recipient, amount);
        assert_eq!(result, Err(SorochargeError::ExpectedTransferMissing));
    }

    #[test]
    fn rejects_a_second_transfer_event() {
        let f = load();
        let (asset, payer, recipient, amount) = expected(&f);
        let mut events = f.diagnostic_events_xdr_base64.clone();
        let transfer = events
            .iter()
            .find(|e| is_transfer_event(e))
            .unwrap()
            .clone();
        events.push(transfer);
        let result = verify_transfer_effects(&events, &asset, &payer, &recipient, amount);
        assert!(matches!(
            result,
            Err(SorochargeError::UnexpectedBalanceChange { .. })
        ));
    }

    /// Renaming a transfer's topics to `mint` leaves `from` where a `mint`
    /// names its `to`, so the event no longer points at the expected
    /// recipient and must not be accepted as one.
    #[test]
    fn rejects_a_mint_whose_to_topic_is_not_the_expected_recipient() {
        let f = load();
        let (asset, payer, recipient, amount) = expected(&f);
        let mut events = f.diagnostic_events_xdr_base64.clone();
        let idx = events.iter().position(|e| is_transfer_event(e)).unwrap();
        events[idx] = edited_transfer(&events[idx], |ev| {
            let Body::V0(v0) = &mut ev.event.body;
            let mut topics: Vec<ScVal> = v0.topics.to_vec();
            topics[0] = ScVal::Symbol(ScSymbol("mint".try_into().unwrap()));
            v0.topics = VecM::try_from(topics).unwrap();
        });
        let result = verify_transfer_effects(&events, &asset, &payer, &recipient, amount);
        assert!(matches!(
            result,
            Err(SorochargeError::UnexpectedBalanceChange { .. })
        ));
    }

    #[test]
    fn rejects_a_balance_event_from_another_contract() {
        let f = load();
        let (asset, payer, recipient, amount) = expected(&f);
        let mut events = f.diagnostic_events_xdr_base64.clone();
        let idx = events.iter().position(|e| is_transfer_event(e)).unwrap();
        events[idx] = edited_transfer(&events[idx], |ev| {
            ev.event.contract_id = Some(ContractId(stellar_xdr::Hash([0x42; 32])));
        });
        let result = verify_transfer_effects(&events, &asset, &payer, &recipient, amount);
        assert!(matches!(
            result,
            Err(SorochargeError::UnexpectedBalanceChange { .. })
        ));
    }

    #[test]
    fn rejects_an_event_that_does_not_decode() {
        let f = load();
        let (asset, payer, recipient, amount) = expected(&f);
        let result = verify_transfer_effects(
            &["not-base64!!".to_string()],
            &asset,
            &payer,
            &recipient,
            amount,
        );
        assert!(matches!(
            result,
            Err(SorochargeError::SimulationEventsMalformed { .. })
        ));
    }

    #[test]
    fn rejects_a_transfer_event_lacking_from_to_address_topics() {
        let f = load();
        let (asset, payer, recipient, amount) = expected(&f);
        let mut events = f.diagnostic_events_xdr_base64.clone();
        let idx = events.iter().position(|e| is_transfer_event(e)).unwrap();
        // Keep only the "transfer" symbol topic, dropping the from/to addresses.
        events[idx] = edited_transfer(&events[idx], |ev| {
            let Body::V0(v0) = &mut ev.event.body;
            v0.topics = VecM::try_from(vec![v0.topics[0].clone()]).unwrap();
        });
        let result = verify_transfer_effects(&events, &asset, &payer, &recipient, amount);
        assert_eq!(
            result,
            Err(SorochargeError::SimulationEventsMalformed {
                reason: "transfer event lacks from/to address topics".to_string(),
            })
        );
    }

    #[test]
    fn rejects_a_transfer_event_whose_data_is_not_an_i128() {
        let f = load();
        let (asset, payer, recipient, amount) = expected(&f);
        let mut events = f.diagnostic_events_xdr_base64.clone();
        let idx = events.iter().position(|e| is_transfer_event(e)).unwrap();
        // The transfer amount must be an ScVal::I128; anything else is malformed.
        events[idx] = edited_transfer(&events[idx], |ev| {
            let Body::V0(v0) = &mut ev.event.body;
            v0.data = ScVal::I64(1_000_000);
        });
        let result = verify_transfer_effects(&events, &asset, &payer, &recipient, amount);
        assert_eq!(
            result,
            Err(SorochargeError::SimulationEventsMalformed {
                reason: "transfer event data is not an i128".to_string(),
            })
        );
    }

    // The four tests below cover the issuer side of a Stellar Asset Contract
    // transfer, where CAP-67 makes the host emit `mint` (sender is the issuer)
    // or `burn` (recipient is the issuer) instead of `transfer`. Their events
    // are lifted verbatim from a real testnet transaction, so the shapes under
    // test are the host's, not a guess at the CAP text.

    /// A payment *from* the asset's issuer arrives as a `mint` naming the
    /// recipient and the amount, with no `from` topic to check — the host only
    /// emits it when the sender is the issuer, so the payer's identity is
    /// already implied by the shape.
    #[test]
    fn accepts_a_real_issuer_side_mint() {
        let f = load_issuer_mint();
        let (asset, payer, recipient, amount) = expected(&f);
        assert!(
            f.diagnostic_events_xdr_base64
                .iter()
                .any(|e| is_named_event(e, "mint")),
            "fixture must contain a real `mint` event"
        );
        let result = verify_transfer_effects(
            &f.diagnostic_events_xdr_base64,
            &asset,
            &payer,
            &recipient,
            amount,
        );
        assert_eq!(result, Ok(()));
    }

    /// A payment *to* the asset's issuer arrives as a `burn` naming the payer
    /// and the amount. The recipient is the issuer by construction of the
    /// shape, so only the payer and the amount can be checked.
    #[test]
    fn accepts_a_real_issuer_side_burn() {
        let f = load_issuer_burn();
        let (asset, payer, recipient, amount) = expected(&f);
        assert!(
            f.diagnostic_events_xdr_base64
                .iter()
                .any(|e| is_named_event(e, "burn")),
            "fixture must contain a real `burn` event"
        );
        let result = verify_transfer_effects(
            &f.diagnostic_events_xdr_base64,
            &asset,
            &payer,
            &recipient,
            amount,
        );
        assert_eq!(result, Ok(()));
    }

    /// A `mint` that names anybody but the expected recipient is a movement to
    /// the wrong party, whether or not an issuer is involved.
    #[test]
    fn rejects_an_issuer_side_mint_to_someone_else() {
        let f = load_issuer_mint();
        let (asset, payer, _recipient, amount) = expected(&f);
        let result = verify_transfer_effects(
            &f.diagnostic_events_xdr_base64,
            &asset,
            &payer,
            &someone_else(),
            amount,
        );
        assert!(matches!(
            result,
            Err(SorochargeError::UnexpectedBalanceChange { .. })
        ));
    }

    #[test]
    fn rejects_an_issuer_side_mint_of_the_wrong_amount() {
        let f = load_issuer_mint();
        let (asset, payer, recipient, amount) = expected(&f);
        let result = verify_transfer_effects(
            &f.diagnostic_events_xdr_base64,
            &asset,
            &payer,
            &recipient,
            amount + 1,
        );
        assert!(matches!(
            result,
            Err(SorochargeError::UnexpectedBalanceChange { .. })
        ));
    }

    /// A `burn` that names anybody but the expected payer is a movement from
    /// the wrong party — the payer did not fund it.
    #[test]
    fn rejects_an_issuer_side_burn_from_someone_else() {
        let f = load_issuer_burn();
        let (asset, _payer, recipient, amount) = expected(&f);
        let result = verify_transfer_effects(
            &f.diagnostic_events_xdr_base64,
            &asset,
            &someone_else(),
            &recipient,
            amount,
        );
        assert!(matches!(
            result,
            Err(SorochargeError::UnexpectedBalanceChange { .. })
        ));
    }

    #[test]
    fn rejects_an_issuer_side_burn_of_the_wrong_amount() {
        let f = load_issuer_burn();
        let (asset, payer, recipient, amount) = expected(&f);
        let result = verify_transfer_effects(
            &f.diagnostic_events_xdr_base64,
            &asset,
            &payer,
            &recipient,
            amount - 1,
        );
        assert!(matches!(
            result,
            Err(SorochargeError::UnexpectedBalanceChange { .. })
        ));
    }

    /// A live `burn` event paired with an expected-looking `transfer` is two
    /// balance movements, not one payment in disguise.
    #[test]
    fn rejects_an_issuer_side_event_alongside_a_transfer() {
        let transfer = load();
        let burn = load_issuer_burn();
        let (asset, payer, recipient, amount) = expected(&burn);
        let mut events = burn.diagnostic_events_xdr_base64.clone();
        let real_transfer = transfer
            .diagnostic_events_xdr_base64
            .iter()
            .find(|e| is_transfer_event(e))
            .unwrap()
            .clone();
        events.push(real_transfer);
        let result = verify_transfer_effects(&events, &asset, &payer, &recipient, amount);
        assert!(matches!(
            result,
            Err(SorochargeError::UnexpectedBalanceChange { .. })
        ));
    }

    #[test]
    fn rejects_an_issuer_side_event_lacking_its_address_topic() {
        let f = load_issuer_burn();
        let (asset, payer, recipient, amount) = expected(&f);
        let mut events = f.diagnostic_events_xdr_base64.clone();
        let idx = events
            .iter()
            .position(|e| is_named_event(e, "burn"))
            .unwrap();
        // Keep only the "burn" symbol topic, dropping the `from` address.
        events[idx] = edited_transfer(&events[idx], |ev| {
            let Body::V0(v0) = &mut ev.event.body;
            v0.topics = VecM::try_from(vec![v0.topics[0].clone()]).unwrap();
        });
        let result = verify_transfer_effects(&events, &asset, &payer, &recipient, amount);
        assert_eq!(
            result,
            Err(SorochargeError::SimulationEventsMalformed {
                reason: "burn event lacks a `from` address topic".to_string(),
            })
        );
    }
}
