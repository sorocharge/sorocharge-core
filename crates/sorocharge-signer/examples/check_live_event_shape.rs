//! Dev-only check that [`verify_transfer_effects`] still agrees with the
//! events the live Stellar host emits for a SEP-41 transfer.
//!
//! `verify_transfer_effects` deliberately encodes the *actual* event shape a
//! Soroban host produces — `[transfer, from, to, …]` topics with `i128` data,
//! and the CAP-67 issuer-side `mint`/`burn` degenerations — rather than the
//! CAP text, and that shape can change with a protocol upgrade. This example
//! is the periodic re-check: it funds two throwaway testnet accounts through
//! Friendbot, submits a real native-SAC transfer, then runs
//! `verify_transfer_effects` over both the simulation's diagnostic events
//! (the exact input production callers pass) and the executed transaction's
//! contract events from ledger meta. Any drift surfaces as a non-zero exit,
//! which the scheduled `event-shape-check` workflow turns into an alert
//! issue — never a silent pass.
//!
//! It is not part of the library or its test suite. Run it manually with:
//!
//! ```sh
//! cargo run -p sorocharge-signer --example check_live_event_shape
//! ```
//!
//! Optional environment variables:
//!
//! - `SOROCHARGE_TESTNET_RPC_URL` (default `https://soroban-testnet.stellar.org`)
//! - `SOROCHARGE_TESTNET_FRIENDBOT_URL` (default `https://friendbot.stellar.org`)
//!
//! No key is ever read from the environment or committed: both keypairs are
//! randomly generated per run and funded with testnet lumens only.

use std::error::Error;
use std::time::Duration;

use ed25519_dalek::{Signer as DalekSigner, SigningKey};
use sha2::{Digest, Sha256};
use sorocharge_signer::{verify_transfer_effects, Address};
use stellar_rpc_client::Client;
use stellar_xdr::{
    AccountId, Asset, ContractId, ContractIdPreimage, DecoratedSignature, DiagnosticEvent, Hash,
    HashIdPreimage, HashIdPreimageContractId, HostFunction, Int128Parts, InvokeContractArgs,
    InvokeHostFunctionOp, Limits, Memo, MuxedAccount, Operation, OperationBody, Preconditions,
    PublicKey, ReadXdr, ScAddress, ScSymbol, ScVal, SequenceNumber, Signature, SignatureHint,
    SorobanAuthorizationEntry, SorobanAuthorizedFunction, SorobanAuthorizedInvocation,
    SorobanCredentials, Transaction, TransactionEnvelope, TransactionExt, TransactionV1Envelope,
    Uint256, VecM, WriteXdr,
};

const DEFAULT_RPC_URL: &str = "https://soroban-testnet.stellar.org";
const DEFAULT_FRIENDBOT_URL: &str = "https://friendbot.stellar.org";
const NETWORK_PASSPHRASE: &str = "Test SDF Network ; September 2015";

/// 1 XLM in stroops. Small enough that two Friendbot-funded accounts can
/// always afford it, large enough that the amount in the event is
/// unambiguous.
const TRANSFER_AMOUNT: i128 = 10_000_000;

const FRIENDBOT_TIMEOUT: Duration = Duration::from_secs(30);
const FUNDING_ATTEMPTS: u32 = 30;
const FUNDING_POLL_INTERVAL: Duration = Duration::from_secs(2);

type BoxError = Box<dyn Error>;

fn account_address(public_key: [u8; 32]) -> Address {
    ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(
        public_key,
    ))))
}

/// Derives the native Stellar Asset Contract address the same way the
/// network does (CAP-46: `sha256` over the contract-id preimage bound to the
/// network passphrase), instead of hardcoding a per-network constant that a
/// testnet reset would silently invalidate.
fn native_sac_address(passphrase: &str) -> Result<Address, BoxError> {
    let network_id = Hash(Sha256::digest(passphrase.as_bytes()).into());
    let preimage = HashIdPreimage::ContractId(HashIdPreimageContractId {
        network_id,
        contract_id_preimage: ContractIdPreimage::Asset(Asset::Native),
    });
    let encoded = preimage.to_xdr(Limits::none())?;
    let hash: [u8; 32] = Sha256::digest(&encoded).into();
    Ok(ScAddress::Contract(ContractId(Hash(hash))))
}

async fn fund(
    http: &reqwest::Client,
    friendbot_url: &str,
    address: &Address,
) -> Result<(), BoxError> {
    let url = format!("{friendbot_url}?addr={address}");
    let response = http.get(&url).send().await?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("friendbot returned {status} for {address}: {body}").into());
    }
    Ok(())
}

async fn wait_for_account(client: &Client, address: &Address) -> Result<(), BoxError> {
    let mut last_error = String::new();
    for _ in 0..FUNDING_ATTEMPTS {
        match client.get_account(&address.to_string()).await {
            Ok(_) => return Ok(()),
            Err(e) => last_error = e.to_string(),
        }
        tokio::time::sleep(FUNDING_POLL_INTERVAL).await;
    }
    Err(format!("account {address} never appeared over RPC: {last_error}").into())
}

fn transfer_operation(
    asset_contract: &Address,
    payer: &Address,
    recipient: &Address,
    amount: i128,
) -> Result<Operation, BoxError> {
    let function_name: ScSymbol = "transfer"
        .try_into()
        .map_err(|_| "invalid \"transfer\" symbol")?;
    let amount_parts = Int128Parts {
        hi: (amount >> 64) as i64,
        lo: (amount & i128::from(u64::MAX)) as u64,
    };
    let args: VecM<ScVal> = vec![
        ScVal::Address(payer.clone()),
        ScVal::Address(recipient.clone()),
        ScVal::I128(amount_parts),
    ]
    .try_into()
    .map_err(|_| "invalid transfer arguments")?;
    let invoke = InvokeContractArgs {
        contract_address: asset_contract.clone(),
        function_name,
        args,
    };
    // Soroban still wants an explicit entry: `SourceAccount` credentials are
    // how the host learns the transfer's `from` is authorized by the
    // transaction source. This check is about the host's emitted events, not
    // about this library's address credentials.
    let auth = vec![SorobanAuthorizationEntry {
        credentials: SorobanCredentials::SourceAccount,
        root_invocation: SorobanAuthorizedInvocation {
            function: SorobanAuthorizedFunction::ContractFn(invoke.clone()),
            sub_invocations: VecM::default(),
        },
    }]
    .try_into()
    .map_err(|_| "one auth entry")?;
    Ok(Operation {
        source_account: None,
        body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
            host_function: HostFunction::InvokeContract(invoke),
            auth,
        }),
    })
}

fn sign_envelope(
    tx: Transaction,
    signing_key: &SigningKey,
    network_id: [u8; 32],
) -> Result<TransactionEnvelope, BoxError> {
    let hash = tx.hash(network_id)?;
    let signature = signing_key.sign(&hash).to_bytes();
    let public_key = signing_key.verifying_key().to_bytes();
    let decorated = DecoratedSignature {
        hint: SignatureHint([
            public_key[28],
            public_key[29],
            public_key[30],
            public_key[31],
        ]),
        signature: Signature(
            signature
                .to_vec()
                .try_into()
                .map_err(|_| "signature must be 64 bytes")?,
        ),
    };
    Ok(TransactionEnvelope::Tx(TransactionV1Envelope {
        tx,
        signatures: vec![decorated].try_into().map_err(|_| "one signature")?,
    }))
}

/// A one-line description of each contract event, printed so a failure is
/// diagnosable from the CI log without a second run.
fn describe_events(events: &[DiagnosticEvent]) -> Vec<String> {
    events
        .iter()
        .map(|event| {
            let stellar_xdr::ContractEventBody::V0(body) = &event.event.body;
            let name = match body.topics.first() {
                Some(ScVal::Symbol(symbol)) => symbol.0.to_utf8_string_lossy(),
                _ => "<no-symbol-topic>".to_string(),
            };
            let topics: Vec<String> = body
                .topics
                .iter()
                .map(|topic| match topic {
                    ScVal::Symbol(_) => "symbol".to_string(),
                    ScVal::Address(_) => "address".to_string(),
                    ScVal::String(_) => "string".to_string(),
                    other => format!("{other:?}"),
                })
                .collect();
            let data = match &body.data {
                ScVal::I128(_) => "data=i128".to_string(),
                ScVal::U32(_) => "data=u32".to_string(),
                other => format!("data={other:?}"),
            };
            format!("event \"{name}\" topics=[{}] {data}", topics.join(","))
        })
        .collect()
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let rpc_url =
        std::env::var("SOROCHARGE_TESTNET_RPC_URL").unwrap_or_else(|_| DEFAULT_RPC_URL.to_string());
    let friendbot_url = std::env::var("SOROCHARGE_TESTNET_FRIENDBOT_URL")
        .unwrap_or_else(|_| DEFAULT_FRIENDBOT_URL.to_string());

    // `Client::new` sets a 30-second per-request timeout, so no RPC call in
    // this check can hang unboundedly.
    let client = Client::new(&rpc_url)?;
    let http = reqwest::Client::builder()
        .timeout(FRIENDBOT_TIMEOUT)
        .build()?;

    let network = client.get_network().await?;
    if network.passphrase != NETWORK_PASSPHRASE {
        return Err(format!(
            "{rpc_url} is not testnet: passphrase is {:?}",
            network.passphrase
        )
        .into());
    }
    let network_id: [u8; 32] = Sha256::digest(NETWORK_PASSPHRASE.as_bytes()).into();
    println!(
        "testnet: protocol {} (rpc {rpc_url})",
        network.protocol_version
    );

    let asset_contract = native_sac_address(NETWORK_PASSPHRASE)?;
    println!("native SAC: {asset_contract}");

    let payer_key = SigningKey::from_bytes(&random_seed()?);
    let recipient_key = SigningKey::from_bytes(&random_seed()?);
    let payer = account_address(payer_key.verifying_key().to_bytes());
    let recipient = account_address(recipient_key.verifying_key().to_bytes());
    println!("ephemeral payer:     {payer}");
    println!("ephemeral recipient: {recipient}");

    fund(&http, &friendbot_url, &payer).await?;
    fund(&http, &friendbot_url, &recipient).await?;
    wait_for_account(&client, &payer).await?;
    wait_for_account(&client, &recipient).await?;

    let ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(payer_bytes)))) =
        payer
    else {
        return Err("payer is not an ed25519 account".into());
    };
    let account = client.get_account(&payer.to_string()).await?;
    let operation = transfer_operation(&asset_contract, &payer, &recipient, TRANSFER_AMOUNT)?;
    let base_tx = Transaction {
        source_account: MuxedAccount::Ed25519(Uint256(payer_bytes)),
        fee: 100,
        seq_num: SequenceNumber(account.seq_num.0 + 1),
        cond: Preconditions::None,
        memo: Memo::None,
        operations: vec![operation].try_into().map_err(|_| "one operation")?,
        ext: TransactionExt::V0,
    };

    let simulation = client
        .simulate_transaction_envelope(
            &TransactionEnvelope::Tx(TransactionV1Envelope {
                tx: base_tx.clone(),
                signatures: VecM::default(),
            }),
            None,
        )
        .await?;
    if let Some(error) = &simulation.error {
        return Err(format!("simulation of the real transfer failed: {error}").into());
    }

    let fee = simulation
        .min_resource_fee
        .saturating_add(100_000)
        .try_into()
        .map_err(|_| "simulated fee does not fit in u32")?;
    let tx = Transaction {
        fee,
        ext: TransactionExt::V1(simulation.transaction_data()?),
        ..base_tx
    };
    let signed = sign_envelope(tx, &payer_key, network_id)?;

    // The check production code relies on: the exact `DiagnosticEvent` list a
    // simulation hands `verify_transfer_effects` must still describe one
    // expected transfer.
    verify_transfer_effects(
        &simulation.events,
        &asset_contract,
        &payer,
        &recipient,
        TRANSFER_AMOUNT,
    )?;
    println!(
        "simulation events match verify_transfer_effects: {:?}",
        describe_events(
            &simulation
                .events
                .iter()
                .map(|encoded| DiagnosticEvent::from_xdr_base64(encoded, Limits::none()))
                .collect::<Result<Vec<_>, _>>()?
        )
    );

    // Submit directly rather than through `send_transaction_polling`, so a
    // failed transaction still yields its ledger meta (and therefore its
    // diagnostic events) for the alert instead of just an op result code.
    let tx_hash = client.send_transaction(&signed).await?;
    let mut response = client.get_transaction(&tx_hash).await?;
    for _ in 0..FUNDING_ATTEMPTS {
        if response.status != "NOT_FOUND" {
            break;
        }
        tokio::time::sleep(FUNDING_POLL_INTERVAL).await;
        response = client.get_transaction(&tx_hash).await?;
    }
    if response.status != "SUCCESS" {
        let diagnostics = describe_events(&response.events.diagnostic_events);
        let result = response
            .result
            .as_ref()
            .map(|r| format!("{r:?}"))
            .unwrap_or_else(|| "<no result>".to_string());
        return Err(format!(
            "testnet rejected the transfer: status {} result {result}\ndiagnostics: {diagnostics:?}",
            response.status
        )
        .into());
    }
    println!(
        "submitted real transfer: {} (ledger {})",
        response.tx_hash.as_deref().unwrap_or("<unknown>"),
        response
            .ledger
            .map(|l| l.to_string())
            .unwrap_or_else(|| "<unknown>".to_string())
    );

    // ... and the same check against the events the host actually committed
    // to ledger meta, which is where a shape drift would first appear.
    let executed: Vec<DiagnosticEvent> = response
        .events
        .contract_events
        .iter()
        .flatten()
        .map(|event| DiagnosticEvent {
            in_successful_contract_call: true,
            event: event.clone(),
        })
        .collect();
    if executed.is_empty() {
        return Err(
            "executed transaction meta carried no contract events; the host's event shape changed"
                .into(),
        );
    }
    let encoded: Vec<String> = executed
        .iter()
        .map(|event| event.to_xdr_base64(Limits::none()))
        .collect::<Result<_, _>>()?;
    verify_transfer_effects(
        &encoded,
        &asset_contract,
        &payer,
        &recipient,
        TRANSFER_AMOUNT,
    )?;
    println!(
        "executed events match verify_transfer_effects: {:?}",
        describe_events(&executed)
    );
    println!("OK: live event shape still matches verify_transfer_effects");
    Ok(())
}

/// A fresh 32-byte ed25519 seed. `getrandom` is already a runtime dependency
/// of this crate; no secret is stored or reused across runs.
fn random_seed() -> Result<[u8; 32], BoxError> {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|e| format!("OS randomness unavailable: {e}"))?;
    Ok(seed)
}
