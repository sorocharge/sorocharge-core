# Changelog

Notable changes to `sorocharge-core`. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
uses [semantic versioning](https://semver.org/). Before `1.0.0`, a minor
bump may break the API.

## [Unreleased]

### Added

- `sorocharge_signer::verify_delegated_threshold`, which enforces a
  threshold across a delegated-signer entry's signatures. `verify_entry`
  can only prove that one signature is genuine; callers that need the
  entry's delegate threshold honoured must call this separately.
- `SorochargeError::AmountNonPositive`. `build_charge_entry` and
  `verify_entry` now reject zero and negative transfer amounts outright
  rather than letting them reach a token contract.
- `SorochargeError::NonceGenerationFailed`, returned when the OS entropy
  source fails while generating an entry nonce. Previously that failure was
  reported as `XdrEncodingFailed`, which pointed callers at their input
  instead of the environment. The entry still fails closed; no fallback
  nonce is used.
- `UnsignedEntry::signature_expiration_ledger()` and
  `SignedEntry::signature_expiration_ledger()`, so a payer can read back the
  exact ledger the entry expires at. Both return a `Result`, because
  `SignedEntry::from_xdr` accepts entries with no expiration ledger at all.
- `X402Error::HttpClientBuildFailed` and
  `X402Error::UnexpectedStatusAfterPayment`. Client construction failure is
  local and non-retryable; a non-200 on the payment-bearing retry is distinct
  from one on the unpaid request, because a credential has already been sent
  and may have settled.
- `verify_transfer_effects` accepts issuer-side `mint`/`burn` events as the
  expected payment. Per CAP-67 a SAC reports a transfer from the asset's
  issuer as `mint` and one to the issuer as `burn`; those were previously
  rejected, so paying an issuer could never verify. The shape is only
  accepted when it names the expected counterparty and amount.
- `cargo-fuzz` harnesses for all three crates, covering the untrusted-XDR
  boundaries (`verify_entry`, and each adapter's `parse_payment_transaction`),
  plus a bounded nightly CI job.
- An mdBook documentation site: architecture, x402 and MPP client/facilitator
  guides, developer setup, a full API reference, and an error
  troubleshooting guide.
- Runnable doctests across the public API and `Receipt`/`MethodDetails`.
- A dev-only live testnet check for the assumed SAC event shape, and a
  monthly CI job that fails when the live shape or protocol number changes.
- Golden vectors for the `i128` amount boundaries (`1` and `i128::MAX`) and a
  reference-SDK-signed `AddressV2` fixture.
- `CODEOWNERS` covering `security/` and `scripts/malware_scan.py`, an
  `.editorconfig`, `.gitattributes`, structured issue forms, and a pull
  request template.

### Changed

- `stellar-xdr` and `stellar-rpc-client` are pinned to 30.0.0 and
  `stellar-strkey` to 1.0.0, matching live testnet protocol 30 (pubnet was
  at 29 when checked). Being behind on XDR is a correctness risk when
  decoding simulated and executed events.
- The x402 client rejects zero and negative amounts in a challenge's
  selected `accepts[]` entry as `InvalidPaymentRequired`. `i128::from_str`
  accepts a leading `-`, so a hostile challenge could otherwise get a
  non-positive transfer signed.
- Both adapters enforce per-field length caps on deserialize (x402
  `PaymentRequired` and the requirements echoed in a payment payload; MPP
  wire types), so an oversized header or body is rejected before allocation
  grows.
- The x402 client adds a safety margin to its ledger-timeout computation,
  and the MPP server caps `timeBounds.maxTime` on unsponsored settlement when
  the challenge omits `expires`.
- The workspace version is now 0.2.0, and intra-workspace path dependencies
  carry matching version requirements so `cargo package`/`cargo publish`
  accept the manifests.

### Fixed

- **Signature key binding**: `verify_entry` verified the embedded signature
  against whatever public key the signature SCVal claimed, without comparing
  that key to the credential's account. A signed entry claiming account A
  while carrying a genuine signature from unrelated key B passed. Reported
  as `sorocharge-core#9`; the key is now bound to the claimed account.
- `verify_delegated_threshold` now performs the expiry checks its
  documentation always promised (`ExpiredEntry`,
  `ExpirationExceedsAllowance`) and de-duplicates delegate addresses, so a
  repeated delegate node can no longer count one signature twice toward a
  threshold.
- MPP's `retry_get` backoff was `1u64.saturating_pow(n)`, which is always 1;
  it is now 1s, 2s, 4s as documented. The doc claiming 5xx responses were
  retried was corrected: only transport errors are retried.
- Error variants now match their return sites across all three crates, so a
  caller can act on the specific failure rather than a mislabelled one.
- Dependency advisories: `rustls` 0.23.46 (RUSTSEC-2026-0346..0349), `url`
  2.5.9 (RUSTSEC-2026-0592), and `tokio` 1.54.1, with `cargo-deny` scoped to
  the Linux target.

### CI

- A `malware-scan` job runs `scripts/malware_scan.py` against
  `security/malware_iocs.json` and scans the checkout with ClamAV on every
  push and pull request; it is required under branch protection.
- `cargo-semver-checks` runs against `v0.1.2`.
- Every GitHub Action is pinned to a commit SHA.
- The toolchain is pinned to Rust 1.98.1, with rustfmt and release-profile
  settings checked in.

## [0.1.2] — 2026-10-07

### Added

- `verify_transfer_effects`, which decodes a simulation's diagnostic events
  and requires exactly one SEP-41 transfer matching payer, recipient and
  amount. It rejects a second transfer, a transfer to someone else,
  mint/burn/clawback, a balance event from another contract, a missing
  transfer, and malformed events, each with its own error. Wired into the
  x402 facilitator's `verify` and `settle` and the MPP server's pull-mode
  settlement. This closes the gap between "the payer authorized a charge"
  and "submitting this transaction moves only that charge" — the latter is
  what a fee sponsor actually needs.
- `ExpirationExceedsAllowance`, a distinct error from `ExpiredEntry`.

### Fixed

- `verify_entry` now enforces `expected.valid_until_ledger` as an upper
  bound. It previously checked only that the entry had not yet expired, so a
  payer could attach an authorization valid far longer than the payee asked
  for. Both facilitators now compute the real per-spec cap
  (`currentLedger + ceil(allowed_seconds / 5)`) instead of using `0` as a
  placeholder.
- Formatting missed before the tag, which had failed CI's `fmt` check. No
  logic change.

## [0.1.1] — 2026-10-06

### Changed

- `Signer` is now `Send + Sync`, so a `&dyn Signer` can be held across an
  `await` in an async HTTP handler. This is a public-API change to a tagged
  release and is why it ships as a patch rather than a retag.

### Fixed

- MPP unsponsored credentials were rejected with "authorization entry
  expiration exceeds the challenge's allowance". The spec's cap assumes
  5-second ledgers; when ledgers closed slower, a spec-exact client expiry
  outlived the server's shrinking bound. The client now sets half the spec
  allowance, leaving roughly 2x margin at the cost of a shorter
  authorization window (also less exposure). The server's check remains
  spec-faithful.
- Sponsored MPP settlement dropped the Soroban resource data when rebuilding
  the transaction (`TransactionExt::V0`), which `stellar-core` rejects as
  `TxMalformed`. The simulation data is now attached as the x402 facilitator
  already did.
- The MPP resource-server example can now run unsponsored and tracks
  consumed push-mode hashes, which the spec requires even on a fresh
  challenge.

## [0.1.0] — 2026-09-29

First release: one signing engine, two payment protocols.

### Added

- `sorocharge-signer`: `ChargeParams` (asset contract, `i128` amount, payer,
  recipient, ledger-based expiry), `CredentialKind`, and a `SorochargeError`
  variant per failure mode.
- `build_charge_entry` for all three CAP-71 credential shapes: legacy
  `SorobanAddressCredentials`, CAP-71 V2 (`AddressV2`), and delegated signers
  (`AddressWithDelegates`). Every credential kind is diffed byte-for-byte
  against golden vectors from the pinned `@stellar/stellar-sdk`.
- `sign_entry`, with signature bytes checked against reference-SDK output,
  and `verify_entry` with one test per failure mode: expired, wrong asset,
  wrong payer, wrong amount, wrong recipient, bad signature, and an
  invocation that is not a bare SEP-41 transfer.
- `UnsignedEntry`/`SignedEntry` XDR serialization, and `SignedEntry::from_xdr`
  for entries received over the wire.
- `sorocharge-x402`: the payer client (`GET` → 402 → build+sign → retry) and
  facilitator-side `verify`/`settle`/`supported` for x402 protocol v2's
  `exact` scheme on Stellar, as plain functions rather than a bundled server.
- `sorocharge-mpp`: the payer client and server side (challenge issuance,
  verification, settlement) for MPP's `draft-stellar-charge-00` `stellar`
  payment method, `charge` intent — pull mode (sponsored and unsponsored) and
  push mode.
- Runnable examples for both protocols and the verify-and-settle flow, plus a
  README with install instructions, quickstarts, and an explicit note that
  MPP session/channel mode is out of scope.

[Unreleased]: https://github.com/sorocharge/sorocharge-core/compare/v0.1.2...HEAD
[0.1.2]: https://github.com/sorocharge/sorocharge-core/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/sorocharge/sorocharge-core/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/sorocharge/sorocharge-core/releases/tag/v0.1.0
