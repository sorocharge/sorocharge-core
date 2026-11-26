# Threat Model

This document describes the security considerations and threat model for `sorocharge-core`.
It is intended to make explicit what the library defends against and what is explicitly out of scope,
so that security reviews are faster and more complete.

# Attacker Models and Defenses

### 1. Malicious Payer

The payer constructs and signs a Soroban authorization entry to authorize a SEP-41 token transfer.
The payer controls the signing key for the payer address.

**Defended against:**
- **Signature forgery**: The signature on the authorization entry is verified against the
  reconstructed `HashIdPreimage`. A malicious payer cannot forge a valid signature without
  the private key (ed25519).
- **Replay across networks**: The `network_id` (derived from the passphrase) is baked into
  every signing payload via `network_id_hash()`. Signing for `Test SDF Network ; September 2015`
  produces a different signature than `Public Global Stellar Network ; September 2015`,
  preventing replay across networks.
- **Amount/asset/payer/recipient tampering**: `verify_entry` checks all five fields
  (expiry, asset contract, payer, amount, recipient) against expected values before
  checking the signature, so a malicious payer cannot substitute different values.
- **Expiration bypass**: `verify_entry` checks `valid_until_ledger` against `current_ledger`
  and `signature_expiration_ledger` against `expected.valid_until_ledger`, preventing
  entries valid for arbitrarily long periods.

**Out of scope:**
- The payer's key management or custody. Callers pass in a signing key already in memory
  or a signing callback. Key storage, HSM integration, or wallet integration is out of scope.
- Network consensus or on-chain settlement correctness. The library only builds, signs, and
  verifies authorization entries; it does not validate on-chain results beyond what `verify_entry` checks.

### 2. Malicious/Compromised Resource Server (Payee/Facilitator)

The payee/facilitator receives a signed credential from a payer and verifies it before
submitting it to the network.

**Defended against:**
- **Invalid credential acceptance**: `verify_entry` performs a strict order of checks:
  1. Amount non-positive
  2. Expiry against current ledger
  3. Expiration exceeds allowance
  4. Invocation shape (must be bare SEP-41 `transfer`)
  5. Asset contract match
  6. Payer match
  7. Amount match
  8. Recipient match
  9. Signature validity
  This ordered check fails closed on the first mismatch, so a malicious/compromised party
  cannot submit a partially-valid credential.
- **Signature key binding**: `verify_entry` reconstructs the exact `HashIdPreimage` that was
  signed and verifies the signature against it. The `network_id` binding ensures the signature
  is cryptographically bound to the specific network passphrase.
- **Payer address binding**: The authorizing address from the credential must match `expected.payer`,
  preventing a payer from authorizing a transfer from a different address.

**Out of scope:**
- Delegated-signer threshold policy: The library only proves that *at least one* signature is
  valid for a `Delegated` entry. The threshold (how many delegates must sign) is unenforceable
  at this layer and is a known gap (see `verify_delegated_threshold` for more details).
- MPP session/channel mode: Uses a completely different signing primitive (raw ed25519 signature
  over a `one-way-channel` contract's `prepare_commitment` output, not a `SorobanAuthorizationEntry`).
  Explicitly out of scope.

### 3. Malicious Facilitator-Adjacent Party

A party that sits between the payer and the network, potentially observing or modifying
messages in the x402 or MPP flow.

**Defended against:**
- **Credential interception**: The x402 protocol uses `402` payment challenges with signed
  credentials. The facilitator verifies the credential before submitting, preventing
  credential reuse without the payer's consent.
- **Facilitator address conflict**: The x402 and MPP adapters explicitly check that the
  facilitator's own address does not appear where the safety checks forbid it (transaction
  source, operation source, `from` argument, or authorization entry).

**Out of scope:**
- Man-in-the-middle attacks on the HTTP transport. TLS is assumed.
- Rate limiting or DoS protection. These are deployment-level concerns.

### 4. Malicious Contributor / Supply-Chain Compromise

An attacker who can open a pull request (or land a commit) against this repository, or who
compromises a contributor's account or toolchain, rather than attacking the cryptography
directly. This is a real, observed threat class here: the PolinRider campaign targeted a
sibling Stellar Drips Wave repository by appending obfuscated payloads to otherwise-readable
files and exfiltrating through non-Stellar blockchain RPC endpoints. The goal is usually not
to break `verify_entry`; it is to get code merged that steals keys or funds from whoever
embeds this library next.

**Defended against:**
- **Known IOCs**: `scripts/malware_scan.py` scans every git-tracked file against
  `security/malware_iocs.json` — campaign-specific literal strings, exfiltration domains,
  malicious npm package names and Packagist namespaces, and suspicious filenames. The
  `malware-scan` job in `.github/workflows/ci.yml` runs it on every push and pull request,
  and it is a **required check under branch protection**, so a finding blocks merge rather
  than merely annotating the PR.
- **Generic obfuscation heuristics**: independent of any known campaign, the same scan flags
  dynamic-code-execution and process-spawning primitives — `eval` and `new Function`, Node's
  child-process module, Python's subprocess module, `os.system`, `Command::new`,
  `shell_exec`, and similar — long base64/hex-shaped blobs, unusually long high-entropy
  lines appended to readable files, and file types that have no legitimate reason to be
  tracked. A new use of an execution primitive must be added to
  `security/scan_allowlist.json` with a written justification, which is itself a
  security-relevant review.
- **Protected files cannot clear themselves**: `scripts/malware_scan.py`,
  `security/malware_iocs.json` and `security/scan_allowlist.json` are exempt from their own
  pattern checks (they necessarily contain the strings they search for), but any PR that
  touches them hard-fails the scan and requires a maintainer's manual review. `CODEOWNERS`
  requests that review automatically.
- **Signature-based second layer**: the same job runs ClamAV over the checkout as a
  straightforward malware-signature check, independent of the project-specific IOCs.
- **Pinned build inputs**: GitHub Actions are pinned to commit SHAs (`ci.yml` header),
  crate versions are exact, and `cargo-deny` checks advisories and licenses, so a repointed
  tag or a yanked/broken dependency cannot silently change what CI executes.

**What the scan does not catch:**
- **Only the tracked tree at rest.** It reads tracked file contents; it does not execute
  code, observe build scripts or proc-macro behavior, inspect `target/`, `node_modules/` or
  `vendor/`, or watch anything a dependency does at runtime. `cargo build` runs arbitrary
  `build.rs` code that no pattern scan can judge.
- **Only known shapes.** It is pattern- and IOC-based. A new campaign with no entry in
  `security/malware_iocs.json`, a differently obfuscated payload, or malicious code written
  in plain idiomatic Rust/PHP using ordinary APIs (read a file, POST it to an unlisted host)
  will pass cleanly.
- **Only text extensions, for the content checks.** Non-text files are covered only by the
  ClamAV signature scan, and a failed/stale ClamAV signature update is a warning, not a
  blocking failure.
- **The protected-files guard depends on `origin/main` being fetchable.** That diff check is
  skipped when the fetch does not succeed; the content checks still run, but a clean result
  then does not prove a protected file was untouched.
- **Intent and dependency additions.** A pull request adding a plausible-looking new crate
  or package is only checked against known-malicious names; deciding whether the dependency
  is trustworthy remains a human review responsibility.

**Out of scope:**
- Compromise of the maintainers' own GitHub accounts, signing keys, or runners. Branch
  protection and the scan reduce the chance of bad code landing; they do not make a
  compromised maintainer review meaningful.
- Reproducible builds or binary attestation. This repository ships source crates, not
  prebuilt binaries.

## Summary of Current Known Gaps

| Area | Status |
|---|---|
| Delegated-signer threshold policy | **Gap**: `verify_entry` only proves one signature is valid; threshold enforcement requires `verify_delegated_threshold` which is not called via x402 or MPP adapters today |
| MPP session/channel mode | **Out of scope**: Different signing primitive entirely |
| Key custody / HSM integration | **Out of scope**: Callers provide signing keys in memory |
| On-chain settlement validation | **Out of scope**: Library only builds/verifies auth entries |
| Transport security (TLS) | **Assumed** — not a library concern |
| Supply-chain / malicious contribution | **Partially mitigated**: the `malware-scan` CI gate (required via branch protection) catches known IOCs and obfuscation shapes, but not novel campaigns, runtime/build-script behavior, or trustworthy-looking dependency additions |

## Concrete Worked Example

See `sorocharge-core#9` for a real finding: a signature-binding vulnerability was discovered
by reading the code and noticing that `verify_entry` did not check that the authorizing address
matches the expected payer. This was added per the project's conservative stance toward money
and security. A written threat model would have accelerated that review.

## Related

- `sorocharge-signer/src/verify.rs` — contains the full list of checks performed by `verify_entry`
- `benches/signer_benchmarks.rs` — benchmarks for the signing/verification hot path
- `scripts/malware_scan.py` — the supply-chain scan described in section 4
- `security/malware_iocs.json` — campaign IOCs and generic suspicious patterns the scan reads
- `security/scan_allowlist.json` — reviewed exceptions for execution primitives
- `.github/workflows/ci.yml` — the `malware-scan` job that runs the scan and blocks merge