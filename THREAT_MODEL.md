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

## Summary of Current Known Gaps

| Area | Status |
|---|---|
| Delegated-signer threshold policy | **Gap**: `verify_entry` only proves one signature is valid; threshold enforcement requires `verify_delegated_threshold` which is not called via x402 or MPP adapters today |
| MPP session/channel mode | **Out of scope**: Different signing primitive entirely |
| Key custody / HSM integration | **Out of scope**: Callers provide signing keys in memory |
| On-chain settlement validation | **Out of scope**: Library only builds/verifies auth entries |
| Transport security (TLS) | **Assumed** — not a library concern |

## Concrete Worked Example

See `sorocharge-core#9` for a real finding: a signature-binding vulnerability was discovered
by reading the code and noticing that `verify_entry` did not check that the authorizing address
matches the expected payer. This was added per the project's conservative stance toward money
and security. A written threat model would have accelerated that review.

## Related

- `sorocharge-signer/src/verify.rs` — contains the full list of checks performed by `verify_entry`
- `benches/signer_benchmarks.rs` — benchmarks for the signing/verification hot path