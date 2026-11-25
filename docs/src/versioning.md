# Versioning and compatibility

`sorocharge-core` signs and verifies authorizations that move money. A
compatibility surprise is therefore not a cosmetic break: an entry built by
one version and accepted by another must still authorize exactly the transfer
the caller intended. This page states how the workspace versions itself,
what guarantees cross a tag boundary, and what a consumer should pin.

## Exact pins, not ranges

Everything this workspace builds against that defines the wire format or the
cryptography is **exact-pinned** in `Cargo.toml` with `=`, not a caret range:

| Crate | Pin | Why it matters |
|---|---|---|
| `stellar-xdr` | `=30.0.0` | Defines the `SorobanAuthorizationEntry` XDR this library emits and verifies |
| `stellar-strkey` | `=1.0.0` | Address encoding |
| `stellar-rpc-client` | `=30.0.0` | Simulation/submission shapes |
| `ed25519-dalek` | `=3.0.0` | Signature scheme |
| `sha2` | `=0.11.0` | Preimage hashing |
| `getrandom` | `=0.4.3` | Nonce entropy |

`serde`, `serde_json`, `reqwest`, `axum`, and `chrono` are the exceptions:
they use major-range constraints. They do not define the signed bytes — they
carry them over the wire or host them — so a compatible minor update cannot
change what a signature covers. Protocol-critical crates are pinned exactly
because an unexpected XDR or crypto change would.

The pattern is deliberate and repeated: the sibling `sorocharge-php` binding
pins `sorocharge-core` to an exact tagged release for the same reason. That
practice is the recommendation for downstream consumers, not just an
artifact of how this repository builds.

## What a tag guarantees

Each tag (`v0.1.0`, `v0.2.0`, …) is its own compatibility contract. Within a
tagged release, the golden vectors in `tests/golden_vectors/fixtures/` are
the pinned proof of what the library emits: the same inputs produce the
same bytes as the pinned `@stellar/stellar-sdk` version, and CI fails if
that drifts.

**Between tags, no compatibility promise is made beyond Cargo's pre-1.0
semver rules.** With the workspace still in `0.x`, Cargo treats a minor
bump as potentially breaking, and that is accurate here: a minor release may
change public types, error variants, or the minimum protocol version. Patch
releases are bug fixes and are not expected to change signed output, but
they are not a guarantee to build a security argument on. Always read the
release notes for the tag you move to.

This is stronger than ordinary semver, not weaker: the exact-pin table above
means that even a "compatible" dependency bump cannot silently land under a
consumer. If the signed-bytes contract holds, it is because the pins held.

## What a consumer should pin

- **Pin the exact release**, e.g.
  `sorocharge-signer = { git = "https://github.com/sorocharge/sorocharge-core", tag = "v0.2.0" }`,
  not a branch.
- **Never depend on a branch.** `main` is a development target: it is where
  protocol-currency checks and refactors land, and its history is rewritten
  by normal merge workflow.
- **Commit `Cargo.lock`.** For a binary or a service that signs payments,
  the lockfile is part of the deployment artifact; a range in a transitive
  crate is only as stable as the lockfile that resolves it.
- **Re-run the golden vectors when upgrading.** If your service cares about
  byte-identical output (for example because a facilitator caches or diffs
  credentials), keep a copy of the fixtures you were built against and diff
  them after the upgrade.

The same advice applies to the x402 and MPP adapters: they are versioned in
lockstep with `sorocharge-signer` in this workspace, so pin all three at the
same tag rather than mixing releases.
