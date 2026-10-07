# Contributing

Scoped issues are posted for each sprint cycle — see the
[open issues](https://github.com/sorocharge/sorocharge-core/issues) for what's currently
available, organized by area: core protocol correctness, bindings and API surface,
infrastructure and process, publishing and documentation, and contributor-facing examples.
Each issue has a Summary, Acceptance Criteria, and a Tech Stack line, so you can tell what
it needs before picking it up.

## Before you start

- Read [`CLAUDE.md`](https://github.com/sorocharge/sorocharge-core/blob/main/CLAUDE.md) at
  the repo root. It's this project's actual build brief, and the coding standards in it
  (no `unwrap()`/`expect()` outside tests, no floats for amounts or ledger numbers, every
  public error variant specific enough to act on) are enforced, not aspirational.
- Run the full check suite locally before opening a pull request:
  ```sh
  cargo test --workspace
  cargo clippy --workspace --all-targets -- -D warnings
  cargo fmt --all -- --check
  ```
- If your change touches `sorocharge-signer`'s XDR-producing functions, regenerate and
  diff the golden vectors (see [Developer setup](guides/developer-setup.md)) — CI will
  catch a mismatch, but it's faster to catch it yourself first.

## Git workflow

- One commit per logical unit — one function, one type, one test block. Not everything
  bundled into a single "implement feature" commit.
- Conventional commits: `type(scope): description`, lowercase, imperative
  (`fix(signer): ...`, `feat(mpp): ...`, `docs: ...`).
- Push after every commit.
- Never force-push or rewrite already-pushed history.
- Never commit a secret, a test seed phrase, or a funded testnet key — every example reads
  its signing key from an environment variable for exactly this reason.

## Verification standard

This library signs and verifies things that move money. "Looks right" is not the bar —
byte-for-byte correctness against the reference implementation is. If you're adding to
`sorocharge-signer`, a golden-vector test diffing your XDR output against a fixture
generated from the pinned `@stellar/stellar-sdk` version is not optional. If you're adding
a check that reads simulation events or on-chain state, prefer building the test fixture
from a real transaction over a hand-constructed one — see
`crates/sorocharge-signer/src/effects.rs`'s tests for the pattern: a real transaction's
diagnostic events, with specific fields mutated to construct each rejection case.

## Questions

Open an issue, or comment on the one you're planning to pick up before starting substantial
work — especially for anything marked as a scope decision (see e.g.
[`sorocharge-php#5`](https://github.com/sorocharge/sorocharge-php/issues/5), which asks for
a design proposal before any code).
