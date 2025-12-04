//! Mandate core: audit-first, WASM-friendly, no-I/O protocol primitives.
//!
//! Key contracts:
//! - Hashing: canonical JSON (sorted keys, compact) + domain separation, SHA3-256 default with
//!   pluggable digest trait; no floats, ciphertext hashed as-is.
//! - Audit chain: events are signed, signature excluded from content hash; chain is for audit, not
//!   full state replay.
//! - Rings: append-only delta log; reconstruction chooses shortest path from cached anchor to
//!   target hash; ring hashes are order-invariant via nazgul consensus hash.
//! - Storage: single-writer append per tenant, deterministic ordering, zero-copy reads; ring
//!   lookups via `RingView` with optional cache/materialization.
//! - Concurrency: single-writer model avoids optimistic tokens; readers stream deterministically
//!   with keyset pagination.
//! - WASM: no std I/O; `getrandom` wasm_js enabled; target `wasm32-unknown-unknown` should compile
//!   via `cargo check --target wasm32-unknown-unknown`.
//! - Pluggability: digest trait leaves room for future BLAKE3 swap without API breakage.
//!
pub mod crypto;
pub mod event;
pub mod hashing;
pub mod ids;
pub mod ring_log;
pub mod storage;
