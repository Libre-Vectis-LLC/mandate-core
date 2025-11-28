ee08a12a94d0c7e9cbe1fe645b0b6b3e65c172e4
- TODO updated with PostgreSQL-friendly storage guidance: multi-tenant single table, ring hash indexes, keyset pagination, stream replay from cached ring + delta window, and caching RingDeltaLog derived from events to balance cost/latency.

e2788880482d84970a2ea663bd4c9961cc80bb63
- Split P1 ring/poll helpers: ring history/replay stays done; poll hashing/digest helpers remain as TODO.
- Clarified storage concurrency note: single-writer append, no optimistic tokens; SHA3-first stance unchanged.

03359b9c1f2af12b8b89be3f7f63d3523d3d3a7e
- Refactored ring delta log to use nazgul `Ring.members` (public) with sorted members for deterministic hashes; switched point (de)serialization to `LocalByteConvertible` helpers and fixed shortest-path replay logic.
- Bumped nazgul to b9aeb09 for the public members field; TODO reflects single-node append-only storage focus.

df63059adf6d2b5f07d4d6d9e0cce4efcf1f0c1d
- Added single-node ring delta log (`RingDeltaLog`) with shortest-path forward/backward replay to reconstruct rings by `RingHash`; deltas are add/remove master pubkey. Included tests for forward/backward replay; kept SHA3-256 ring hashing.
- Updated TODO: ring history item completed; storage TODO now single-node append-only (no optimistic token).

d415a596fb7b779f0b12f9d00bb0fdb45bb0ed2c
- Rewrote TODO roadmap: SHA3-first, future-digest-pluggable, clarified P1 tasks (signature integration, state reducers, storage traits, PoW) and P2 tests/docs.
- Kept blake3 out by default while reserving abstraction point for future swap; no code changes beyond planning document.

c5d5ba876604271c8c7938ff0cf801726c2bd92b7
- Embedded strong `Signature` type into `Event` (serde-enabled) and added audit-focused round-trip test using contextual BLSAG (compact mode with external ring).
- Marked event-signing TODO as complete; kept ring hash helper for compact verification and avoided key-image compression changes.

51fada2009f7c95c8c37c2f10129a63f17f1c78f
- Rewrote TODO after reset: audit-focused event chain (no full state replay), ring history reconstruction helpers, storage traits for memory/Postgres/append-only backends, SHA3-first with future digest plug point, PoW to use rspow equix.

dcc705da9c38f85864894b7f041f68150ff4462d
- Trimmed TODO backlog by removing completed P0 items and restating remaining work at P1/P2.
- Standardized hash policy to prefer SHA3-256 (use SHA3-512 only when digest length is strictly needed); aligns helpers/tests/docs tasks accordingly.
b72575f6618cab6df9f74b41d6c6b5e2a82d0dcc
- Introduced `hashing` module with SHA3-256 as default and optional SHA3-512, covering byte, ciphertext, and nazgul ring consensus hashes.
- Removed blake3 dependency; pinned nazgul to master (0808e847) to leverage production ring hashing and ordering invariants.
- Added deterministic tests for SHA3 helpers and order-invariant ring hashing; no API surface changes elsewhere.
d29652cbd321042417dd786b075efb0a36921356
- Switched hashing helpers to Newtype pattern (`Hash256`, `Hash512`) for stronger typing; ring hashing now returns `RingHash`.
- Defaulted to nazgul main commit b41d0392… to pick up production consensus hash; SHA3-256 remains default with SHA3-512 as optional.
- Adjusted helpers/tests accordingly; kept WASM-friendly, no I/O changes.
f41a0cef71df3d9d41df1b793ba0be840a4d7507
- Rebased signature layer on Nazgul native types: RingHash re-exported, KeyImage now RistrettoPoint (uncompressed), derive_for_ring_context uses RingContext with SHA3-512 derivation.
- ContextualBLSAG signing kept (compact/archival), removes redundant verify helper; ring hashing stays SHA3-256 for audit paths.
- Tests updated for new derivation and key-image handling; fmt/clippy/tests pass.
9a982f9c454e1d6d9d1d3f5f8db5368dc68b7a5c
- Removed redundant ring-hash helpers after reverting; kept direct consensus hash use via nazgul types for clarity.
cbc6dffc947db2c5d5e0f36a38adced25ffd9fe9
- Updated nazgul dependency to wasm-enabled commit so mandate-core builds on wasm32-unknown-unknown with getrandom wasm_js backend.
e0341d6a21fae1de08e23a76cd90c2d5a58f3a6e
- Added contextual signature abstraction: anonymous/authoritative wrapper over Nazgul `ContextualBLSAG` with compact/archival storage modes and SHA3-512 signing/verification.
- Introduced `MasterKeypair` helper deriving session keys from ring hash (SHA3-512), exposed key images as strong `KeyImage` newtype, and provided ring-hash accessors.
- Tests cover compact vs archival verification, deterministic derivation, and key-image extraction; fmt/clippy/tests all pass.
f41a0cef71df3d9d41df1b793ba0be840a4d7507
- Rebased signature layer on Nazgul native types: RingHash re-exported, KeyImage now RistrettoPoint (uncompressed), derive_for_ring_context uses RingContext with SHA3-512 derivation.
- ContextualBLSAG signing kept (compact/archival), removes redundant verify helper; ring hashing stays SHA3-256 for audit paths.
- Tests updated for new derivation and key-image handling; fmt/clippy/tests pass.
