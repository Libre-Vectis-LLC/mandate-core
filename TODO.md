# Mandate Core TODO (API-first, SHA3-first, audit-friendly)

## Completed
- [x] SHA3-first hashing helpers with `Hash256`/`Hash512`; ring consensus hash via `nazgul` (SHA3-256 default, SHA3-512 only when needed).
- [x] Contextual BLSAG wrapper: `SignatureKind` (anonymous/authoritative), compact/archival, `MasterKeypair` ring-context derivation (SHA3-512); `KeyImage` kept uncompressed.
- [x] WASM path: nazgul pinned to wasm-capable rev; `getrandom` wasm_js enabled.

## P1 (must-have for MVP)
- [x] Event signing integration (audit-focused): replace `Event.signature: Option<Vec<u8>>` with strong `Signature` + Serde; verification API must accept external ring for compact mode. Event chain is for audit (not full state replay), so keep payload canonical and self-verifiable.
- [x] Ring history & replay helpers: define ring-delta records and helpers to reconstruct rings from `RingHash` (ordered members) to support compact signatures and ring-history queries while keeping storage compact.
- [x] Storage traits (memory/Postgres/append-only chain): `EventStore` append (single-node append-only, multi-tenant single table). `RingView` resolves rings by hash with cache hooks; `BanIndex` optional lookup. Postgres-friendly: btree/hash indexes on `(ring_hash)`, `(tenant_token, ring_hash)`, `(master_pubkey, created_at)`; keyset pagination; avoid loading full 10^5-member rings—stream replay from nearest cached ring + delta window. RingDeltaLog derivable from Events; consider materialized cache for hot rings to balance cost vs. latency. Zero-copy reads (`Arc<[u8]>`/slices), deterministic ordering; no full-state replay beyond ring reconstruction.
- [ ] Hash/serialization policy: canonical JSON (sorted keys, no whitespace) + domain-separation prefixes. Keep SHA3-256 default, SHA3-512 when length is required; introduce pluggable digest trait so future BLAKE3 swap is non-breaking.
- [ ] Poll helpers: canonical poll hash (ID-sorted), ciphertext digest helpers; avoid unnecessary Ristretto compression/expansion.

## P2 (quality & docs)
- [ ] Tests: property-based determinism for hashing/serialization; golden vectors (genesis ID, ring hash, poll hash); signature Serde round-trip; lightweight wasm32 check.
- [ ] Docs: expand `lib.rs`/README to spell out audit chain rules, ring reconstruction contract, hash policy, storage concurrency model (single-writer append, no optimistic tokens), WASM notes, and digest-pluggability for future BLAKE3.
