# Mandate Core TODO (API-first, SHA3-first, audit-friendly)

## Completed
- [x] SHA3-first hashing helpers with `Hash256`/`Hash512`; ring consensus hash via `nazgul` (SHA3-256 default, SHA3-512 only when needed).
- [x] Contextual BLSAG wrapper: `SignatureKind` (anonymous/authoritative), compact/archival, `MasterKeypair` ring-context derivation (SHA3-512); `KeyImage` kept uncompressed.
- [x] WASM path: nazgul pinned to wasm-capable rev; `getrandom` wasm_js enabled.

## P1 (must-have for MVP)
- [x] Event signing integration (audit-focused): replace `Event.signature: Option<Vec<u8>>` with strong `Signature` + Serde; verification API must accept external ring for compact mode. Event chain is for audit (not full state replay), so keep payload canonical and self-verifiable.
- [x] Ring history & replay helpers: define ring-delta records and helpers to reconstruct rings from `RingHash` (ordered members) to support compact signatures and ring-history queries while keeping storage compact.
- [x] Storage traits (memory/Postgres/append-only chain): `EventStore` append (single-node append-only, multi-tenant single table). `RingView` resolves rings by hash with cache hooks; `BanIndex` optional lookup. Postgres-friendly: btree/hash indexes on `(ring_hash)`, `(tenant_token, ring_hash)`, `(master_pubkey, created_at)`; keyset pagination; avoid loading full 10^5-member rings—stream replay from nearest cached ring + delta window. RingDeltaLog derivable from Events; consider materialized cache for hot rings to balance cost vs. latency. Zero-copy reads (`Arc<[u8]>`/slices), deterministic ordering; no full-state replay beyond ring reconstruction.
- [x] Hash/serialization policy: canonical JSON (sorted keys, no whitespace) + domain-separation prefixes. Keep SHA3-256 default, SHA3-512 when length is required; introduce pluggable digest trait so future BLAKE3 swap is non-breaking.
- [x] Poll helpers: canonical poll hash (ID-sorted), ciphertext digest helpers; avoid unnecessary Ristretto compression/expansion.
- [x] KeyManager & Encryption: BIP39 wallet, HKDF-SHA3 key derivation (Nazgul/Rage), and Age X25519 integration for event content encryption.

## P2 (quality & docs)
- [x] Tests: property-based determinism for hashing/serialization; golden vectors (genesis ID, ring hash, poll hash); signature Serde round-trip; lightweight wasm32 check.
- [x] Docs: expand `lib.rs`/README to spell out audit chain rules, ring reconstruction contract, hash policy, storage concurrency model (single-writer append, no optimistic tokens), WASM notes, and digest-pluggability for future BLAKE3.

## Next (design alignment with latest dev drafts)
- [x] KDF/Derivation unification: add HKDF-SHA3 helpers (default 256, optional 512; keep pluggable interface for future BLAKE3). Provide domain/context builders for group/event/poll keys.
- [x] Group/key types: introduce `GroupId` (UUID/ULID newtype) and `EventUlid` to replace raw strings in derivations/hashes; bind derivation helpers to these types.
- [x] Poll key reuse rule: encode that VoteCast derives its symmetric key from the PollCreate event_id (ULID) to avoid per-vote key inflation; document and test.
- [x] E2EE access after ban: clarify docs that kicked members retain K_shared but cannot fetch new ciphertext, so cannot read new events.
- [x] Public/private derivation parity: in key manager expose helpers so clients (KeyPair) and servers (RistrettoPoint only) share non-hardened derivation paths via `nazgul::traits::Derivable`, incorporating group_id/ring_hash/poll contexts.
- [x] Key blob helpers: pure-logic interfaces for “one bucket per person” K_shared distribution (age/rage-based), no I/O; align with group_encryption_design.md.

## gRPC implementation (shared server/edge APIs)
- [x] Error model & status mapping: gRPC status → domain errors; document token metadata key.
- [x] Service stubs wired to core types: AuthService, BillingService, GroupService, MemberService, EventService, RingService.
- [x] Conversion completeness: proto ↔ core coverage for ring deltas, key blobs, hashes; add tests.
- [ ] Pagination & limits: finalize `PageToken` semantics and default/max `limit` per service.
- [ ] Authn interceptor: enforce `x-api-token` metadata; tonic unit tests.
- [ ] Storage wiring: map EventStore/RingView/BanIndex traits to service handlers (with in-memory mock for tests).
- [ ] Streaming smoke tests: StreamEvents/StreamRing with pagination and batching.
