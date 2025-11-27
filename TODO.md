# Mandate Core TODO (API-first, EE-ready)

- [ ] P1 Crypto abstraction: define signature enum (anonymous vs authoritative), Nazgul key-image helpers, and session/master key derivation API surface; keep implementations pure and panic-free.
- [ ] P1 State/cache view models: structs for `Group`, `Member` (with status), `AnonymousAccount` quotas, `BanRecord`, and `RingBanInfo`; outline pure reducers that apply `EventType` deltas to these views for high read throughput.
- [ ] P1 High-concurrency log API: sketch traits for append-only event log, ring snapshot, and ban index (`EventStore`, `RingView`, `BanIndex`) with optimistic append tokens, group-based sharding hints, and zero-copy read views (`Arc<[u8]>`/slices) for EE latency budgets.
- [ ] P1 Hash policy & helpers: standardize on SHA3-256 for event/payload/ring hashes (only fall back to SHA3-512 when digest extension is strictly required); provide helpers for compressed Ristretto bytes, ciphertext digests, ring hash from ordered member list, and poll hash from canonical event strings; keep algorithms `no_std` friendly and bench-ready.
- [ ] P2 Testing scaffold: property-based tests for deterministic serialization/hashing (aligned with SHA3-256 policy), golden vectors for genesis id/ring hash, and concurrency-safety apply tests (single-threaded runner acceptable for now).
- [ ] P2 Documentation: expand `lib.rs` docs to spell out event-chain rules, determinism requirements, hash policy, and how storage/backends should consume the core in enterprise deployments.
