# mandate-core

Mandate core provides audit-first primitives (hashing, signing, key derivation, and storage contracts) for the Mandate protocol. It is WASM-friendly and keeps I/O out of the crate so callers can plug in their own transports and persistence layers.

## Hashing & IDs
- Canonical JSON (sorted keys, no whitespace) with domain separation; SHA3-256 by default, SHA3-512 available when length is needed. Digest abstraction allows a future BLAKE3 swap without API breakage.
- Strongly typed identifiers: `GroupId` / `TenantId` / `EventUlid` (ULID newtypes) and byte-based `EventId` / `ContentHash`.

## Key Derivation & Encryption
- HKDF-SHA3 helpers with labeled contexts: identities, group-shared secret (`K_shared`), delegate signer, member session (group + ring), event keys, and poll keys (VoteCast reuses the PollCreate ULID-derived key to avoid per-vote inflation).
- Public-only derivation mirrors private derivation via nazgul `Derivable`, so servers that hold only public keys can verify delegate/session keys without secrets.
- Key blobs: “one bucket per person” helpers encrypt `K_shared` to a recipient’s rage public key with a versioned prefix check; pure logic, no I/O side effects.

## Storage & Concurrency
- Single-writer append per tenant; deterministic keyset pagination for readers. No optimistic tokens are needed because the writer is serialized; readers stream in order.
- Rings are reconstructed from deltas via shortest-path replay; storage traits stay zero-copy (`Arc<[u8]>`).

## Billing Semantics
- Tenants hold a spendable balance in nanos; gift card redemption credits that balance.
- Group budgets are funded by tenant transfers; `BillingStore` debits the tenant and credits the group in one transaction, rejecting overdrafts.

## Ban & Anti-Replay Indices
- `BanIndex` answers whether a key image is banned for a specific operation (`PostMessage`, `CreatePoll`, `CastVote`) based on `BanScope`.
- `VoteKeyImageIndex` tracks `(tenant, group_id, poll_id, key_image)` reuse to prevent double voting; writers should update it atomically with event append.

## Multi-Group Invariants
- The external API boundary is `(tenant token, group_id)`: every RPC that reads or mutates group state must take a `group_id` and must never mix state across groups.
- Rings are per group. Two groups may have identical membership sets (and therefore the same ring hash), but they are still distinct groups.
- Key derivation is group-scoped:
  - `K_shared` is derived from `group_id`, so event/poll encryption keys derived from `K_shared` inherit group isolation.
  - Session signing keys are derived from `group_id || ring_hash`, so even identical rings across groups produce distinct session keys.
- These invariants prevent cross-group privacy leaks and avoid derivation collisions in multi-group tenants.

## Access After Ban (E2EE)
- A removed member retains any prior `K_shared`, but cannot fetch new ciphertext after removal. Without the new ciphertext they cannot decrypt new events, even though old keys remain.

## WASM
- `getrandom` is enabled for `wasm32-unknown-unknown`; the crate avoids std I/O to keep the target clean.
