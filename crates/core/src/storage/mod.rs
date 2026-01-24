//! Storage-facing traits for audit-first, single-writer append workflows.
//!
//! Design goals:
//! - Single table, multi-tenant, append-only event log (no routine replay; audit-focused).
//! - Zero-copy reads via `Arc<[u8]>`/slices; deterministic ordering by append sequence.
//! - Ring reconstruction is the only replay scenario; implementations find a shortest-path delta slice.
//! - PostgreSQL-friendly: btree/hash indexes on `(ring_hash)`, `(tenant_id, group_id, ring_hash)`,
//!   `(master_pubkey, created_at)`, keyset pagination.

pub mod facade;
pub use facade::{StorageFacade, StorageFacadeBuilder, StorageFacadeBuilderError};

pub mod billing;
pub mod event;
pub mod group;
pub mod index;
pub mod keys;
pub mod ring;
pub mod tenant;
pub mod types;

// Flattened re-exports for backward compatibility
pub use types::{
    EventBytes, EventRecord, IdempotencyErrorCode, IdempotencyResult, NotFound, RingDeltaPath,
    StorageError, TenantTokenError,
};

pub use event::{EventReader, EventStore, EventWriter};

pub use ring::{RingView, RingWriter};

pub use keys::KeyBlobStore;

pub use tenant::TenantTokenStore;

pub use group::{
    GroupMetadataStore, MemberInfo, PendingMember, PendingMemberStatus, PendingMemberStore,
};

pub use billing::{BillingStore, GiftCard, GiftCardStore, TenantBalanceInfo};

pub use index::{
    BanIndex, BannedOperation, PollRingHashIndex, VoteKeyImageIndex, MAX_BANS_PER_RING_HASH,
};
