/// In-memory storage implementations for all domain modules.
///
/// This module provides pluggable in-memory backends for development,
/// testing, and the Community Edition reference server.
///
/// # Architecture
///
/// Each submodule implements storage traits for a specific domain:
/// - `tenant`: Tenant token resolution
/// - `event`: Event streaming and append-only log
/// - `ring`: Ring delta log and reconstruction
/// - `billing`: Tenant/group balance tracking and gift cards
/// - `member`: Pending member queue
/// - `key_blob`: Encrypted key blob storage
/// - `group`: Group metadata
/// - `ban`: Ban index for moderation
/// - `vote`: Vote key image deduplication
pub mod ban;
pub mod billing;
pub mod event;
pub mod group;
pub mod key_blob;
pub mod member;
pub mod ring;
pub mod tenant;
pub mod vote;

// Re-export all public types for backward compatibility
pub use ban::{InMemoryBanIndex, NoopBanIndex};
pub use billing::{InMemoryBilling, InMemoryGiftCards};
pub use event::InMemoryEvents;
pub use group::InMemoryGroups;
pub use key_blob::InMemoryKeyBlobs;
pub use member::InMemoryPendingMembers;
pub use ring::InMemoryRings;
pub use tenant::InMemoryTenantTokens;
pub use vote::{InMemoryVoteKeyImages, NoopVoteKeyImages};
