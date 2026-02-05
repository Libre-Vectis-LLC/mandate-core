//! Specialized lookup indices (bans, votes, polls).

use crate::ids::{KeyImage, OrganizationId, RingHash, TenantId};
use async_trait::async_trait;

use super::types::StorageError;

/// Maximum number of bans allowed per ring hash to prevent OOM attacks.
///
/// This limit defends against malicious tenants creating unlimited fake KeyImages
/// to exhaust server memory. Since bans are cached in memory, an attacker could
/// otherwise add millions of bans to cause out-of-memory conditions.
///
/// The limit is per ring hash because:
/// - Each ring update naturally clears old bans (different KeyImages)
/// - Legitimate use cases rarely need more than a few hundred bans per ring state
/// - This allows gradual growth with ring updates while preventing abuse
pub const MAX_BANS_PER_RING_HASH: usize = 1000;

/// Operation categories enforced by ban scopes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BannedOperation {
    /// Message creation and other content posts.
    PostMessage,
    /// Vote casting within a poll.
    CastVote,
    /// Poll creation (treated as a content post for bans).
    CreatePoll,
}

/// Optional ban index for fast key-image checks.
#[async_trait]
pub trait BanIndex {
    /// Check whether a key image is currently banned for a specific operation.
    ///
    /// This method provides fast lookups for ban enforcement. Implementations may use
    /// an index (e.g., PostgreSQL partial index on active bans) to avoid full table scans.
    ///
    /// # Arguments
    /// * `tenant` - The tenant identifier
    /// * `org_id` - The org IDentifier
    /// * `key_image` - The key image to check
    /// * `operation` - The operation type being attempted
    ///
    /// # Returns
    /// `true` if the key image is currently banned for this operation, `false` otherwise.
    ///
    /// # Errors
    /// * `StorageError::Backend` - When the underlying storage layer fails
    ///
    /// # Invariants
    /// * Bans are scoped per `(org_id, operation)` pair
    /// * A banned key image for `PostMessage` does not affect `CastVote` unless separately banned
    async fn is_banned(
        &self,
        tenant: TenantId,
        org_id: OrganizationId,
        key_image: &KeyImage,
        operation: BannedOperation,
    ) -> Result<bool, StorageError>;

    /// Count the number of active bans for a specific ring hash.
    ///
    /// This method is used to enforce [`MAX_BANS_PER_RING_HASH`] limits to prevent
    /// OOM attacks where malicious tenants add unlimited fake KeyImages.
    ///
    /// # Arguments
    /// * `tenant` - The tenant identifier
    /// * `org_id` - The org IDentifier
    /// * `ring_hash` - The ring hash to count bans for
    ///
    /// # Returns
    /// The count of active bans associated with the given ring hash.
    ///
    /// # Errors
    /// * `StorageError::Backend` - When the underlying storage layer fails
    async fn count_bans_for_ring(
        &self,
        tenant: TenantId,
        org_id: OrganizationId,
        ring_hash: &RingHash,
    ) -> Result<usize, StorageError>;
}

/// Index to prevent vote key-image reuse within a poll.
#[async_trait]
pub trait VoteKeyImageIndex {
    /// Check whether a key image has already been used to vote in a specific poll.
    ///
    /// This enforces the one-vote-per-member rule by tracking key images per poll.
    /// Implementations should use an index on `(poll_id, key_image)` for fast lookups.
    ///
    /// # Arguments
    /// * `tenant` - The tenant identifier
    /// * `org_id` - The org IDentifier
    /// * `poll_id` - The poll identifier
    /// * `key_image` - The key image to check
    ///
    /// # Returns
    /// `true` if this key image has already voted in this poll, `false` otherwise.
    ///
    /// # Errors
    /// * `StorageError::Backend` - When the underlying storage layer fails
    ///
    /// # Invariants
    /// * Key images are scoped per `(poll_id, org_id)` pair
    /// * A key image used in Poll A does not affect eligibility in Poll B
    async fn is_used(
        &self,
        tenant: TenantId,
        org_id: OrganizationId,
        poll_id: &str,
        key_image: &KeyImage,
    ) -> Result<bool, StorageError>;
}

/// Index mapping poll IDs to the ring hash at poll creation time.
///
/// This index is used during vote verification to retrieve the exact ring
/// that was in effect when the poll was created. Votes must be verified
/// against this ring to ensure only eligible members (those present at
/// poll creation) can vote.
#[async_trait]
pub trait PollRingHashIndex {
    /// Store the ring hash for a newly created poll.
    ///
    /// This should be called atomically when a `PollCreate` event is appended
    /// to the event log. The stored ring hash represents the membership snapshot
    /// at poll creation time.
    ///
    /// # Arguments
    /// * `tenant` - The tenant identifier
    /// * `org_id` - The org IDentifier
    /// * `poll_id` - The poll identifier (unique within the group)
    /// * `ring_hash` - The ring hash at poll creation time
    ///
    /// # Returns
    /// `Ok(())` on successful storage.
    ///
    /// # Errors
    /// * `StorageError::AlreadyExists` - When a mapping for this poll already exists
    /// * `StorageError::Backend` - When the underlying storage layer fails
    ///
    /// # Invariants
    /// * Each poll has exactly one associated ring hash (immutable after creation)
    /// * The ring hash is scoped per `(tenant, org_id, poll_id)` tuple
    async fn store(
        &self,
        tenant: TenantId,
        org_id: OrganizationId,
        poll_id: &str,
        ring_hash: RingHash,
    ) -> Result<(), StorageError>;

    /// Retrieve the ring hash for a poll.
    ///
    /// This is used during vote verification to get the ring against which
    /// the vote's ring signature must be verified.
    ///
    /// # Arguments
    /// * `tenant` - The tenant identifier
    /// * `org_id` - The org IDentifier
    /// * `poll_id` - The poll identifier
    ///
    /// # Returns
    /// The `RingHash` that was in effect when the poll was created.
    ///
    /// # Errors
    /// * `StorageError::NotFound` - When the poll does not exist
    /// * `StorageError::Backend` - When the underlying storage layer fails
    async fn get(
        &self,
        tenant: TenantId,
        org_id: OrganizationId,
        poll_id: &str,
    ) -> Result<RingHash, StorageError>;
}
