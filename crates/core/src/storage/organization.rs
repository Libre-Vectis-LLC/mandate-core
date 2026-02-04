//! Group metadata and member management.

use crate::ids::{OrganizationId, MasterPublicKey, TenantId};
use async_trait::async_trait;

use super::types::StorageError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PendingMemberStatus {
    Pending,
    Approved,
    Removed,
}

impl PendingMemberStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            PendingMemberStatus::Pending => "pending",
            PendingMemberStatus::Approved => "approved",
            PendingMemberStatus::Removed => "removed",
        }
    }
}

/// Phase 4: Complete member information including identity and status.
/// This struct is returned by `list_all_members` for unified member listing.
#[derive(Clone, Debug)]
pub struct MemberInfo {
    pub nazgul_pub: MasterPublicKey,
    pub identity: crate::event::MemberIdentity,
    pub status: String, // "pending", "approved", "banned"
    pub joined_at_ms: i64,
}

/// Summary of a member's group membership.
/// This struct is returned by `list_organizations_for_member` for wallet restore flow.
#[derive(Clone, Debug)]
pub struct OrganizationMembershipInfo {
    pub org_id: OrganizationId,
    pub joined_at_ms: i64,
    pub status: String,
}

#[derive(Clone, Debug)]
pub struct PendingMember {
    pub pending_id: String,
    pub tg_user_id: String,
    pub nazgul_pub: MasterPublicKey,
    pub rage_pub: [u8; 32],
    pub submitted_at_ms: i64,
}

#[async_trait]
pub trait OrganizationMetadataStore {
    /// Create a new group record.
    ///
    /// This method initializes a new group within a tenant's account and associates it
    /// with a Telegram group identifier.
    ///
    /// # Arguments
    /// * `tenant` - The tenant identifier owning this group
    /// * `tg_group_id` - The Telegram group ID (e.g., `-1001234567890`)
    ///
    /// # Returns
    /// A newly generated `OrganizationId` for the created group.
    ///
    /// # Errors
    /// * `StorageError::AlreadyExists` - When a group with this Telegram ID already exists
    /// * `StorageError::Backend` - When the underlying storage layer fails
    ///
    /// # Invariants
    /// * Group IDs are globally unique
    /// * Each Telegram group ID maps to at most one Mandate group
    async fn create_organization(
        &self,
        tenant: TenantId,
        tg_group_id: &str,
    ) -> Result<OrganizationId, StorageError>;

    /// Retrieve group metadata by group ID.
    ///
    /// # Arguments
    /// * `org_id` - The group identifier
    ///
    /// # Returns
    /// A tuple of `(TenantId, tg_group_id)` containing the owning tenant and Telegram group ID.
    ///
    /// # Errors
    /// * `StorageError::NotFound(NotFound::Organization)` - When the group does not exist
    /// * `StorageError::Backend` - When the underlying storage layer fails
    async fn get_organization(&self, org_id: OrganizationId) -> Result<(TenantId, String), StorageError>;

    /// Set the owner's Nazgul master public key for a group.
    ///
    /// This key is used to:
    /// - Verify owner signatures on admin events (RingUpdate, BanCreate, BanRevoke)
    /// - Derive delegate public keys for delegated signing
    ///
    /// # Arguments
    /// * `org_id` - The group identifier
    /// * `owner_pubkey` - The owner's Nazgul master public key
    ///
    /// # Errors
    /// * `StorageError::NotFound(NotFound::Organization)` - When the group does not exist
    /// * `StorageError::Backend` - When the underlying storage layer fails
    async fn set_owner_pubkey(
        &self,
        org_id: OrganizationId,
        owner_pubkey: MasterPublicKey,
    ) -> Result<(), StorageError>;

    /// Retrieve the owner's Nazgul master public key for a group.
    ///
    /// # Arguments
    /// * `org_id` - The group identifier
    ///
    /// # Returns
    /// The owner's `MasterPublicKey` if set, `None` if not yet configured.
    ///
    /// # Errors
    /// * `StorageError::NotFound(NotFound::Organization)` - When the group does not exist
    /// * `StorageError::Backend` - When the underlying storage layer fails
    async fn get_owner_pubkey(
        &self,
        org_id: OrganizationId,
    ) -> Result<Option<MasterPublicKey>, StorageError>;
}

#[async_trait]
pub trait PendingMemberStore {
    /// Submit a new member join request.
    ///
    /// This method creates a pending member record awaiting owner approval. The member
    /// provides their cryptographic public keys upfront for efficient onboarding after approval.
    ///
    /// # Arguments
    /// * `tenant` - The tenant identifier
    /// * `org_id` - The group identifier
    /// * `tg_user_id` - The Telegram user ID of the joining member
    /// * `nazgul_pub` - The member's Nazgul master public key (for ring signatures)
    /// * `rage_pub` - The member's Rage public key (for encrypted key distribution)
    ///
    /// # Returns
    /// A unique `pending_id` identifying this join request.
    ///
    /// # Errors
    /// * `StorageError::AlreadyExists` - When this user already has a pending request
    /// * `StorageError::Backend` - When the underlying storage layer fails
    ///
    /// # Invariants
    /// * Each Telegram user can have at most one pending request per group
    /// * `submitted_at_ms` is set to the current timestamp in milliseconds
    async fn submit(
        &self,
        tenant: TenantId,
        org_id: OrganizationId,
        tg_user_id: &str,
        nazgul_pub: MasterPublicKey,
        rage_pub: [u8; 32],
    ) -> Result<String, StorageError>;

    /// List pending member join requests (approved members are excluded).
    ///
    /// This method supports keyset pagination using opaque page tokens for efficient
    /// iteration over large pending queues.
    ///
    /// # Arguments
    /// * `tenant` - The tenant identifier
    /// * `org_id` - The group identifier
    /// * `limit` - Maximum number of pending members to return
    /// * `page_token` - Optional continuation token from a previous call
    ///
    /// # Returns
    /// A tuple of `(pending_members, next_page_token)` where `next_page_token` is `None`
    /// if no more results exist.
    ///
    /// # Errors
    /// * `StorageError::Backend` - When the underlying storage layer fails
    ///
    /// # Invariants
    /// * Results are ordered by `submitted_at_ms` (oldest first)
    /// * Approved members (status = Approved) are never included
    async fn list(
        &self,
        tenant: TenantId,
        org_id: OrganizationId,
        limit: usize,
        page_token: Option<String>,
    ) -> Result<(Vec<PendingMember>, Option<String>), StorageError>;

    /// Get an approved member by their Telegram user ID.
    ///
    /// This method retrieves an approved member's record for the purpose of
    /// obtaining their cryptographic keys (e.g., for ring operations like kick).
    ///
    /// # Arguments
    /// * `tenant` - The tenant identifier
    /// * `org_id` - The group identifier
    /// * `tg_user_id` - The Telegram user ID to look up
    ///
    /// # Returns
    /// The approved member's record if found, `None` if no approved member
    /// exists with the given Telegram user ID.
    ///
    /// # Errors
    /// * `StorageError::Backend` - When the underlying storage layer fails
    ///
    /// # Invariants
    /// * Only returns members with status = Approved
    /// * Returns the most recently approved record if multiple exist
    async fn get_approved_by_tg_user_id(
        &self,
        tenant: TenantId,
        org_id: OrganizationId,
        tg_user_id: &str,
    ) -> Result<Option<PendingMember>, StorageError>;

    /// Register a standalone user via invite code.
    ///
    /// This method atomically validates the invite code, increments its usage count,
    /// and creates a pending member record for a standalone (non-Telegram) user.
    ///
    /// # Arguments
    /// * `tenant` - The tenant identifier
    /// * `invite_code` - The invite code to redeem
    /// * `nazgul_pub` - The member's Nazgul master public key (for ring signatures)
    /// * `rage_pub` - The member's Rage public key (for encrypted key distribution)
    /// * `display_name` - Optional user-provided display name
    ///
    /// # Returns
    /// A tuple of `(pending_id, org_id)` on success.
    ///
    /// # Errors
    /// * `StorageError::NotFound` - When invite code doesn't exist
    /// * `StorageError::FailedPrecondition` - When invite code is expired, exhausted, or revoked
    /// * `StorageError::Backend` - When the underlying storage layer fails
    ///
    /// # Invariants
    /// * Operation is atomic: invite code validation, usage increment, and member creation
    ///   all succeed or fail together
    /// * The created member has `identity_source = "standalone"`
    /// * `submitted_at` and `registered_at` are set to the current timestamp
    async fn register_standalone(
        &self,
        tenant: TenantId,
        invite_code: &str,
        nazgul_pub: MasterPublicKey,
        rage_pub: [u8; 32],
        display_name: Option<String>,
    ) -> Result<(String, OrganizationId), StorageError>;

    /// List all members in a group with optional filtering (Phase 4).
    ///
    /// This method returns unified member information including identity and status,
    /// supporting both Telegram and Standalone members.
    ///
    /// # Arguments
    /// * `tenant` - The tenant identifier
    /// * `org_id` - The group identifier
    /// * `limit` - Maximum number of members to return
    /// * `page_token` - Optional continuation token from a previous call
    /// * `filter_source` - Optional filter by identity source
    /// * `filter_status` - Optional filter by status (if None, returns only "approved")
    ///
    /// # Returns
    /// A tuple of `(members, next_page_token, total_count)` where `next_page_token` is `None`
    /// if no more results exist. `total_count` is the total number of members matching criteria.
    ///
    /// # Errors
    /// * `StorageError::Backend` - When the underlying storage layer fails
    ///
    /// # Invariants
    /// * Results are ordered by `submitted_at_ms` (oldest first)
    /// * If `filter_status` is None, only approved members are returned (backward compatibility)
    async fn list_all_members(
        &self,
        tenant: TenantId,
        org_id: OrganizationId,
        limit: usize,
        page_token: Option<String>,
        filter_source: Option<&str>,
        filter_status: Option<&str>,
    ) -> Result<(Vec<MemberInfo>, Option<String>, u32), StorageError>;

    /// List all groups that a member belongs to, by their Nazgul public key.
    ///
    /// This method is used for wallet restore flow where the client needs to discover
    /// its group memberships after recovering from a seed phrase.
    ///
    /// # Arguments
    /// * `tenant` - The tenant identifier
    /// * `nazgul_pub` - The member's Nazgul master public key (32 bytes)
    /// * `limit` - Maximum number of groups to return
    /// * `page_token` - Optional continuation token from a previous call
    /// * `filter_status` - Optional filter by membership status (if None, returns only "approved")
    ///
    /// # Returns
    /// A tuple of `(groups, next_page_token, total_count)` where `next_page_token` is `None`
    /// if no more results exist. `total_count` is the total number of groups matching criteria.
    ///
    /// # Errors
    /// * `StorageError::Backend` - When the underlying storage layer fails
    ///
    /// # Invariants
    /// * Results are ordered by `joined_at_ms` (oldest first)
    /// * If `filter_status` is None, only approved memberships are returned
    async fn list_organizations_for_member(
        &self,
        tenant: TenantId,
        nazgul_pub: &[u8],
        limit: usize,
        page_token: Option<String>,
        filter_status: Option<&str>,
    ) -> Result<(Vec<OrganizationMembershipInfo>, Option<String>, u32), StorageError>;
}
