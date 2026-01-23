use super::StorageFacade;
use crate::ids::{GroupId, MasterPublicKey, TenantId};
use crate::storage::{PendingMember, StorageError};

impl StorageFacade {
    // ─────────────────────────────────────────────────────────────────────────
    // Group methods
    // ─────────────────────────────────────────────────────────────────────────

    /// Create a new group.
    pub async fn create_group(
        &self,
        tenant: TenantId,
        tg_group_id: &str,
    ) -> Result<GroupId, StorageError> {
        self.groups.create_group(tenant, tg_group_id).await
    }

    /// Get a group's metadata (tenant ID and Telegram group ID).
    pub async fn get_group(&self, group_id: GroupId) -> Result<(TenantId, String), StorageError> {
        self.groups.get_group(group_id).await
    }

    /// Set the owner's Nazgul public key for a group.
    ///
    /// This key is used for verifying owner/delegate signatures on admin events.
    pub async fn set_owner_pubkey(
        &self,
        group_id: GroupId,
        owner_pubkey: MasterPublicKey,
    ) -> Result<(), StorageError> {
        self.groups.set_owner_pubkey(group_id, owner_pubkey).await
    }

    /// Get the owner's Nazgul public key for a group.
    ///
    /// Returns `None` if the owner pubkey has not been set yet.
    pub async fn get_owner_pubkey(
        &self,
        group_id: GroupId,
    ) -> Result<Option<MasterPublicKey>, StorageError> {
        self.groups.get_owner_pubkey(group_id).await
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Pending member methods
    // ─────────────────────────────────────────────────────────────────────────

    /// Submit a pending member application.
    pub async fn submit_pending_member(
        &self,
        tenant: TenantId,
        group_id: GroupId,
        tg_user_id: &str,
        nazgul_pub: MasterPublicKey,
        rage_pub: [u8; 32],
    ) -> Result<String, StorageError> {
        self.pending_members
            .submit(tenant, group_id, tg_user_id, nazgul_pub, rage_pub)
            .await
    }

    /// List pending members for a group.
    pub async fn list_pending_members(
        &self,
        tenant: TenantId,
        group_id: GroupId,
        limit: usize,
        page_token: Option<String>,
    ) -> Result<(Vec<PendingMember>, Option<String>), StorageError> {
        self.pending_members
            .list(tenant, group_id, limit, page_token)
            .await
    }

    /// Get an approved member by their Telegram user ID.
    ///
    /// This method retrieves an approved member's record for the purpose of
    /// obtaining their cryptographic keys (e.g., for ring operations like kick).
    pub async fn get_approved_member_by_tg_user_id(
        &self,
        tenant: TenantId,
        group_id: GroupId,
        tg_user_id: &str,
    ) -> Result<Option<PendingMember>, StorageError> {
        self.pending_members
            .get_approved_by_tg_user_id(tenant, group_id, tg_user_id)
            .await
    }

    /// Register a standalone user via invite code.
    ///
    /// This atomically validates the invite code, increments its usage,
    /// and creates a pending member record.
    pub async fn register_standalone_member(
        &self,
        tenant: TenantId,
        invite_code: &str,
        nazgul_pub: MasterPublicKey,
        rage_pub: [u8; 32],
        display_name: Option<String>,
        organization_id: Option<String>,
    ) -> Result<(String, GroupId), StorageError> {
        self.pending_members
            .register_standalone(
                tenant,
                invite_code,
                nazgul_pub,
                rage_pub,
                display_name,
                organization_id,
            )
            .await
    }

    /// List all members with optional filtering (Phase 4).
    ///
    /// Returns unified member information including identity and status.
    pub async fn list_all_members(
        &self,
        tenant: TenantId,
        group_id: GroupId,
        limit: usize,
        page_token: Option<String>,
        filter_source: Option<&str>,
        filter_status: Option<&str>,
    ) -> Result<(Vec<crate::storage::MemberInfo>, Option<String>, u32), StorageError> {
        self.pending_members
            .list_all_members(
                tenant,
                group_id,
                limit,
                page_token,
                filter_source,
                filter_status,
            )
            .await
    }
}
