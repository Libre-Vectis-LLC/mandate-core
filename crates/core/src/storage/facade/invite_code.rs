use crate::ids::{OrganizationId, TenantId};
use crate::storage::invite_code::{CreateInviteCodeParams, InviteCodeEntry};
use crate::storage::{StorageError, StorageFacade};

impl StorageFacade {
    /// Create a new invite code. Requires the invite code store to be configured.
    pub async fn create_invite_code(
        &self,
        tenant: TenantId,
        params: CreateInviteCodeParams,
    ) -> Result<String, StorageError> {
        self.invite_codes
            .as_ref()
            .ok_or_else(|| StorageError::Backend("invite code store not configured".into()))?
            .create_invite_code(tenant, params)
            .await
    }

    /// Retrieve an invite code entry by its code string.
    pub async fn get_invite_code(
        &self,
        tenant: TenantId,
        code: &str,
    ) -> Result<InviteCodeEntry, StorageError> {
        self.invite_codes
            .as_ref()
            .ok_or_else(|| StorageError::Backend("invite code store not configured".into()))?
            .get_invite_code(tenant, code)
            .await
    }

    /// List invite codes for an organization.
    pub async fn list_invite_codes(
        &self,
        tenant: TenantId,
        org_id: OrganizationId,
        limit: usize,
        page_token: Option<String>,
    ) -> Result<(Vec<InviteCodeEntry>, Option<String>), StorageError> {
        self.invite_codes
            .as_ref()
            .ok_or_else(|| StorageError::Backend("invite code store not configured".into()))?
            .list_invite_codes(tenant, org_id, limit, page_token)
            .await
    }

    /// Atomically validate an invite code and increment its usage count.
    pub async fn validate_and_increment_invite_code(
        &self,
        tenant: TenantId,
        code: &str,
    ) -> Result<InviteCodeEntry, StorageError> {
        self.invite_codes
            .as_ref()
            .ok_or_else(|| StorageError::Backend("invite code store not configured".into()))?
            .validate_and_increment_usage(tenant, code)
            .await
    }

    /// Revoke an invite code.
    pub async fn revoke_invite_code(
        &self,
        tenant: TenantId,
        code: &str,
    ) -> Result<(), StorageError> {
        self.invite_codes
            .as_ref()
            .ok_or_else(|| StorageError::Backend("invite code store not configured".into()))?
            .revoke_invite_code(tenant, code)
            .await
    }
}
