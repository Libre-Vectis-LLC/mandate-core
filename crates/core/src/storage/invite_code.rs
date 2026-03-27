//! Invite code storage trait for managing organization membership invite codes.

use crate::ids::{OrganizationId, TenantId};
use crate::storage::StorageError;
use async_trait::async_trait;

/// Metadata for a stored invite code.
#[derive(Clone, Debug)]
pub struct InviteCodeEntry {
    /// The invite code string (URL-safe, 20 characters).
    pub code: String,
    /// Tenant that owns this invite code.
    pub tenant_id: TenantId,
    /// Organization this invite code grants access to.
    pub org_id: OrganizationId,
    /// Admin ID who created this code.
    pub created_by: String,
    /// Unix timestamp in milliseconds when the code was created.
    pub created_at_ms: i64,
    /// Optional expiration time (Unix timestamp in milliseconds).
    pub expires_at_ms: Option<i64>,
    /// Maximum number of times this code can be redeemed.
    pub max_uses: u32,
    /// Current number of times this code has been redeemed.
    pub current_uses: u32,
    /// Optional JSON metadata for registration form pre-fill.
    pub metadata: Option<String>,
    /// Whether the code is active (false if revoked).
    pub is_active: bool,
}

/// Parameters for creating a new invite code.
pub struct CreateInviteCodeParams {
    /// Organization this invite code grants access to.
    pub org_id: OrganizationId,
    /// Admin ID who is creating this code.
    pub created_by: String,
    /// Optional expiration time (Unix timestamp in milliseconds).
    pub expires_at_ms: Option<i64>,
    /// Maximum number of times this code can be redeemed (must be >= 1).
    pub max_uses: u32,
    /// Optional JSON metadata for registration form pre-fill.
    pub metadata: Option<String>,
}

/// Storage trait for invite code lifecycle management.
///
/// Implementations must be safe for concurrent access from multiple
/// gRPC handler tasks.
#[async_trait]
pub trait InviteCodeStore {
    /// Create a new invite code with a cryptographically random value.
    ///
    /// Returns the generated code string on success.
    async fn create_invite_code(
        &self,
        tenant: TenantId,
        params: CreateInviteCodeParams,
    ) -> Result<String, StorageError>;

    /// Retrieve an invite code entry by its code string.
    ///
    /// Returns `StorageError::NotFound` if the code does not exist.
    async fn get_invite_code(
        &self,
        tenant: TenantId,
        code: &str,
    ) -> Result<InviteCodeEntry, StorageError>;

    /// List invite codes for an organization in reverse chronological order.
    ///
    /// Returns `(entries, next_page_token)`. The page token is opaque.
    async fn list_invite_codes(
        &self,
        tenant: TenantId,
        org_id: OrganizationId,
        limit: usize,
        page_token: Option<String>,
    ) -> Result<(Vec<InviteCodeEntry>, Option<String>), StorageError>;

    /// Atomically validate an invite code and increment its usage count.
    ///
    /// This operation MUST be atomic: the check (active, not expired,
    /// `current_uses < max_uses`) and the increment MUST be indivisible.
    /// Concurrent callers racing on the same code MUST NOT exceed `max_uses`.
    ///
    /// Returns the updated `InviteCodeEntry` on success.
    ///
    /// # Errors
    /// - `StorageError::NotFound` if code does not exist
    /// - `StorageError::PreconditionFailed` if code is revoked, expired, or exhausted
    async fn validate_and_increment_usage(
        &self,
        tenant: TenantId,
        code: &str,
    ) -> Result<InviteCodeEntry, StorageError>;

    /// Revoke an invite code (set `is_active = false`).
    ///
    /// Idempotent: revoking an already-revoked code succeeds.
    ///
    /// Returns `StorageError::NotFound` if the code does not exist.
    async fn revoke_invite_code(&self, tenant: TenantId, code: &str) -> Result<(), StorageError>;
}
