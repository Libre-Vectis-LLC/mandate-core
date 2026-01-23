use super::StorageFacade;
use crate::ids::{TenantId, TenantToken};
use crate::storage::{StorageError, TenantTokenError};

impl StorageFacade {
    // ─────────────────────────────────────────────────────────────────────────
    // Tenant token methods
    // ─────────────────────────────────────────────────────────────────────────

    /// Resolve a tenant token to a tenant ID.
    pub async fn resolve_tenant(&self, token: &TenantToken) -> Result<TenantId, TenantTokenError> {
        self.tenant_tokens.resolve_tenant(token).await
    }

    /// Insert a new tenant token mapping.
    pub async fn insert_tenant_token(
        &self,
        token: &TenantToken,
        tenant: TenantId,
    ) -> Result<(), StorageError> {
        self.tenant_tokens.insert(token, tenant).await
    }
}
