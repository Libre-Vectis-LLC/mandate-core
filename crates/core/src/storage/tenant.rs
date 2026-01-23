//! Tenant identity resolution.

use crate::ids::{TenantId, TenantToken};
use async_trait::async_trait;

use super::types::{StorageError, TenantTokenError};

/// Resolve a tenant-scoped API token into a tenant identity.
///
/// The real implementation belongs to server/enterprise (cache + DB). Core uses this
/// abstraction so it does not bake in any assumptions about token format or rotation.
#[async_trait]
pub trait TenantTokenStore {
    /// Resolve a tenant token into the associated tenant identifier.
    ///
    /// # Arguments
    /// * `token` - Opaque tenant token provided by the client
    ///
    /// # Returns
    /// The `TenantId` associated with this token.
    ///
    /// # Errors
    /// * `TenantTokenError::Unknown` - When the token does not exist in the store
    /// * `TenantTokenError::Backend` - When the underlying storage layer fails
    async fn resolve_tenant(&self, token: &TenantToken) -> Result<TenantId, TenantTokenError>;

    /// Insert a new tenant token mapping.
    ///
    /// # Arguments
    /// * `token` - The token to store
    /// * `tenant` - The tenant identifier to associate with this token
    ///
    /// # Returns
    /// `Ok(())` on successful insertion.
    ///
    /// # Errors
    /// * `StorageError::AlreadyExists` - When a mapping for this token already exists
    /// * `StorageError::Backend` - When the underlying storage layer fails
    async fn insert(&self, token: &TenantToken, tenant: TenantId) -> Result<(), StorageError>;
}
