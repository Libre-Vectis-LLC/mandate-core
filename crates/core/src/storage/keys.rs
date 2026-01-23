//! Key material storage (encrypted blobs).

use crate::ids::{GroupId, TenantId};
use async_trait::async_trait;
use std::sync::Arc;

use super::types::StorageError;

/// Store for member key blobs, indexed by Rage public key.
///
/// Keys are scoped by `(tenant, group_id, rage_pub)` to avoid cross-group and cross-tenant leaks.
#[async_trait]
pub trait KeyBlobStore {
    /// Insert multiple encrypted key blobs atomically.
    ///
    /// This method is used during member onboarding to store encrypted key material
    /// for all existing members. Each blob is indexed by the recipient's Rage public key.
    ///
    /// # Arguments
    /// * `tenant` - The tenant identifier
    /// * `group_id` - The group identifier
    /// * `blobs` - Vector of `(rage_pub, encrypted_blob)` pairs
    ///
    /// # Returns
    /// `Ok(())` on successful insertion of all blobs.
    ///
    /// # Errors
    /// * `StorageError::Backend` - When the underlying storage layer fails
    /// * `StorageError::PreconditionFailed` - When tenant or group does not exist
    ///
    /// # Invariants
    /// * All blobs are inserted atomically (all or nothing)
    /// * Duplicate `rage_pub` keys within a single call may cause implementation-defined behavior
    async fn put_many(
        &self,
        tenant: TenantId,
        group_id: GroupId,
        blobs: Vec<([u8; 32], Arc<[u8]>)>,
    ) -> Result<(), StorageError>;

    /// Retrieve an encrypted key blob by Rage public key.
    ///
    /// # Arguments
    /// * `tenant` - The tenant identifier
    /// * `group_id` - The group identifier
    /// * `rage_pub` - The recipient's Rage public key
    ///
    /// # Returns
    /// The encrypted key blob as `Arc<[u8]>`.
    ///
    /// # Errors
    /// * `StorageError::NotFound(NotFound::KeyBlob)` - When no blob exists for this key
    /// * `StorageError::Backend` - When the underlying storage layer fails
    async fn get_one(
        &self,
        tenant: TenantId,
        group_id: GroupId,
        rage_pub: [u8; 32],
    ) -> Result<Arc<[u8]>, StorageError>;
}
