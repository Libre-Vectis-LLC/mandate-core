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

/// Store for Edge access token blobs, indexed by Rage public key.
///
/// Follows the same pattern as `KeyBlobStore` but for the EdgeAccessToken,
/// which controls read access at the Edge layer. Rotated on every ring change.
#[async_trait]
pub trait AccessTokenBlobStore {
    /// Insert multiple encrypted access token blobs atomically.
    ///
    /// Called after every RingUpdate event. Each current ring member receives
    /// the same EdgeAccessToken encrypted to their Rage public key.
    ///
    /// # Arguments
    /// * `tenant` - The tenant identifier
    /// * `group_id` - The group identifier
    /// * `ring_hash` - The ring hash at the time of generation
    /// * `blobs` - Vector of `(rage_pub, encrypted_token)` pairs
    async fn put_many_access_tokens(
        &self,
        tenant: TenantId,
        group_id: GroupId,
        ring_hash: [u8; 32],
        blobs: Vec<([u8; 32], Arc<[u8]>)>,
    ) -> Result<(), StorageError>;

    /// Retrieve an encrypted access token blob by Rage public key.
    async fn get_one_access_token(
        &self,
        tenant: TenantId,
        group_id: GroupId,
        rage_pub: [u8; 32],
    ) -> Result<Arc<[u8]>, StorageError>;
}

/// Store for raw Edge access tokens (used by Edge to validate client requests).
///
/// The server stores the raw token alongside the encrypted blobs so that
/// Edge can fetch it via `GetEdgeAccessToken` RPC.
#[async_trait]
pub trait EdgeAccessTokenStore {
    /// Upsert the current access token for a group.
    ///
    /// The previous token is preserved for grace-period validation at Edge.
    async fn upsert(
        &self,
        tenant: TenantId,
        group_id: GroupId,
        ring_hash: [u8; 32],
        current_token: [u8; 32],
        previous_token: Option<[u8; 32]>,
        rotated_at_ms: u64,
    ) -> Result<(), StorageError>;

    /// Get the current and previous access tokens for a group.
    ///
    /// Returns `(current_token, previous_token, rotated_at_ms)`.
    async fn get(
        &self,
        tenant: TenantId,
        group_id: GroupId,
    ) -> Result<([u8; 32], Option<[u8; 32]>, u64), StorageError>;
}
