use std::sync::Arc;

use super::StorageFacade;
use crate::ids::{OrganizationId, TenantId};
use crate::storage::StorageError;

impl StorageFacade {
    // ─────────────────────────────────────────────────────────────────────────
    // Key blob methods
    // ─────────────────────────────────────────────────────────────────────────

    /// Store multiple key blobs.
    pub async fn put_key_blobs(
        &self,
        tenant: TenantId,
        org_id: OrganizationId,
        blobs: Vec<([u8; 32], Arc<[u8]>)>,
    ) -> Result<(), StorageError> {
        self.key_blobs.put_many(tenant, org_id, blobs).await
    }

    /// Retrieve a single key blob by rage public key.
    pub async fn get_key_blob(
        &self,
        tenant: TenantId,
        org_id: OrganizationId,
        rage_pub: [u8; 32],
    ) -> Result<Arc<[u8]>, StorageError> {
        self.key_blobs.get_one(tenant, org_id, rage_pub).await
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Access token blob methods (enterprise-only)
    // ─────────────────────────────────────────────────────────────────────────

    /// Store multiple access token blobs.
    pub async fn put_access_token_blobs(
        &self,
        tenant: TenantId,
        org_id: OrganizationId,
        ring_hash: [u8; 32],
        blobs: Vec<([u8; 32], Arc<[u8]>)>,
    ) -> Result<(), StorageError> {
        self.access_token_blobs
            .as_ref()
            .ok_or(StorageError::Backend(
                "access token blobs not configured".into(),
            ))?
            .put_many_access_tokens(tenant, org_id, ring_hash, blobs)
            .await
    }

    /// Retrieve a single access token blob by rage public key.
    pub async fn get_access_token_blob(
        &self,
        tenant: TenantId,
        org_id: OrganizationId,
        rage_pub: [u8; 32],
    ) -> Result<Arc<[u8]>, StorageError> {
        self.access_token_blobs
            .as_ref()
            .ok_or(StorageError::Backend(
                "access token blobs not configured".into(),
            ))?
            .get_one_access_token(tenant, org_id, rage_pub)
            .await
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Edge access token methods (enterprise-only)
    // ─────────────────────────────────────────────────────────────────────────

    /// Upsert edge access token for an org.
    pub async fn upsert_edge_access_token(
        &self,
        tenant: TenantId,
        org_id: OrganizationId,
        ring_hash: [u8; 32],
        current_token: [u8; 32],
        previous_token: Option<[u8; 32]>,
        rotated_at_ms: u64,
    ) -> Result<(), StorageError> {
        self.edge_access_tokens
            .as_ref()
            .ok_or(StorageError::Backend(
                "edge access tokens not configured".into(),
            ))?
            .upsert(
                tenant,
                org_id,
                ring_hash,
                current_token,
                previous_token,
                rotated_at_ms,
            )
            .await
    }

    /// Get edge access token for an org.
    pub async fn get_edge_access_token(
        &self,
        tenant: TenantId,
        org_id: OrganizationId,
    ) -> Result<([u8; 32], Option<[u8; 32]>, u64), StorageError> {
        self.edge_access_tokens
            .as_ref()
            .ok_or(StorageError::Backend(
                "edge access tokens not configured".into(),
            ))?
            .get(tenant, org_id)
            .await
    }
}
