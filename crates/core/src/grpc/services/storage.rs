//! StorageService gRPC implementation.

use crate::billing::{default_egress_meter, SharedEgressMeter};
use crate::ids::GroupId;
use crate::rpc::RpcError;
use crate::storage::facade::StorageFacade;
use mandate_proto::mandate::v1::{
    storage_service_server::StorageService, DownloadMyAccessTokenBlobRequest,
    DownloadMyAccessTokenBlobResponse, DownloadMyKeyBlobRequest, DownloadMyKeyBlobResponse,
    GetEdgeAccessTokenRequest, GetEdgeAccessTokenResponse, UploadAccessTokenBlobsRequest,
    UploadAccessTokenBlobsResponse, UploadKeyBlobsRequest, UploadKeyBlobsResponse,
};
use tonic::{Request, Response, Status};

use super::{extract_tenant_id, keyblobs_max_blob_bytes, keyblobs_max_count, to_status};

#[derive(Clone)]
pub struct StorageServiceImpl {
    store: StorageFacade,
    egress_meter: SharedEgressMeter,
}

impl StorageServiceImpl {
    /// Create a new StorageService with the default no-op egress meter.
    pub fn new(store: StorageFacade) -> Self {
        Self {
            store,
            egress_meter: default_egress_meter(),
        }
    }

    /// Create a new StorageService with a custom egress meter.
    pub fn with_egress_meter(store: StorageFacade, egress_meter: SharedEgressMeter) -> Self {
        Self {
            store,
            egress_meter,
        }
    }
}

#[tonic::async_trait]
impl StorageService for StorageServiceImpl {
    async fn upload_key_blobs(
        &self,
        request: Request<UploadKeyBlobsRequest>,
    ) -> Result<Response<UploadKeyBlobsResponse>, Status> {
        let tenant = extract_tenant_id(&request, &self.store).await?;
        let body = request.into_inner();
        let group_id = GroupId(crate::proto::parse_ulid(&body.group_id).map_err(|e| {
            RpcError::InvalidArgument {
                field: "group_id",
                reason: e.to_string(),
            }
        })?);

        if body.blobs.len() > keyblobs_max_count() {
            return Err(RpcError::InvalidArgument {
                field: "blobs",
                reason: format!("too many ({} > {})", body.blobs.len(), keyblobs_max_count()),
            }
            .into());
        }
        let max_blob_bytes = keyblobs_max_blob_bytes();
        if body.blobs.iter().any(|b| b.blob.len() > max_blob_bytes) {
            return Err(RpcError::InvalidArgument {
                field: "blobs",
                reason: format!("blob too large (max {} bytes)", max_blob_bytes),
            }
            .into());
        }

        let mut entries = Vec::with_capacity(body.blobs.len());
        for blob in body.blobs {
            let rage_pub = blob
                .rage_pub
                .as_ref()
                .ok_or_else(|| RpcError::InvalidArgument {
                    field: "rage_pub",
                    reason: "missing in blob entry".into(),
                })?;
            let rage_pub = crate::proto::rage_pub_from_proto(rage_pub).map_err(|e| {
                RpcError::InvalidArgument {
                    field: "rage_pub",
                    reason: e.to_string(),
                }
            })?;
            entries.push((rage_pub, blob.blob.into()));
        }

        self.store
            .put_key_blobs(tenant, group_id, entries)
            .await
            .map_err(to_status)?;
        Ok(Response::new(UploadKeyBlobsResponse {}))
    }

    async fn download_my_key_blob(
        &self,
        request: Request<DownloadMyKeyBlobRequest>,
    ) -> Result<Response<DownloadMyKeyBlobResponse>, Status> {
        let tenant = extract_tenant_id(&request, &self.store).await?;
        let body = request.into_inner();
        let group_id = GroupId(crate::proto::parse_ulid(&body.group_id).map_err(|e| {
            RpcError::InvalidArgument {
                field: "group_id",
                reason: e.to_string(),
            }
        })?);
        let rage_pub = body
            .rage_pub
            .as_ref()
            .ok_or_else(|| RpcError::InvalidArgument {
                field: "rage_pub",
                reason: "missing".into(),
            })?;
        let rage_pub =
            crate::proto::rage_pub_from_proto(rage_pub).map_err(|e| RpcError::InvalidArgument {
                field: "rage_pub",
                reason: e.to_string(),
            })?;

        let blob = self
            .store
            .get_key_blob(tenant, group_id, rage_pub)
            .await
            .map_err(to_status)?;

        // Calculate egress bytes for billing
        let total_bytes = blob.len();
        let group_id_str = group_id.to_string();

        // Check egress balance before sending data
        self.egress_meter
            .check_egress(&group_id_str, total_bytes)
            .await
            .map_err(|e| Status::resource_exhausted(format!("egress check failed: {}", e)))?;

        // Record egress after preparing response
        let _ = self
            .egress_meter
            .record_egress(&group_id_str, total_bytes)
            .await;

        Ok(Response::new(DownloadMyKeyBlobResponse {
            blob: blob.to_vec(),
        }))
    }

    async fn upload_access_token_blobs(
        &self,
        request: Request<UploadAccessTokenBlobsRequest>,
    ) -> Result<Response<UploadAccessTokenBlobsResponse>, Status> {
        let tenant = extract_tenant_id(&request, &self.store).await?;
        let body = request.into_inner();
        let group_id = GroupId(crate::proto::parse_ulid(&body.group_id).map_err(|e| {
            RpcError::InvalidArgument {
                field: "group_id",
                reason: e.to_string(),
            }
        })?);

        if body.blobs.len() > keyblobs_max_count() {
            return Err(RpcError::InvalidArgument {
                field: "blobs",
                reason: format!("too many ({} > {})", body.blobs.len(), keyblobs_max_count()),
            }
            .into());
        }
        let max_blob_bytes = keyblobs_max_blob_bytes();
        if body
            .blobs
            .iter()
            .any(|b| b.encrypted_token.len() > max_blob_bytes)
        {
            return Err(RpcError::InvalidArgument {
                field: "blobs",
                reason: format!("blob too large (max {} bytes)", max_blob_bytes),
            }
            .into());
        }

        let mut entries = Vec::with_capacity(body.blobs.len());
        for blob in body.blobs {
            let rage_pub = blob
                .rage_pub
                .as_ref()
                .ok_or_else(|| RpcError::InvalidArgument {
                    field: "rage_pub",
                    reason: "missing in blob entry".into(),
                })?;
            let rage_pub = crate::proto::rage_pub_from_proto(rage_pub).map_err(|e| {
                RpcError::InvalidArgument {
                    field: "rage_pub",
                    reason: e.to_string(),
                }
            })?;
            entries.push((rage_pub, blob.encrypted_token.into()));
        }

        // ring_hash is not passed in this RPC — the server determines it internally.
        // Use a zero hash as placeholder; the storage layer records the current ring_hash.
        let ring_hash = [0u8; 32];

        self.store
            .put_access_token_blobs(tenant, group_id, ring_hash, entries)
            .await
            .map_err(to_status)?;
        Ok(Response::new(UploadAccessTokenBlobsResponse {}))
    }

    async fn download_my_access_token_blob(
        &self,
        request: Request<DownloadMyAccessTokenBlobRequest>,
    ) -> Result<Response<DownloadMyAccessTokenBlobResponse>, Status> {
        let tenant = extract_tenant_id(&request, &self.store).await?;
        let body = request.into_inner();
        let group_id = GroupId(crate::proto::parse_ulid(&body.group_id).map_err(|e| {
            RpcError::InvalidArgument {
                field: "group_id",
                reason: e.to_string(),
            }
        })?);
        let rage_pub = body
            .rage_pub
            .as_ref()
            .ok_or_else(|| RpcError::InvalidArgument {
                field: "rage_pub",
                reason: "missing".into(),
            })?;
        let rage_pub =
            crate::proto::rage_pub_from_proto(rage_pub).map_err(|e| RpcError::InvalidArgument {
                field: "rage_pub",
                reason: e.to_string(),
            })?;

        let blob = self
            .store
            .get_access_token_blob(tenant, group_id, rage_pub)
            .await
            .map_err(to_status)?;

        Ok(Response::new(DownloadMyAccessTokenBlobResponse {
            encrypted_token: blob.to_vec(),
        }))
    }

    async fn get_edge_access_token(
        &self,
        request: Request<GetEdgeAccessTokenRequest>,
    ) -> Result<Response<GetEdgeAccessTokenResponse>, Status> {
        let tenant = extract_tenant_id(&request, &self.store).await?;
        let body = request.into_inner();
        let group_id = GroupId(crate::proto::parse_ulid(&body.group_id).map_err(|e| {
            RpcError::InvalidArgument {
                field: "group_id",
                reason: e.to_string(),
            }
        })?);

        let (current, previous, rotated_at_ms) = self
            .store
            .get_edge_access_token(tenant, group_id)
            .await
            .map_err(to_status)?;

        Ok(Response::new(GetEdgeAccessTokenResponse {
            current_token: current.to_vec(),
            previous_token: previous.map(|t| t.to_vec()).unwrap_or_default(),
            rotated_at_ms,
        }))
    }
}
