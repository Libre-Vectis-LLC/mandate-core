//! GroupService gRPC implementation.

use crate::ids::{GroupId, TenantId};
use crate::ring_log::RingDelta;
use crate::rpc::RpcError;
use crate::storage::facade::StorageFacade;
use mandate_proto::mandate::v1::{
    group_service_server::GroupService, CreateGroupRequest, CreateGroupResponse, GetGroupRequest,
    GetGroupResponse, SetOwnerPublicKeyRequest, SetOwnerPublicKeyResponse,
};
use nazgul::traits::LocalByteConvertible;
use tonic::{Request, Response, Status};

use super::to_status;

#[derive(Clone)]
pub struct GroupServiceImpl {
    store: StorageFacade,
}

impl GroupServiceImpl {
    pub fn new(store: StorageFacade) -> Self {
        Self { store }
    }
}

#[tonic::async_trait]
impl GroupService for GroupServiceImpl {
    async fn create_group(
        &self,
        request: Request<CreateGroupRequest>,
    ) -> Result<Response<CreateGroupResponse>, Status> {
        // Extract authenticated tenant from interceptor
        let authenticated_tenant =
            request
                .extensions()
                .get::<TenantId>()
                .cloned()
                .ok_or_else(|| RpcError::Unauthenticated {
                    credential: "tenant_context",
                    reason: "missing from request extensions".into(),
                })?;

        let body = request.into_inner();
        let requested_tenant =
            TenantId(crate::proto::parse_ulid(&body.tenant_id).map_err(|e| {
                RpcError::InvalidArgument {
                    field: "tenant_id",
                    reason: e.to_string(),
                }
            })?);

        // Authorization check: verify authenticated tenant matches requested tenant
        if authenticated_tenant != requested_tenant {
            return Err(RpcError::PermissionDenied {
                resource: "tenant",
                reason: "not authorized for requested tenant".into(),
            }
            .into());
        }

        let group_id = self
            .store
            .create_group(authenticated_tenant, &body.tg_group_id)
            .await
            .map_err(to_status)?;

        Ok(Response::new(CreateGroupResponse {
            group_id: group_id.to_string(),
        }))
    }

    async fn set_owner_public_key(
        &self,
        request: Request<SetOwnerPublicKeyRequest>,
    ) -> Result<Response<SetOwnerPublicKeyResponse>, Status> {
        // Extract authenticated tenant from interceptor
        let authenticated_tenant =
            request
                .extensions()
                .get::<TenantId>()
                .cloned()
                .ok_or_else(|| RpcError::Unauthenticated {
                    credential: "tenant_context",
                    reason: "missing from request extensions".into(),
                })?;

        let body = request.into_inner();
        let group_id = GroupId(crate::proto::parse_ulid(&body.group_id).map_err(|e| {
            RpcError::InvalidArgument {
                field: "group_id",
                reason: e.to_string(),
            }
        })?);

        let (group_tenant, _) = self.store.get_group(group_id).await.map_err(to_status)?;

        // Authorization check: verify authenticated tenant owns the group
        if authenticated_tenant != group_tenant {
            return Err(RpcError::PermissionDenied {
                resource: "group",
                reason: "not authorized for requested group".into(),
            }
            .into());
        }

        let tenant = group_tenant;

        let owner_pubkey = body
            .owner_pubkey
            .as_ref()
            .ok_or_else(|| RpcError::InvalidArgument {
                field: "owner_pubkey",
                reason: "missing".into(),
            })?;
        let owner_pubkey = crate::proto::nazgul_pub_from_proto(owner_pubkey).map_err(|e| {
            RpcError::InvalidArgument {
                field: "owner_pubkey",
                reason: e.to_string(),
            }
        })?;

        match self.store.current_ring(tenant, group_id).await {
            Ok(ring) => {
                let is_idempotent = ring.members().len() == 1
                    && ring
                        .members()
                        .iter()
                        .any(|p| p.to_bytes() == owner_pubkey.0);
                if is_idempotent {
                    return Ok(Response::new(SetOwnerPublicKeyResponse {}));
                }

                return Err(RpcError::FailedPrecondition {
                    operation: "set_owner_public_key",
                    reason: "group ring already initialized".into(),
                }
                .into());
            }
            Err(crate::storage::StorageError::NotFound(_)) => {}
            Err(err) => return Err(to_status(err)),
        }

        // Store owner pubkey in group metadata for delegate key derivation
        self.store
            .set_owner_pubkey(group_id, crate::ids::MasterPublicKey(owner_pubkey.0))
            .await
            .map_err(to_status)?;

        // Add owner pubkey to ring as first member
        self.store
            .append_ring_delta(tenant, group_id, RingDelta::Add(owner_pubkey))
            .await
            .map_err(to_status)?;

        Ok(Response::new(SetOwnerPublicKeyResponse {}))
    }

    async fn get_group(
        &self,
        request: Request<GetGroupRequest>,
    ) -> Result<Response<GetGroupResponse>, Status> {
        let body = request.into_inner();
        let group_id = GroupId(crate::proto::parse_ulid(&body.group_id).map_err(|e| {
            RpcError::InvalidArgument {
                field: "group_id",
                reason: e.to_string(),
            }
        })?);

        let (tenant_id, _tg_group_id) = self.store.get_group(group_id).await.map_err(to_status)?;
        let owner_pubkey = self
            .store
            .get_owner_pubkey(group_id)
            .await
            .map_err(to_status)?;

        Ok(Response::new(GetGroupResponse {
            group_id: group_id.to_string(),
            tenant_id: tenant_id.0.to_string(),
            owner_pubkey: owner_pubkey.map(|pk| crate::proto::master_pub_to_proto(&pk)),
        }))
    }
}
