//! OrganizationService gRPC implementation.

use crate::ids::{OrganizationId, TenantId};
use crate::ring_log::RingDelta;
use crate::rpc::RpcError;
use crate::storage::facade::StorageFacade;
use mandate_proto::mandate::v1::{
    organization_service_server::OrganizationService, CreateOrganizationRequest,
    CreateOrganizationResponse, GetOrganizationRequest, GetOrganizationResponse,
    SetOwnerPublicKeyRequest, SetOwnerPublicKeyResponse,
};
use nazgul::traits::LocalByteConvertible;
use tonic::{Request, Response, Status};

use super::to_status;

#[derive(Clone)]
pub struct OrganizationServiceImpl {
    store: StorageFacade,
}

impl OrganizationServiceImpl {
    pub fn new(store: StorageFacade) -> Self {
        Self { store }
    }
}

#[tonic::async_trait]
impl OrganizationService for OrganizationServiceImpl {
    async fn create_organization(
        &self,
        request: Request<CreateOrganizationRequest>,
    ) -> Result<Response<CreateOrganizationResponse>, Status> {
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

        let org_id = self
            .store
            .create_organization(authenticated_tenant, &body.tg_group_id)
            .await
            .map_err(to_status)?;

        Ok(Response::new(CreateOrganizationResponse {
            org_id: org_id.to_string(),
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
        let org_id = OrganizationId(crate::proto::parse_ulid(&body.org_id).map_err(|e| {
            RpcError::InvalidArgument {
                field: "org_id",
                reason: e.to_string(),
            }
        })?);

        let (org_tenant, _) = self
            .store
            .get_organization(org_id)
            .await
            .map_err(to_status)?;

        // Authorization check: verify authenticated tenant owns the org
        if authenticated_tenant != org_tenant {
            return Err(RpcError::PermissionDenied {
                resource: "organization",
                reason: "not authorized for requested organization".into(),
            }
            .into());
        }

        let tenant = org_tenant;

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

        match self.store.current_ring(tenant, org_id).await {
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
                    reason: "organization ring already initialized".into(),
                }
                .into());
            }
            Err(crate::storage::StorageError::NotFound(_)) => {}
            Err(err) => return Err(to_status(err)),
        }

        // Store owner pubkey in org metadata for delegate key derivation
        self.store
            .set_owner_pubkey(org_id, crate::ids::MasterPublicKey(owner_pubkey.0))
            .await
            .map_err(to_status)?;

        // Add owner pubkey to ring as first member
        self.store
            .append_ring_delta(tenant, org_id, RingDelta::Add(owner_pubkey))
            .await
            .map_err(to_status)?;

        Ok(Response::new(SetOwnerPublicKeyResponse {}))
    }

    async fn get_organization(
        &self,
        request: Request<GetOrganizationRequest>,
    ) -> Result<Response<GetOrganizationResponse>, Status> {
        let body = request.into_inner();
        let org_id = OrganizationId(crate::proto::parse_ulid(&body.org_id).map_err(|e| {
            RpcError::InvalidArgument {
                field: "org_id",
                reason: e.to_string(),
            }
        })?);

        let (tenant_id, _tg_group_id) = self
            .store
            .get_organization(org_id)
            .await
            .map_err(to_status)?;
        let owner_pubkey = self
            .store
            .get_owner_pubkey(org_id)
            .await
            .map_err(to_status)?;

        Ok(Response::new(GetOrganizationResponse {
            org_id: org_id.to_string(),
            tenant_id: tenant_id.0.to_string(),
            owner_pubkey: owner_pubkey.map(|pk| crate::proto::master_pub_to_proto(&pk)),
        }))
    }
}
