//! BillingService gRPC implementation.

use crate::ids::{GroupId, Nanos, TenantId};
use crate::rpc::RpcError;
use crate::storage::facade::StorageFacade;
use mandate_proto::mandate::v1::{
    billing_service_server::BillingService, GetGroupBalanceRequest, GetGroupBalanceResponse,
    TransferToGroupRequest, TransferToGroupResponse,
};
use tonic::{Request, Response, Status};

use super::to_status;

#[derive(Clone)]
pub struct BillingServiceImpl {
    #[allow(dead_code)]
    store: StorageFacade,
}

impl BillingServiceImpl {
    pub fn new(store: StorageFacade) -> Self {
        Self { store }
    }
}

#[tonic::async_trait]
impl BillingService for BillingServiceImpl {
    async fn transfer_to_group(
        &self,
        request: Request<TransferToGroupRequest>,
    ) -> Result<Response<TransferToGroupResponse>, Status> {
        let body = request.into_inner();
        let tenant_id = TenantId(crate::proto::parse_ulid(&body.tenant_id).map_err(|e| {
            RpcError::InvalidArgument {
                field: "tenant_id",
                reason: e.to_string(),
            }
        })?);
        let group_id = GroupId(crate::proto::parse_ulid(&body.group_id).map_err(|e| {
            RpcError::InvalidArgument {
                field: "group_id",
                reason: e.to_string(),
            }
        })?);
        if body.amount_nanos <= 0 {
            return Err(RpcError::InvalidArgument {
                field: "amount_nanos",
                reason: "must be positive".into(),
            }
            .into());
        }
        let amount = u64::try_from(body.amount_nanos).map_err(|_| RpcError::InvalidArgument {
            field: "amount_nanos",
            reason: "too large for u64".into(),
        })?;
        let balance = self
            .store
            .transfer_to_group(tenant_id, group_id, Nanos::new(amount))
            .await
            .map_err(to_status)?;
        Ok(Response::new(TransferToGroupResponse {
            balance_after_nanos: balance.as_u64() as i64,
        }))
    }

    async fn get_group_balance(
        &self,
        request: Request<GetGroupBalanceRequest>,
    ) -> Result<Response<GetGroupBalanceResponse>, Status> {
        let body = request.into_inner();
        let group_id = GroupId(crate::proto::parse_ulid(&body.group_id).map_err(|e| {
            RpcError::InvalidArgument {
                field: "group_id",
                reason: e.to_string(),
            }
        })?);
        let balance = self
            .store
            .get_group_balance(group_id)
            .await
            .map_err(to_status)?;
        Ok(Response::new(GetGroupBalanceResponse {
            balance_nanos: balance.as_u64() as i64,
        }))
    }
}
