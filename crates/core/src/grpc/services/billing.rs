//! BillingService gRPC implementation.

use crate::ids::{GroupId, Nanos, TenantId};
use crate::rpc::RpcError;
use crate::storage::facade::StorageFacade;
use crate::storage::{IdempotencyErrorCode, IdempotencyResult};
use mandate_proto::mandate::v1::{
    billing_service_server::BillingService, GetGroupBalanceRequest, GetGroupBalanceResponse,
    GetTenantBalanceRequest, GetTenantBalanceResponse, TransferBetweenGroupsRequest,
    TransferBetweenGroupsResponse, TransferToGroupRequest, TransferToGroupResponse,
    WithdrawFromGroupRequest, WithdrawFromGroupResponse,
};
use tonic::{Code, Request, Response, Status};

use super::to_status;

/// Default time-to-live for idempotency keys in seconds (24 hours).
const IDEMPOTENCY_TTL_SECS: u64 = 86400;

/// Convert an idempotency error code back to a tonic status code.
fn from_idempotency_error_code(code: IdempotencyErrorCode) -> Code {
    match code {
        IdempotencyErrorCode::InvalidArgument => Code::InvalidArgument,
        IdempotencyErrorCode::FailedPrecondition => Code::FailedPrecondition,
        IdempotencyErrorCode::NotFound => Code::NotFound,
        IdempotencyErrorCode::AlreadyExists => Code::AlreadyExists,
        IdempotencyErrorCode::PermissionDenied => Code::PermissionDenied,
        IdempotencyErrorCode::ResourceExhausted => Code::ResourceExhausted,
        IdempotencyErrorCode::Cancelled => Code::Cancelled,
        IdempotencyErrorCode::Aborted => Code::Aborted,
        IdempotencyErrorCode::DeadlineExceeded => Code::DeadlineExceeded,
        IdempotencyErrorCode::Internal => Code::Internal,
        IdempotencyErrorCode::Unavailable => Code::Unavailable,
        IdempotencyErrorCode::DataLoss => Code::DataLoss,
        IdempotencyErrorCode::Unauthenticated => Code::Unauthenticated,
        IdempotencyErrorCode::Unimplemented => Code::Unimplemented,
        IdempotencyErrorCode::Unknown => Code::Unknown,
    }
}

/// Map a storage error reference to idempotency error code (without consuming it).
fn storage_error_to_idempotency(err: &crate::storage::StorageError) -> IdempotencyErrorCode {
    use crate::storage::StorageError;
    match err {
        StorageError::NotFound(_) => IdempotencyErrorCode::NotFound,
        StorageError::AlreadyExists => IdempotencyErrorCode::AlreadyExists,
        StorageError::PreconditionFailed(_) => IdempotencyErrorCode::FailedPrecondition,
        StorageError::Backend(_) => IdempotencyErrorCode::Internal,
    }
}

fn ensure_payments_enabled() -> Result<(), Status> {
    if cfg!(feature = "payments") {
        Ok(())
    } else {
        Err(Status::unimplemented(
            "payment features are disabled; rebuild with --features payments",
        ))
    }
}

#[derive(Clone)]
pub struct BillingServiceImpl {
    store: StorageFacade,
}

impl BillingServiceImpl {
    pub fn new(store: StorageFacade) -> Self {
        Self { store }
    }
}

#[tonic::async_trait]
impl BillingService for BillingServiceImpl {
    /// Transfer credits from tenant wallet to group wallet.
    ///
    /// # Authentication
    ///
    /// Requires `x-tenant-id` header in request metadata. The tenant ID is obtained
    /// from the authenticated context (injected by `make_bot_secret_interceptor`),
    /// NOT from the request body.
    ///
    /// This prevents a compromised Bot from transferring funds from arbitrary tenants.
    /// The Bot must explicitly authenticate as the tenant it intends to act for.
    async fn transfer_to_group(
        &self,
        request: Request<TransferToGroupRequest>,
    ) -> Result<Response<TransferToGroupResponse>, Status> {
        ensure_payments_enabled()?;
        // Extract tenant_id from authenticated context (set by interceptor from x-tenant-id header).
        // This is a defense-in-depth measure: even if Bot is compromised, it can only
        // transfer from the tenant it authenticated as, not arbitrary tenants.
        let tenant_id = request
            .extensions()
            .get::<TenantId>()
            .cloned()
            .ok_or_else(|| RpcError::Unauthenticated {
                credential: "tenant_id",
                reason: "missing x-tenant-id header".into(),
            })?;

        let body = request.into_inner();

        // Extract optional idempotency key
        let idempotency_key = body.idempotency_key.filter(|k| !k.is_empty());

        // If idempotency key is provided, check for existing result
        if let Some(ref key) = idempotency_key {
            match self.store.check_idempotency_key(key).await {
                Ok(Some(IdempotencyResult::Success { balance_nanos })) => {
                    // Replay successful result
                    let balance_i64 =
                        i64::try_from(balance_nanos).map_err(|_| RpcError::Internal {
                            operation: "transfer_to_group",
                            details: "cached balance exceeds i64::MAX".into(),
                        })?;
                    return Ok(Response::new(TransferToGroupResponse {
                        balance_after_nanos: balance_i64,
                    }));
                }
                Ok(Some(IdempotencyResult::Error { code, message })) => {
                    // Replay error result
                    return Err(Status::new(from_idempotency_error_code(code), message));
                }
                Ok(None) => {
                    // Key not found, proceed with operation
                }
                Err(_) => {
                    // Backend error checking idempotency key - proceed without idempotency
                    // to avoid blocking operations. Logging is handled at the storage layer.
                }
            }
        }

        // Parse and validate request parameters
        // Note: body.tenant_id is ignored - we use the authenticated tenant_id from context
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

        // Execute the transfer
        let result = self
            .store
            .transfer_to_group(tenant_id, group_id, Nanos::new(amount))
            .await;

        // Record result if idempotency key was provided
        if let Some(ref key) = idempotency_key {
            let idempotency_result = match &result {
                Ok(balance) => IdempotencyResult::Success {
                    balance_nanos: balance.as_u64(),
                },
                Err(e) => IdempotencyResult::Error {
                    code: storage_error_to_idempotency(e),
                    message: e.to_string(),
                },
            };

            // Record result - ignore errors (best effort)
            // Logging is handled at the storage layer.
            let _ = self
                .store
                .record_idempotency_result(key, idempotency_result, IDEMPOTENCY_TTL_SECS)
                .await;
        }

        // Return result
        let balance = result.map_err(to_status)?;
        let balance_i64 = balance.try_as_i64().ok_or_else(|| RpcError::Internal {
            operation: "transfer_to_group",
            details: "balance exceeds i64::MAX".into(),
        })?;
        Ok(Response::new(TransferToGroupResponse {
            balance_after_nanos: balance_i64,
        }))
    }

    async fn get_group_balance(
        &self,
        request: Request<GetGroupBalanceRequest>,
    ) -> Result<Response<GetGroupBalanceResponse>, Status> {
        ensure_payments_enabled()?;
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
        let balance_i64 = balance.try_as_i64().ok_or_else(|| RpcError::Internal {
            operation: "get_group_balance",
            details: "balance exceeds i64::MAX".into(),
        })?;
        Ok(Response::new(GetGroupBalanceResponse {
            balance_nanos: balance_i64,
        }))
    }

    async fn get_tenant_balance(
        &self,
        request: Request<GetTenantBalanceRequest>,
    ) -> Result<Response<GetTenantBalanceResponse>, Status> {
        ensure_payments_enabled()?;
        // Extract tenant_id from authenticated context (set by interceptor from x-api-token header).
        // The request body is empty - tenant is identified by the API token.
        let tenant_id = request
            .extensions()
            .get::<TenantId>()
            .cloned()
            .ok_or_else(|| RpcError::Unauthenticated {
                credential: "tenant_id",
                reason: "missing x-api-token header".into(),
            })?;

        let balance_info = self
            .store
            .get_tenant_balance(tenant_id)
            .await
            .map_err(to_status)?;
        let balance_i64 = balance_info
            .balance
            .try_as_i64()
            .ok_or_else(|| RpcError::Internal {
                operation: "get_tenant_balance",
                details: "balance exceeds i64::MAX".into(),
            })?;
        let updated_at_u64 = u64::try_from(balance_info.updated_at_ms).unwrap_or(0);
        Ok(Response::new(GetTenantBalanceResponse {
            balance_nanos: balance_i64,
            updated_at: updated_at_u64,
        }))
    }

    async fn withdraw_from_group(
        &self,
        request: Request<WithdrawFromGroupRequest>,
    ) -> Result<Response<WithdrawFromGroupResponse>, Status> {
        ensure_payments_enabled()?;
        // Extract tenant_id from authenticated context (set by interceptor from x-tenant-id header).
        let tenant_id = request
            .extensions()
            .get::<TenantId>()
            .cloned()
            .ok_or_else(|| RpcError::Unauthenticated {
                credential: "tenant_id",
                reason: "missing x-tenant-id header".into(),
            })?;

        let body = request.into_inner();

        // Parse and validate request parameters
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

        // Execute the withdrawal
        let _tenant_balance = self
            .store
            .withdraw_from_group(tenant_id, group_id, Nanos::new(amount))
            .await
            .map_err(to_status)?;

        // Generate transfer ID and timestamp
        let transfer_id = ulid::Ulid::new().to_string();
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Ok(Response::new(WithdrawFromGroupResponse {
            transfer_id,
            amount_nanos: body.amount_nanos,
            timestamp,
        }))
    }

    async fn transfer_between_groups(
        &self,
        request: Request<TransferBetweenGroupsRequest>,
    ) -> Result<Response<TransferBetweenGroupsResponse>, Status> {
        ensure_payments_enabled()?;
        // Extract tenant_id from authenticated context (set by interceptor from x-tenant-id header).
        let tenant_id = request
            .extensions()
            .get::<TenantId>()
            .cloned()
            .ok_or_else(|| RpcError::Unauthenticated {
                credential: "tenant_id",
                reason: "missing x-tenant-id header".into(),
            })?;

        let body = request.into_inner();

        // Parse and validate request parameters
        let source_group_id =
            GroupId(crate::proto::parse_ulid(&body.from_group_id).map_err(|e| {
                RpcError::InvalidArgument {
                    field: "from_group_id",
                    reason: e.to_string(),
                }
            })?);
        let dest_group_id = GroupId(crate::proto::parse_ulid(&body.to_group_id).map_err(|e| {
            RpcError::InvalidArgument {
                field: "to_group_id",
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

        // Execute the transfer
        let (_source_balance, _dest_balance) = self
            .store
            .transfer_between_groups(
                tenant_id,
                source_group_id,
                dest_group_id,
                Nanos::new(amount),
            )
            .await
            .map_err(to_status)?;

        // Generate transfer ID and timestamp
        let transfer_id = ulid::Ulid::new().to_string();
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Ok(Response::new(TransferBetweenGroupsResponse {
            transfer_id,
            amount_nanos: body.amount_nanos,
            timestamp,
        }))
    }
}
