//! InviteService gRPC implementation.

use crate::storage::facade::StorageFacade;
use dashmap::DashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

mod create;
mod list;
mod register;
mod revoke;
mod validate;

/// Per-tenant token bucket for rate limiting.
struct TenantBucket {
    /// Available tokens (capped at `capacity`).
    tokens: AtomicU32,
    /// Last refill timestamp in milliseconds.
    last_refill_ms: std::sync::atomic::AtomicI64,
}

/// Configuration for the invite service rate limiter.
#[derive(Clone, Debug)]
pub struct InviteRateLimitConfig {
    /// Maximum requests per window per tenant.
    pub capacity: u32,
    /// Window duration in milliseconds.
    pub window_ms: i64,
}

impl Default for InviteRateLimitConfig {
    fn default() -> Self {
        Self {
            capacity: 10,
            window_ms: 60_000, // 1 minute
        }
    }
}

#[derive(Clone)]
pub struct InviteServiceImpl {
    pub(crate) store: StorageFacade,
    rate_limit: InviteRateLimitConfig,
    /// Per-tenant token buckets for ValidateInviteCode and RegisterWithInviteCode.
    buckets: Arc<DashMap<crate::ids::TenantId, Arc<TenantBucket>>>,
}

impl InviteServiceImpl {
    pub fn new(store: StorageFacade) -> Self {
        Self {
            store,
            rate_limit: InviteRateLimitConfig::default(),
            buckets: Arc::new(DashMap::new()),
        }
    }

    pub fn with_rate_limit(store: StorageFacade, config: InviteRateLimitConfig) -> Self {
        Self {
            store,
            rate_limit: config,
            buckets: Arc::new(DashMap::new()),
        }
    }

    /// Check rate limit for a tenant. Returns Ok(()) if allowed, or RESOURCE_EXHAUSTED status.
    ///
    /// Note: `result_large_err` is acceptable here as `tonic::Status` is the required error type
    /// for gRPC services. Boxing would break compatibility with tonic's service API.
    #[allow(clippy::result_large_err)]
    fn check_rate_limit(&self, tenant: crate::ids::TenantId) -> Result<(), tonic::Status> {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        let bucket = self
            .buckets
            .entry(tenant)
            .or_insert_with(|| {
                Arc::new(TenantBucket {
                    tokens: AtomicU32::new(self.rate_limit.capacity),
                    last_refill_ms: std::sync::atomic::AtomicI64::new(now_ms),
                })
            })
            .clone();

        // Refill tokens if window has elapsed
        let last_refill = bucket.last_refill_ms.load(Ordering::Acquire);
        if now_ms - last_refill >= self.rate_limit.window_ms {
            // Try to claim the refill (CAS to prevent double-refill)
            if bucket
                .last_refill_ms
                .compare_exchange(last_refill, now_ms, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                bucket
                    .tokens
                    .store(self.rate_limit.capacity, Ordering::Release);
            }
        }

        // Try to consume a token
        loop {
            let current = bucket.tokens.load(Ordering::Acquire);
            if current == 0 {
                return Err(crate::rpc::RpcError::ResourceExhausted {
                    resource: "invite_validation",
                    limit: format!(
                        "{} requests per {} seconds",
                        self.rate_limit.capacity,
                        self.rate_limit.window_ms / 1000
                    ),
                }
                .into());
            }
            if bucket
                .tokens
                .compare_exchange(current, current - 1, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Ok(());
            }
        }
    }
}

use mandate_proto::mandate::v1::invite_service_server::InviteService;

#[tonic::async_trait]
impl InviteService for InviteServiceImpl {
    async fn create_invite_code(
        &self,
        request: tonic::Request<mandate_proto::mandate::v1::CreateInviteCodeRequest>,
    ) -> Result<tonic::Response<mandate_proto::mandate::v1::CreateInviteCodeResponse>, tonic::Status>
    {
        create::create_invite_code(self, request).await
    }

    async fn list_invite_codes(
        &self,
        request: tonic::Request<mandate_proto::mandate::v1::ListInviteCodesRequest>,
    ) -> Result<tonic::Response<mandate_proto::mandate::v1::ListInviteCodesResponse>, tonic::Status>
    {
        list::list_invite_codes(self, request).await
    }

    async fn validate_invite_code(
        &self,
        request: tonic::Request<mandate_proto::mandate::v1::ValidateInviteCodeRequest>,
    ) -> Result<
        tonic::Response<mandate_proto::mandate::v1::ValidateInviteCodeResponse>,
        tonic::Status,
    > {
        validate::validate_invite_code(self, request).await
    }

    async fn revoke_invite_code(
        &self,
        request: tonic::Request<mandate_proto::mandate::v1::RevokeInviteCodeRequest>,
    ) -> Result<tonic::Response<mandate_proto::mandate::v1::RevokeInviteCodeResponse>, tonic::Status>
    {
        revoke::revoke_invite_code(self, request).await
    }

    async fn register_with_invite_code(
        &self,
        request: tonic::Request<mandate_proto::mandate::v1::RegisterWithInviteCodeRequest>,
    ) -> Result<
        tonic::Response<mandate_proto::mandate::v1::RegisterWithInviteCodeResponse>,
        tonic::Status,
    > {
        register::register_with_invite_code(self, request).await
    }
}
