//! gRPC service implementations, each in its own module.

mod admin;
mod auth;
mod billing;
mod event;
mod member;
mod organization;
mod ring;
mod storage;

pub use admin::AdminServiceImpl;
pub use auth::AuthServiceImpl;
pub use billing::BillingServiceImpl;
pub use event::EventServiceImpl;
pub use member::MemberServiceImpl;
pub use organization::OrganizationServiceImpl;
pub use ring::RingServiceImpl;
pub use storage::StorageServiceImpl;

use crate::rpc::RpcError;
use crate::storage::facade::StorageFacade;
use crate::storage::TenantTokenError;
use tonic::{Request, Status};

// ─────────────────────────────────────────────────────────────────────────────
// Shared helpers
// ─────────────────────────────────────────────────────────────────────────────

pub(crate) fn clamp_limit(client_limit: u32, default_limit: usize, max_limit: usize) -> usize {
    let requested = if client_limit == 0 {
        default_limit
    } else {
        client_limit as usize
    };
    requested.clamp(1, max_limit)
}

pub(crate) fn env_usize(key: &str, default: usize) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(default)
}

pub(crate) fn max_event_bytes() -> usize {
    env_usize("MANDATE_GRPC_MAX_EVENT_BYTES", 1024 * 1024)
}

pub(crate) fn keyblobs_max_count() -> usize {
    env_usize("MANDATE_GRPC_KEYBLOBS_MAX_COUNT", 1024)
}

pub(crate) fn keyblobs_max_blob_bytes() -> usize {
    env_usize("MANDATE_GRPC_KEYBLOBS_MAX_BLOB_BYTES", 64 * 1024)
}

/// Maximum allowed length for poll_id and question_id fields (256 bytes).
pub(crate) fn max_poll_id_length() -> usize {
    env_usize("MANDATE_GRPC_MAX_POLL_ID_LENGTH", 256)
}

/// Maximum allowed length for message content in UTF-8 characters (default: 3000).
///
/// This prevents resource exhaustion from extremely large messages and ensures
/// reasonable display sizes across clients.
pub(crate) fn max_message_content_chars() -> usize {
    env_usize("MANDATE_GRPC_MAX_MESSAGE_CONTENT_CHARS", 3000)
}

pub(crate) fn clamp_events_limit(client_limit: u32) -> usize {
    let max_limit = env_usize("MANDATE_GRPC_EVENTS_MAX_LIMIT", 100);
    let default_limit = env_usize("MANDATE_GRPC_EVENTS_DEFAULT_LIMIT", 50).min(max_limit);
    clamp_limit(client_limit, default_limit, max_limit)
}

pub(crate) fn clamp_ring_limit(client_limit: u32) -> usize {
    let max_limit = env_usize("MANDATE_GRPC_RING_MAX_LIMIT", 100);
    let default_limit = env_usize("MANDATE_GRPC_RING_DEFAULT_LIMIT", 50).min(max_limit);
    clamp_limit(client_limit, default_limit, max_limit)
}

pub(crate) fn to_status(err: crate::storage::StorageError) -> Status {
    match err {
        crate::storage::StorageError::NotFound(not_found) => {
            // Never return internal debug identifiers (tenant/org/key bytes) to callers.
            // Keep user-facing errors stable and non-enumerable.
            let (resource, id) = match not_found {
                crate::storage::NotFound::Event { .. } => ("event", "not found"),
                crate::storage::NotFound::Tenant { .. } => ("tenant", "not found"),
                crate::storage::NotFound::Organization { .. } => ("organization", "not found"),
                crate::storage::NotFound::Tail { .. } => ("event_tail", "not found"),
                crate::storage::NotFound::Ring { .. } => ("ring", "not found"),
                crate::storage::NotFound::RingDeltaPath { .. } => ("ring_delta_path", "not found"),
                crate::storage::NotFound::KeyBlob { .. } => ("key_blob", "not found"),
                crate::storage::NotFound::GiftCard { .. } => ("gift_card", "not found"),
                crate::storage::NotFound::InviteCode { .. } => ("invite_code", "not found"),
                crate::storage::NotFound::AccessTokenBlob { .. } => {
                    ("access_token_blob", "not found")
                }
                crate::storage::NotFound::EdgeAccessToken { .. } => {
                    ("edge_access_token", "not found")
                }
            };
            RpcError::NotFound {
                resource,
                id: id.into(),
            }
            .into()
        }
        crate::storage::StorageError::Backend(msg) => RpcError::Internal {
            operation: "storage_backend",
            details: msg,
        }
        .into(),
        crate::storage::StorageError::AlreadyExists => RpcError::AlreadyExists {
            resource: "storage_item",
            id: "duplicate".into(),
        }
        .into(),
        crate::storage::StorageError::PreconditionFailed(msg) => RpcError::FailedPrecondition {
            operation: "storage_operation",
            reason: msg,
        }
        .into(),
    }
}

/// Extract tenant token from request extensions or metadata.
///
/// Note: `result_large_err` is acceptable here as `tonic::Status` is the required error type
/// for gRPC services. Boxing would break compatibility with tonic's service API.
#[allow(clippy::result_large_err)]
pub(crate) fn extract_tenant_token<T>(req: &Request<T>) -> Result<crate::ids::TenantToken, Status> {
    if let Some(token) = req.extensions().get::<crate::ids::TenantToken>() {
        return Ok(token.clone());
    }

    let token = req
        .metadata()
        .get(crate::proto::API_TOKEN_METADATA_KEY)
        .ok_or_else(|| RpcError::Unauthenticated {
            credential: "api_token",
            reason: "missing".into(),
        })?
        .to_str()
        .map_err(|_| RpcError::Unauthenticated {
            credential: "api_token",
            reason: "bad encoding".into(),
        })?;

    if token.is_empty() {
        return Err(RpcError::Unauthenticated {
            credential: "api_token",
            reason: "empty".into(),
        }
        .into());
    }

    Ok(crate::ids::TenantToken::from(token))
}

fn to_status_token(err: TenantTokenError) -> Status {
    match err {
        TenantTokenError::Unknown => RpcError::Unauthenticated {
            credential: "api_token",
            reason: "unknown token".into(),
        }
        .into(),
        TenantTokenError::Backend(msg) => RpcError::Unavailable {
            service: "token_validation",
            reason: msg,
        }
        .into(),
    }
}

/// Extract and validate tenant ID from request token.
///
/// Note: `result_large_err` is acceptable here as `tonic::Status` is the required error type
/// for gRPC services. Boxing would break compatibility with tonic's service API.
#[allow(clippy::result_large_err)]
pub(crate) async fn extract_tenant_id<T>(
    req: &Request<T>,
    store: &StorageFacade,
) -> Result<crate::ids::TenantId, Status> {
    if let Some(tenant) = req.extensions().get::<crate::ids::TenantId>() {
        return Ok(*tenant);
    }

    let token = extract_tenant_token(req)?;
    let tenant_id: crate::ids::TenantId = store
        .resolve_tenant(&token)
        .await
        .map_err(to_status_token)?;
    Ok(tenant_id)
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests;
