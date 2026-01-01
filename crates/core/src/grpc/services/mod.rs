//! gRPC service implementations, each in its own module.

mod admin;
mod auth;
mod billing;
mod event;
mod group;
mod member;
mod ring;
mod storage;

pub use admin::AdminServiceImpl;
pub use auth::AuthServiceImpl;
pub use billing::BillingServiceImpl;
pub use event::EventServiceImpl;
pub use group::GroupServiceImpl;
pub use member::MemberServiceImpl;
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
        crate::storage::StorageError::NotFound(not_found) => RpcError::NotFound {
            resource: "storage_item",
            id: not_found.to_string(),
        }
        .into(),
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
mod tests {
    use super::*;
    use crate::grpc::wiring::CoreServices;
    use crate::ids::TenantId;
    use mandate_proto::mandate::v1::event_service_server::EventService;
    use mandate_proto::mandate::v1::storage_service_server::StorageService;
    use mandate_proto::mandate::v1::{
        KeyBlob, PushEventRequest, RagePublicKey, UploadKeyBlobsRequest,
    };
    use tonic::Code;

    #[tokio::test]
    async fn push_event_rejects_oversized_event_bytes() {
        let services = CoreServices::new_in_memory().expect("in-memory services");
        let tenant = TenantId(ulid::Ulid::new());

        let mut req = Request::new(PushEventRequest {
            event_bytes: vec![0u8; max_event_bytes() + 1],
        });
        req.extensions_mut().insert(tenant);

        let err = services.event.push_event(req).await.expect_err("reject");
        assert_eq!(err.code(), Code::InvalidArgument);
    }

    #[tokio::test]
    async fn upload_key_blobs_rejects_oversized_blob() {
        let services = CoreServices::new_in_memory().expect("in-memory services");
        let tenant = TenantId(ulid::Ulid::new());
        let group_id = ulid::Ulid::new().to_string();

        let mut req = Request::new(UploadKeyBlobsRequest {
            group_id,
            blobs: vec![KeyBlob {
                rage_pub: Some(RagePublicKey {
                    value: vec![7u8; 32],
                }),
                blob: vec![0u8; keyblobs_max_blob_bytes() + 1],
            }],
        });
        req.extensions_mut().insert(tenant);

        let err = services
            .storage
            .upload_key_blobs(req)
            .await
            .expect_err("reject");
        assert_eq!(err.code(), Code::InvalidArgument);
    }

    #[tokio::test]
    async fn upload_key_blobs_rejects_too_many_entries() {
        let services = CoreServices::new_in_memory().expect("in-memory services");
        let tenant = TenantId(ulid::Ulid::new());
        let group_id = ulid::Ulid::new().to_string();

        let blobs = (0..(keyblobs_max_count() + 1))
            .map(|_| KeyBlob {
                rage_pub: Some(RagePublicKey {
                    value: vec![7u8; 32],
                }),
                blob: vec![0u8; 1],
            })
            .collect();

        let mut req = Request::new(UploadKeyBlobsRequest { group_id, blobs });
        req.extensions_mut().insert(tenant);

        let err = services
            .storage
            .upload_key_blobs(req)
            .await
            .expect_err("reject");
        assert_eq!(err.code(), Code::InvalidArgument);
    }

    #[tokio::test]
    async fn push_event_rejects_oversized_poll_id() {
        use crate::crypto::ciphertext::Ciphertext;
        use crate::event::{Event, EventType, Poll, PollQuestion, PollQuestionKind};
        use crate::ids::{EventId, EventUlid, GroupId, RingHash, Ulid};

        let services = CoreServices::new_in_memory().expect("in-memory services");
        let tenant = TenantId(ulid::Ulid::new());

        // Create a poll event with an oversized poll_id
        let oversized_poll_id = "x".repeat(max_poll_id_length() + 1);
        let poll = Poll {
            group_id: GroupId(Ulid::new()),
            ring_hash: RingHash([0u8; 32]),
            poll_id: oversized_poll_id,
            questions: vec![PollQuestion {
                question_id: "q1".into(),
                title: Ciphertext(b"test".to_vec()),
                kind: PollQuestionKind::FillInTheBlank,
            }],
            created_at: 123,
            instructions: None,
        };

        let event = Event {
            event_ulid: EventUlid(Ulid::new()),
            previous_event_hash: EventId([0u8; 32]),
            group_id: poll.group_id,
            sequence_no: None,
            processed_at: 123,
            serialization_version: 1,
            event_type: EventType::PollCreate(poll),
            signature: None,
        };

        let event_bytes = serde_json::to_vec(&event).expect("serialize");
        let mut req = Request::new(PushEventRequest { event_bytes });
        req.extensions_mut().insert(tenant);

        let err = services.event.push_event(req).await.expect_err("reject");
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("poll_id"));
    }
}
