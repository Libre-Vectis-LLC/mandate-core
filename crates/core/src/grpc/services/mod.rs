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
mod tests {
    use super::*;
    use crate::grpc::wiring::CoreServices;
    use crate::ids::{OrganizationId, TenantId};
    use mandate_proto::mandate::v1::event_service_server::EventService;
    use mandate_proto::mandate::v1::organization_service_server::OrganizationService;
    use mandate_proto::mandate::v1::storage_service_server::StorageService;
    use mandate_proto::mandate::v1::{
        CreateOrganizationRequest, KeyBlob, PushEventRequest, RagePublicKey, UploadKeyBlobsRequest,
    };

    /// Create an organization owned by the given tenant for tests that need BOLA checks.
    async fn create_test_org(services: &CoreServices, tenant: TenantId) -> OrganizationId {
        let mut req = Request::new(CreateOrganizationRequest {
            tenant_id: tenant.0.to_string(),
            tg_group_id: "test-group".to_string(),
        });
        req.extensions_mut().insert(tenant);
        let resp = services
            .organization
            .create_organization(req)
            .await
            .expect("create test org");
        OrganizationId(ulid::Ulid::from_string(&resp.into_inner().org_id).expect("parse org_id"))
    }
    use crate::crypto::ciphertext::Ciphertext;
    use crate::crypto::signature::{sign_contextual, SignatureKind, StorageMode};
    use crate::event::{
        AnonymousMessage, Event, EventType, Poll, PollQuestion, PollQuestionKind, Vote,
        VoteSelection,
    };
    use crate::hashing::ring_hash_sha3_256;
    use crate::ids::{EventId, EventUlid, Ulid};
    use nazgul::keypair::KeyPair;
    use nazgul::ring::Ring;
    use rand::rngs::OsRng;
    use tonic::Code;

    fn make_signing_ring(size: usize) -> (KeyPair, Ring) {
        let mut csprng = OsRng;
        let signer = KeyPair::generate(&mut csprng);
        let mut members: Vec<_> = (0..size - 1)
            .map(|_| *KeyPair::generate(&mut csprng).public())
            .collect();
        members.push(*signer.public());
        (signer, Ring::new(members))
    }

    fn sign_event_archival(event: &mut Event, signer: &KeyPair, ring: &Ring) {
        let signing_bytes = event.to_signing_bytes().expect("signing bytes");
        let signature = sign_contextual(
            SignatureKind::Anonymous,
            StorageMode::Archival,
            signer,
            ring,
            &signing_bytes,
        )
        .expect("sign archival event");
        event.signature = Some(signature);
    }

    fn make_push_event_request(tenant: TenantId, event: &Event) -> Request<PushEventRequest> {
        let event_bytes = serde_json::to_vec(event).expect("serialize");
        let mut req = Request::new(PushEventRequest {
            event_bytes,
            pow_submission: None,
        });
        req.extensions_mut().insert(tenant);
        req
    }

    #[tokio::test]
    async fn push_event_rejects_oversized_event_bytes() {
        let services = CoreServices::new_in_memory().expect("in-memory services");
        let tenant = TenantId(ulid::Ulid::new());

        let mut req = Request::new(PushEventRequest {
            event_bytes: vec![0u8; max_event_bytes() + 1],
            pow_submission: None,
        });
        req.extensions_mut().insert(tenant);

        let err = services.event.push_event(req).await.expect_err("reject");
        assert_eq!(err.code(), Code::InvalidArgument);
    }

    #[tokio::test]
    async fn upload_key_blobs_rejects_oversized_blob() {
        let services = CoreServices::new_in_memory().expect("in-memory services");
        let tenant = TenantId(ulid::Ulid::new());
        let org_id = ulid::Ulid::new().to_string();

        let mut req = Request::new(UploadKeyBlobsRequest {
            org_id,
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
        let org_id = ulid::Ulid::new().to_string();

        let blobs = (0..(keyblobs_max_count() + 1))
            .map(|_| KeyBlob {
                rage_pub: Some(RagePublicKey {
                    value: vec![7u8; 32],
                }),
                blob: vec![0u8; 1],
            })
            .collect();

        let mut req = Request::new(UploadKeyBlobsRequest { org_id, blobs });
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
        use crate::ids::{EventId, EventUlid, RingHash, Ulid};

        let services = CoreServices::new_in_memory().expect("in-memory services");
        let tenant = TenantId(ulid::Ulid::new());
        let org_id = create_test_org(&services, tenant).await;

        // Create a poll event with an oversized poll_id
        let oversized_poll_id = "x".repeat(max_poll_id_length() + 1);
        let poll = Poll {
            org_id,
            ring_hash: RingHash([0u8; 32]),
            poll_id: oversized_poll_id,
            questions: vec![PollQuestion {
                question_id: "q1".into(),
                title: Ciphertext(b"test".to_vec()),
                kind: PollQuestionKind::FillInTheBlank,
            }],
            created_at: 123,
            instructions: None,
            deadline: None,
        };

        let event = Event {
            event_ulid: EventUlid(Ulid::new()),
            previous_event_hash: EventId([0u8; 32]),
            org_id: poll.org_id,
            sequence_no: None,
            processed_at: 123,
            serialization_version: 1,
            event_type: EventType::PollCreate(poll),
            signature: None,
        };

        let event_bytes = serde_json::to_vec(&event).expect("serialize");
        let mut req = Request::new(PushEventRequest {
            event_bytes,
            pow_submission: None,
        });
        req.extensions_mut().insert(tenant);

        let err = services.event.push_event(req).await.expect_err("reject");
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("poll_id"));
    }

    #[tokio::test]
    async fn push_event_rejects_oversized_message_content() {
        use crate::crypto::ciphertext::Ciphertext;
        use crate::event::{AnonymousMessage, Event, EventType};
        use crate::ids::{EventId, EventUlid, RingHash, Ulid};

        let services = CoreServices::new_in_memory().expect("in-memory services");
        let tenant = TenantId(ulid::Ulid::new());
        let org_id = create_test_org(&services, tenant).await;

        // Create a message event with oversized content (in UTF-8 characters)
        let oversized_content = "x".repeat(max_message_content_chars() + 1);
        let message = AnonymousMessage {
            org_id,
            ring_hash: RingHash([0u8; 32]),
            message_id: Ulid::new().to_string(),
            content: Ciphertext(oversized_content.into_bytes()),
            sent_at: 123,
        };

        let event = Event {
            event_ulid: EventUlid(Ulid::new()),
            previous_event_hash: EventId([0u8; 32]),
            org_id,
            sequence_no: None,
            processed_at: 123,
            serialization_version: 1,
            event_type: EventType::MessageCreate(message),
            signature: None,
        };

        let event_bytes = serde_json::to_vec(&event).expect("serialize");
        let mut req = Request::new(PushEventRequest {
            event_bytes,
            pow_submission: None,
        });
        req.extensions_mut().insert(tenant);

        let err = services.event.push_event(req).await.expect_err("reject");
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("message_content"));
    }

    // --- TB-B-001: VoteCast must be bound to the ring snapshot at poll creation ---

    #[tokio::test]
    async fn push_event_rejects_vote_when_poll_ring_hash_mismatches() {
        let services = CoreServices::new_in_memory().expect("in-memory services");
        let tenant = TenantId(ulid::Ulid::new());
        let org_id = create_test_org(&services, tenant).await;

        let mut csprng = OsRng;
        let owner = KeyPair::generate(&mut csprng);
        let extra = KeyPair::generate(&mut csprng);
        let ring_at_poll = Ring::new(vec![*owner.public()]);
        let ring_after = Ring::new(vec![*owner.public(), *extra.public()]);
        let ring_hash_at_poll = ring_hash_sha3_256(&ring_at_poll);
        let ring_hash_after = ring_hash_sha3_256(&ring_after);

        // Create poll with original ring
        let poll = Poll {
            org_id,
            ring_hash: ring_hash_at_poll,
            poll_id: "poll-ring-binding-reject".into(),
            questions: vec![PollQuestion {
                question_id: "q1".into(),
                title: Ciphertext(b"question".to_vec()),
                kind: PollQuestionKind::FillInTheBlank,
            }],
            created_at: 1,
            instructions: None,
            deadline: None,
        };
        let poll_hash = poll.hash().expect("poll hash");

        let mut poll_event = Event {
            event_ulid: EventUlid(Ulid::new()),
            previous_event_hash: EventId([0u8; 32]),
            org_id,
            sequence_no: None,
            processed_at: 1,
            serialization_version: 1,
            event_type: EventType::PollCreate(poll.clone()),
            signature: None,
        };
        sign_event_archival(&mut poll_event, &owner, &ring_at_poll);
        services
            .event
            .push_event(make_push_event_request(tenant, &poll_event))
            .await
            .expect("poll accepted");

        // Vote claims a DIFFERENT ring hash than what the poll was created with
        let vote = Vote {
            org_id,
            ring_hash: ring_hash_after,
            poll_id: poll.poll_id.clone(),
            poll_hash,
            poll_ring_hash: ring_hash_after, // mismatch: poll was created with ring_hash_at_poll
            selections: vec![VoteSelection {
                question_id: "q1".into(),
                option_ids: vec![],
                write_in: None,
            }],
        };

        let mut vote_event = Event {
            event_ulid: EventUlid(Ulid::new()),
            previous_event_hash: EventId([0u8; 32]),
            org_id,
            sequence_no: None,
            processed_at: 2,
            serialization_version: 1,
            event_type: EventType::VoteCast(vote),
            signature: None,
        };
        sign_event_archival(&mut vote_event, &owner, &ring_after);

        let err = services
            .event
            .push_event(make_push_event_request(tenant, &vote_event))
            .await
            .expect_err("vote must be rejected");
        assert_eq!(err.code(), Code::FailedPrecondition);
        assert!(err
            .message()
            .contains("vote.poll_ring_hash does not match poll snapshot"));
    }

    #[tokio::test]
    async fn push_event_accepts_vote_when_ring_matches_poll_snapshot() {
        let services = CoreServices::new_in_memory().expect("in-memory services");
        let tenant = TenantId(ulid::Ulid::new());
        let org_id = create_test_org(&services, tenant).await;

        let mut csprng = OsRng;
        let owner = KeyPair::generate(&mut csprng);
        let voter = KeyPair::generate(&mut csprng);
        let ring = Ring::new(vec![*owner.public(), *voter.public()]);
        let ring_hash = ring_hash_sha3_256(&ring);

        let poll = Poll {
            org_id,
            ring_hash,
            poll_id: "poll-ring-binding-accept".into(),
            questions: vec![PollQuestion {
                question_id: "q1".into(),
                title: Ciphertext(b"question".to_vec()),
                kind: PollQuestionKind::FillInTheBlank,
            }],
            created_at: 1,
            instructions: None,
            deadline: None,
        };
        let poll_hash = poll.hash().expect("poll hash");

        let mut poll_event = Event {
            event_ulid: EventUlid(Ulid::new()),
            previous_event_hash: EventId([0u8; 32]),
            org_id,
            sequence_no: None,
            processed_at: 1,
            serialization_version: 1,
            event_type: EventType::PollCreate(poll.clone()),
            signature: None,
        };
        sign_event_archival(&mut poll_event, &owner, &ring);
        services
            .event
            .push_event(make_push_event_request(tenant, &poll_event))
            .await
            .expect("poll accepted");

        let vote = Vote {
            org_id,
            ring_hash,
            poll_id: poll.poll_id.clone(),
            poll_hash,
            poll_ring_hash: ring_hash, // matches poll creation ring
            selections: vec![VoteSelection {
                question_id: "q1".into(),
                option_ids: vec![],
                write_in: None,
            }],
        };

        let mut vote_event = Event {
            event_ulid: EventUlid(Ulid::new()),
            previous_event_hash: EventId([0u8; 32]),
            org_id,
            sequence_no: None,
            processed_at: 2,
            serialization_version: 1,
            event_type: EventType::VoteCast(vote),
            signature: None,
        };
        sign_event_archival(&mut vote_event, &voter, &ring);

        services
            .event
            .push_event(make_push_event_request(tenant, &vote_event))
            .await
            .expect("vote accepted");
    }

    // --- TB-B-003: Archival ring_hash consistency ---

    #[tokio::test]
    async fn push_event_rejects_archival_signature_ring_hash_mismatch() {
        let services = CoreServices::new_in_memory().expect("in-memory services");
        let tenant = TenantId(ulid::Ulid::new());
        let org_id = create_test_org(&services, tenant).await;

        let (signer, signing_ring) = make_signing_ring(4);
        // Declare a ring_hash that doesn't match the actual signing ring
        let mut declared_ring_hash = ring_hash_sha3_256(&signing_ring);
        declared_ring_hash.0[0] ^= 0x01;

        let mut event = Event {
            event_ulid: EventUlid(Ulid::new()),
            previous_event_hash: EventId([0u8; 32]),
            org_id,
            sequence_no: None,
            processed_at: 123,
            serialization_version: 1,
            event_type: EventType::MessageCreate(AnonymousMessage {
                org_id,
                ring_hash: declared_ring_hash,
                message_id: Ulid::new().to_string(),
                content: Ciphertext(b"hello".to_vec()),
                sent_at: 123,
            }),
            signature: None,
        };
        sign_event_archival(&mut event, &signer, &signing_ring);

        let err = services
            .event
            .push_event(make_push_event_request(tenant, &event))
            .await
            .expect_err("reject mismatched archival ring hash");
        assert_eq!(err.code(), Code::FailedPrecondition);
        assert!(err.message().contains("ring_hash"));
    }

    #[tokio::test]
    async fn push_event_accepts_archival_signature_when_ring_hash_matches() {
        let services = CoreServices::new_in_memory().expect("in-memory services");
        let tenant = TenantId(ulid::Ulid::new());
        let org_id = create_test_org(&services, tenant).await;

        let (signer, signing_ring) = make_signing_ring(4);
        let declared_ring_hash = ring_hash_sha3_256(&signing_ring);

        let mut event = Event {
            event_ulid: EventUlid(Ulid::new()),
            previous_event_hash: EventId([0u8; 32]),
            org_id,
            sequence_no: None,
            processed_at: 123,
            serialization_version: 1,
            event_type: EventType::MessageCreate(AnonymousMessage {
                org_id,
                ring_hash: declared_ring_hash,
                message_id: Ulid::new().to_string(),
                content: Ciphertext(b"hello".to_vec()),
                sent_at: 123,
            }),
            signature: None,
        };
        sign_event_archival(&mut event, &signer, &signing_ring);

        let resp = services
            .event
            .push_event(make_push_event_request(tenant, &event))
            .await
            .expect("accept");
        assert!(resp.into_inner().event_ulid.is_some());
    }

    #[test]
    fn to_status_not_found_does_not_leak_internal_ids() {
        use crate::ids::{OrganizationId, TenantId, Ulid};
        use crate::storage::{NotFound, StorageError};

        let status = to_status(StorageError::NotFound(NotFound::KeyBlob {
            tenant: TenantId(Ulid::new()),
            org_id: OrganizationId(Ulid::new()),
            rage_pub: [7u8; 32],
        }));

        assert_eq!(status.code(), Code::NotFound);
        assert!(status.message().contains("key_blob not found"));
        assert!(!status.message().contains("TenantId"));
        assert!(!status.message().contains("OrganizationId"));
        assert!(!status.message().contains("rage_pub"));
    }
}
