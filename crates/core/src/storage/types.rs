//! Core data types and errors for storage layer.

use crate::ids::{EventId, OrganizationId, RingHash, SequenceNo, TenantId};
use crate::ring_log::{apply_delta, RingDelta, RingLogError};
use nazgul::ring::Ring;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Canonical, signed event bytes (audit-preserving).
pub type EventBytes = Arc<[u8]>;

/// Event identifier, canonical bytes, and sequence number.
pub type EventRecord = (EventId, EventBytes, SequenceNo);

/// Path-limited slice of a ring delta log, usable for incremental replay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RingDeltaPath {
    /// Starting ring hash (anchor) of this slice.
    pub from: RingHash,
    /// Target ring hash after applying all deltas.
    pub to: RingHash,
    /// Ordered deltas leading from `from` to `to` (shortest path chosen by storage layer).
    pub deltas: Vec<RingDelta>,
}

impl RingDeltaPath {
    /// Replay the delta path onto an anchor ring, returning the final ring.
    /// Caller supplies the anchor ring whose hash must equal `from`.
    pub fn apply(self, mut anchor_ring: Ring) -> Result<Ring, RingLogError> {
        for delta in &self.deltas {
            apply_delta(&mut anchor_ring, delta)?;
        }
        Ok(anchor_ring)
    }
}

/// Unified storage error for trait implementors.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum StorageError {
    #[error("not found: {0}")]
    NotFound(NotFound),
    #[error("backend error: {0}")]
    Backend(String),
    #[error("already exists")]
    AlreadyExists,
    #[error("precondition failed: {0}")]
    PreconditionFailed(String),
}

/// Errors returned while resolving a tenant token to a tenant identity.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TenantTokenError {
    #[error("unknown tenant token")]
    Unknown,
    #[error("backend error: {0}")]
    Backend(String),
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NotFound {
    #[error("event {id:?} for tenant {tenant:?} group {org_id:?}")]
    Event {
        id: EventId,
        tenant: TenantId,
        org_id: OrganizationId,
    },
    #[error("tenant {tenant:?}")]
    Tenant { tenant: TenantId },
    #[error("group {org_id:?}")]
    Group { org_id: OrganizationId },
    #[error("tail for tenant {tenant:?} group {org_id:?}")]
    Tail { tenant: TenantId, org_id: OrganizationId },
    #[error("ring {hash:?} for tenant {tenant:?} group {org_id:?}")]
    Ring {
        hash: RingHash,
        tenant: TenantId,
        org_id: OrganizationId,
    },
    #[error("ring delta path from {from:?} to {to:?} for tenant {tenant:?} group {org_id:?}")]
    RingDeltaPath {
        from: Option<RingHash>,
        to: RingHash,
        tenant: TenantId,
        org_id: OrganizationId,
    },
    #[error("key blob for tenant {tenant:?} group {org_id:?} rage_pub {rage_pub:?}")]
    KeyBlob {
        tenant: TenantId,
        org_id: OrganizationId,
        rage_pub: [u8; 32],
    },
    #[error("gift card {code}")]
    GiftCard { code: String },
    #[error("invite code {code}")]
    InviteCode { code: String },
    #[error("access token blob for tenant {tenant:?} group {org_id:?} rage_pub {rage_pub:?}")]
    AccessTokenBlob {
        tenant: TenantId,
        org_id: OrganizationId,
        rage_pub: [u8; 32],
    },
    #[error("edge access token for tenant {tenant:?} group {org_id:?}")]
    EdgeAccessToken { tenant: TenantId, org_id: OrganizationId },
}

/// Error codes for idempotency results, mapped from gRPC status codes.
///
/// When an idempotent operation is retried, this enum captures the original
/// error type so the same error can be returned to the client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IdempotencyErrorCode {
    /// Request is malformed or contains invalid data.
    InvalidArgument,
    /// Operation was rejected due to insufficient balance or other precondition.
    FailedPrecondition,
    /// Resource (tenant, group, etc.) was not found.
    NotFound,
    /// Request conflicts with existing state.
    AlreadyExists,
    /// Caller lacks permission for this operation.
    PermissionDenied,
    /// Resource quota exceeded.
    ResourceExhausted,
    /// Operation was cancelled.
    Cancelled,
    /// Operation was aborted due to concurrency conflict.
    Aborted,
    /// Operation timed out.
    DeadlineExceeded,
    /// Unrecoverable internal error.
    Internal,
    /// Service temporarily unavailable.
    Unavailable,
    /// Data loss or corruption detected.
    DataLoss,
    /// Caller is not authenticated.
    Unauthenticated,
    /// Operation not implemented.
    Unimplemented,
    /// Unknown error type.
    Unknown,
}

/// Result of an idempotent operation, stored for replay on retry.
///
/// When a client retries an operation with the same idempotency key,
/// the stored result is returned instead of re-executing the operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IdempotencyResult {
    /// Operation completed successfully with the resulting balance.
    Success {
        /// The balance after the operation completed, in nanos.
        balance_nanos: u64,
    },
    /// Operation failed with an error.
    Error {
        /// The error code category.
        code: IdempotencyErrorCode,
        /// Human-readable error message.
        message: String,
    },
}
