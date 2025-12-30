//! gRPC-facing error helpers and metadata keys.

use crate::proto::API_TOKEN_METADATA_KEY;
use tonic::{Code, Status};

/// Map domain or validation errors into tonic statuses.
pub enum RpcError {
    /// Invalid request argument (field validation, parsing, format).
    InvalidArgument { field: &'static str, reason: String },
    /// Resource not found.
    NotFound { resource: &'static str, id: String },
    /// Resource already exists.
    AlreadyExists { resource: &'static str, id: String },
    /// Permission denied for resource.
    PermissionDenied { resource: &'static str, reason: String },
    /// Authentication failed (missing/invalid credentials).
    Unauthenticated { credential: &'static str, reason: String },
    /// Rate limit or quota exceeded.
    ResourceExhausted { resource: &'static str, limit: String },
    /// Business rule violation (chain mismatch, duplicate action, ban).
    FailedPrecondition { operation: &'static str, reason: String },
    /// Concurrent modification conflict.
    Conflict { resource: &'static str, reason: String },
    /// Operation aborted (transient).
    Aborted { operation: &'static str, reason: String },
    /// Internal server error.
    Internal { operation: &'static str, details: String },
    /// Service unavailable.
    Unavailable { service: &'static str, reason: String },
}

impl From<RpcError> for Status {
    fn from(err: RpcError) -> Self {
        match err {
            RpcError::InvalidArgument { field, reason } => {
                Status::new(Code::InvalidArgument, format!("{field}: {reason}"))
            }
            RpcError::NotFound { resource, id } => {
                Status::new(Code::NotFound, format!("{resource} not found: {id}"))
            }
            RpcError::AlreadyExists { resource, id } => {
                Status::new(Code::AlreadyExists, format!("{resource} already exists: {id}"))
            }
            RpcError::PermissionDenied { resource, reason } => {
                Status::new(Code::PermissionDenied, format!("{resource}: {reason}"))
            }
            RpcError::Unauthenticated { credential, reason } => {
                Status::new(Code::Unauthenticated, format!("{credential}: {reason}"))
            }
            RpcError::ResourceExhausted { resource, limit } => {
                Status::new(Code::ResourceExhausted, format!("{resource}: {limit}"))
            }
            RpcError::FailedPrecondition { operation, reason } => {
                Status::new(Code::FailedPrecondition, format!("{operation}: {reason}"))
            }
            RpcError::Conflict { resource, reason } => {
                Status::new(Code::Aborted, format!("{resource}: {reason}"))
            }
            RpcError::Aborted { operation, reason } => {
                Status::new(Code::Aborted, format!("{operation}: {reason}"))
            }
            RpcError::Internal { operation, details } => {
                Status::new(Code::Internal, format!("{operation}: {details}"))
            }
            RpcError::Unavailable { service, reason } => {
                Status::new(Code::Unavailable, format!("{service}: {reason}"))
            }
        }
    }
}

/// Metadata key for API tokens (kept here to avoid magic strings).
pub fn api_token_metadata_key() -> &'static str {
    API_TOKEN_METADATA_KEY
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rpc_error_to_status_code() {
        let s: Status = RpcError::InvalidArgument {
            field: "test_field",
            reason: "bad".into(),
        }
        .into();
        assert_eq!(s.code(), Code::InvalidArgument);
        assert_eq!(s.message(), "test_field: bad");
    }

    #[test]
    fn api_token_key_constant() {
        assert_eq!(api_token_metadata_key(), "x-api-token");
    }
}
