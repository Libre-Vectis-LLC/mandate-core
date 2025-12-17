//! gRPC-facing error helpers and metadata keys.

use crate::proto::API_TOKEN_METADATA_KEY;
use tonic::{Code, Status};

/// Map domain or validation errors into tonic statuses.
pub enum RpcError {
    InvalidArgument(String),
    NotFound(String),
    AlreadyExists(String),
    PermissionDenied(String),
    Unauthenticated(String),
    ResourceExhausted(String),
    FailedPrecondition(String),
    Conflict(String),
    Aborted(String),
    Internal(String),
    Unavailable(String),
}

impl From<RpcError> for Status {
    fn from(err: RpcError) -> Self {
        match err {
            RpcError::InvalidArgument(msg) => Status::new(Code::InvalidArgument, msg),
            RpcError::NotFound(msg) => Status::new(Code::NotFound, msg),
            RpcError::AlreadyExists(msg) => Status::new(Code::AlreadyExists, msg),
            RpcError::PermissionDenied(msg) => Status::new(Code::PermissionDenied, msg),
            RpcError::Unauthenticated(msg) => Status::new(Code::Unauthenticated, msg),
            RpcError::ResourceExhausted(msg) => Status::new(Code::ResourceExhausted, msg),
            RpcError::FailedPrecondition(msg) => Status::new(Code::FailedPrecondition, msg),
            RpcError::Conflict(msg) => Status::new(Code::Aborted, msg),
            RpcError::Aborted(msg) => Status::new(Code::Aborted, msg),
            RpcError::Internal(msg) => Status::new(Code::Internal, msg),
            RpcError::Unavailable(msg) => Status::new(Code::Unavailable, msg),
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
        let s: Status = RpcError::InvalidArgument("bad".into()).into();
        assert_eq!(s.code(), Code::InvalidArgument);
        assert_eq!(s.message(), "bad");
    }

    #[test]
    fn api_token_key_constant() {
        assert_eq!(api_token_metadata_key(), "x-api-token");
    }
}
