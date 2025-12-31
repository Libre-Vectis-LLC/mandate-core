//! gRPC layer: service stubs and simple in-memory mocks.

pub mod inmemory;
pub mod interceptor;
pub mod services;
pub mod wiring;

/// Re-export shim for backward compatibility.
///
/// **Deprecated**: Import directly from `crate::grpc::inmemory` instead.
/// This module will be removed in a future release.
#[deprecated(
    since = "0.1.0",
    note = "Use `crate::grpc::inmemory` instead. This re-export shim will be removed."
)]
pub mod types;
