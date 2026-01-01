//! **Deprecated re-export shim**
//!
//! This module only exists for backward compatibility. All types have been moved
//! to the `inmemory` module. Import directly from `crate::grpc::inmemory` instead.
//!
//! This module will be removed in a future release.

#![allow(deprecated)]

pub use super::inmemory::{
    InMemoryBanIndex, InMemoryBilling, InMemoryEvents, InMemoryGiftCards, InMemoryGroups,
    InMemoryKeyBlobs, InMemoryPendingMembers, InMemoryRings, InMemoryTenantTokens,
    InMemoryVoteKeyImages, NoopBanIndex, NoopVoteKeyImages,
};
