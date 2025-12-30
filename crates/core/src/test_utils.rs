//! Test-only helpers shared across unit and integration tests.
//!
//! IMPORTANT: Mandate requires at least 256-bit security for user keys.
//! Use 24-word BIP39 mnemonics in production; 12-word (128-bit) mnemonics are not allowed.

use crate::ids::{EventUlid, GroupId, TenantId};
use ulid::Ulid;

/// Fixed 24‑word BIP39 mnemonic used in tests for deterministic key derivations.
pub const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

/// Standard test ULID strings for consistent test data across the codebase.
///
/// These are deterministic, well-formed ULIDs suitable for unit and integration tests.
/// Using constants avoids magic strings and ensures test reproducibility.
pub const TEST_GROUP_ID_STR: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
pub const TEST_TENANT_ID_STR: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAQ";
pub const TEST_EVENT_ULID_STR: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";

/// Alternative test ULIDs for isolation tests requiring distinct identifiers.
pub const TEST_GROUP_ID_STR_ALT1: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAY";
pub const TEST_GROUP_ID_STR_ALT2: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAZ";

/// Construct a GroupId from a ULID string. Panics if invalid (test-only).
pub fn test_group_id() -> GroupId {
    GroupId(Ulid::from_string(TEST_GROUP_ID_STR).expect("static test ULID"))
}

/// Construct an alternative GroupId for isolation tests.
pub fn test_group_id_alt1() -> GroupId {
    GroupId(Ulid::from_string(TEST_GROUP_ID_STR_ALT1).expect("static test ULID"))
}

/// Construct a second alternative GroupId for isolation tests.
pub fn test_group_id_alt2() -> GroupId {
    GroupId(Ulid::from_string(TEST_GROUP_ID_STR_ALT2).expect("static test ULID"))
}

/// Construct a TenantId from the standard test ULID string.
pub fn test_tenant_id() -> TenantId {
    TenantId(Ulid::from_string(TEST_TENANT_ID_STR).expect("static test ULID"))
}

/// Construct an EventUlid from the standard test ULID string.
pub fn test_event_ulid() -> EventUlid {
    EventUlid(Ulid::from_string(TEST_EVENT_ULID_STR).expect("static test ULID"))
}

/// Generic ULID parser for custom test identifiers. Panics on parse error.
pub fn parse_test_ulid(s: &str) -> Ulid {
    Ulid::from_string(s).expect("valid test ULID")
}

/// Construct a GroupId from an arbitrary ULID string. Panics if invalid.
pub fn group_id_from_str(s: &str) -> GroupId {
    GroupId(parse_test_ulid(s))
}

/// Construct an EventUlid from an arbitrary ULID string. Panics if invalid.
pub fn event_ulid_from_str(s: &str) -> EventUlid {
    EventUlid(parse_test_ulid(s))
}
