use curve25519_dalek::ristretto::RistrettoPoint;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

pub use nazgul::ring::RingHash;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EventId(pub [u8; 32]);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ContentHash(pub [u8; 32]);

/// Key image represented as an uncompressed Ristretto point (32 bytes compressed form).
pub type KeyImage = RistrettoPoint;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MasterPublicKey(pub [u8; 32]);

pub use ulid::Ulid;

/// ULID-based event identifier used for derivations (separate from content-hash `EventId`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EventUlid(pub Ulid);

impl EventUlid {
    pub fn to_bytes(self) -> [u8; 16] {
        self.0.to_bytes()
    }

    pub fn as_ulid(self) -> Ulid {
        self.0
    }
}

impl fmt::Display for EventUlid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<Ulid> for EventUlid {
    fn from(value: Ulid) -> Self {
        Self(value)
    }
}

impl From<EventUlid> for Ulid {
    fn from(value: EventUlid) -> Self {
        value.0
    }
}

impl FromStr for EventUlid {
    type Err = ulid::DecodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(Ulid::from_string(s)?))
    }
}

/// Multi-tenant identifier (one ring per paying tenant). Newtype to avoid stringly-typed usage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TenantId(pub Ulid);

/// Group identifier (server-assigned ULID) used in derivations and hashing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct GroupId(pub Ulid);

impl GroupId {
    pub fn to_bytes(self) -> [u8; 16] {
        self.0.to_bytes()
    }

    pub fn as_ulid(self) -> Ulid {
        self.0
    }
}

impl fmt::Display for GroupId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<Ulid> for GroupId {
    fn from(value: Ulid) -> Self {
        Self(value)
    }
}

impl From<GroupId> for Ulid {
    fn from(value: GroupId) -> Self {
        value.0
    }
}

impl FromStr for GroupId {
    type Err = ulid::DecodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(Ulid::from_string(s)?))
    }
}
