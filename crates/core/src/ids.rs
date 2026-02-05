use curve25519_dalek::ristretto::RistrettoPoint;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use std::sync::Arc;

pub use nazgul::ring::RingHash;

/// Common trait for types wrapping a 32-byte hash.
///
/// This trait provides a uniform interface for types that represent cryptographic hashes,
/// identifiers, or keys stored as 32-byte arrays.
///
/// # Design rationale
///
/// While the underlying types currently expose their inner arrays as public fields,
/// this trait serves as:
/// - A clear semantic marker for "this is a 32-byte hash type"
/// - A foundation for future API evolution (if fields become private)
/// - An interface for generic programming over hash types
///
/// # Examples
///
/// ```
/// use mandate_core::ids::{Hash32, EventId};
///
/// fn print_hash<H: Hash32>(hash: &H) {
///     println!("{:x?}", hash.as_bytes());
/// }
///
/// let event_id = EventId::from_bytes([0u8; 32]);
/// print_hash(&event_id);
/// ```
pub trait Hash32 {
    /// Returns a reference to the inner 32-byte array.
    fn as_bytes(&self) -> &[u8; 32];

    /// Creates a new instance from a 32-byte array.
    fn from_bytes(bytes: [u8; 32]) -> Self;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EventId(pub [u8; 32]);

impl Hash32 for EventId {
    fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ContentHash(pub [u8; 32]);

impl Hash32 for ContentHash {
    fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// Key image represented as an uncompressed Ristretto point (32 bytes compressed form).
pub type KeyImage = RistrettoPoint;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MasterPublicKey(pub [u8; 32]);

impl Hash32 for MasterPublicKey {
    fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

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

/// Tenant-scoped API token carried via gRPC metadata (`x-api-token`).
///
/// This value is **secret and rotatable**; treat it as opaque and avoid logging.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct TenantToken(Arc<str>);

impl TenantToken {
    pub fn new(token: impl Into<Arc<str>>) -> Self {
        Self(token.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for TenantToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TenantToken(<redacted>)")
    }
}

impl From<String> for TenantToken {
    fn from(value: String) -> Self {
        Self::new(Arc::<str>::from(value))
    }
}

impl From<&str> for TenantToken {
    fn from(value: &str) -> Self {
        Self::new(Arc::<str>::from(value))
    }
}

impl From<Arc<str>> for TenantToken {
    fn from(value: Arc<str>) -> Self {
        Self::new(value)
    }
}

impl AsRef<str> for TenantToken {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

/// Internal bot authentication secret carried via gRPC metadata (`x-bot-secret`).
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct BotSecret(Arc<str>);

impl BotSecret {
    pub fn new(secret: impl Into<Arc<str>>) -> Self {
        Self(secret.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl fmt::Debug for BotSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BotSecret(<redacted>)")
    }
}

impl From<String> for BotSecret {
    fn from(value: String) -> Self {
        Self::new(Arc::<str>::from(value))
    }
}

impl From<&str> for BotSecret {
    fn from(value: &str) -> Self {
        Self::new(Arc::<str>::from(value))
    }
}

/// org IDentifier (server-assigned ULID) used in derivations and hashing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct OrganizationId(pub Ulid);

impl OrganizationId {
    pub fn to_bytes(self) -> [u8; 16] {
        self.0.to_bytes()
    }

    pub fn as_ulid(self) -> Ulid {
        self.0
    }
}

impl fmt::Display for OrganizationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<Ulid> for OrganizationId {
    fn from(value: Ulid) -> Self {
        Self(value)
    }
}

impl From<OrganizationId> for Ulid {
    fn from(value: OrganizationId) -> Self {
        value.0
    }
}

impl FromStr for OrganizationId {
    type Err = ulid::DecodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(Ulid::from_string(s)?))
    }
}

/// Monetary amount in nanocents (1 cent = 10^9 nanos).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Nanos(pub u64);

impl Nanos {
    pub const ZERO: Self = Self(0);
    pub const ONE_DOLLAR: Self = Self(1_000_000_000);

    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// Returns the raw nanos value.
    pub const fn value(self) -> u64 {
        self.0
    }

    /// Creates a Nanos value from a dollar amount (with precision up to 9 decimal places).
    pub fn from_dollars(dollars: f64) -> Self {
        Self((dollars * 1_000_000_000.0) as u64)
    }

    /// Converts the nanos value to dollars (as floating point).
    pub fn to_dollars(self) -> f64 {
        self.0 as f64 / 1_000_000_000.0
    }

    pub fn checked_add(self, other: Self) -> Option<Self> {
        self.0.checked_add(other.0).map(Self)
    }

    pub fn checked_sub(self, other: Self) -> Option<Self> {
        self.0.checked_sub(other.0).map(Self)
    }

    /// Saturating multiplication by a scalar.
    pub fn saturating_mul(self, scalar: u64) -> Self {
        Self(self.0.saturating_mul(scalar))
    }

    /// Convert to i64, returning None if the value exceeds i64::MAX.
    pub fn try_as_i64(self) -> Option<i64> {
        i64::try_from(self.0).ok()
    }
}

impl fmt::Display for Nanos {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::ops::Add for Nanos {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0.saturating_add(rhs.0))
    }
}

impl std::ops::Sub for Nanos {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0.saturating_sub(rhs.0))
    }
}

impl std::ops::Mul<i64> for Nanos {
    type Output = Self;

    fn mul(self, rhs: i64) -> Self::Output {
        if rhs < 0 {
            Self(0) // Saturate to zero for negative multipliers
        } else {
            Self(self.0.saturating_mul(rhs as u64))
        }
    }
}

/// Monotonically increasing sequence number for event ordering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SequenceNo(pub i64);

impl SequenceNo {
    /// Genesis sequence number (before first event).
    pub const GENESIS: Self = Self(-1);

    pub const fn new(value: i64) -> Self {
        Self(value)
    }

    pub const fn as_i64(self) -> i64 {
        self.0
    }

    pub fn next(self) -> Self {
        Self(self.0.saturating_add(1))
    }
}

impl fmt::Display for SequenceNo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
