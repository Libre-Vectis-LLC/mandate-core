use curve25519_dalek::ristretto::RistrettoPoint;
use serde::{Deserialize, Serialize};

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
