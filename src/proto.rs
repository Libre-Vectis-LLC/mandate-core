//! Helpers to convert between generated gRPC types and core newtypes.
//! Keep these minimal to avoid leaking prost/tonic details into the rest of the crate.

use crate::ids::{ContentHash, EventId, GroupId, MasterPublicKey, RingHash};
use crate::ring_log::RingDelta;
use mandate_proto::mandate::v1::{Hash32, NazgulMasterPublicKey, RagePublicKey, Ulid as ProtoUlid};
use thiserror::Error;
use ulid::Ulid;

/// Metadata key for API token expected on incoming gRPC requests.
pub const API_TOKEN_METADATA_KEY: &str = "x-api-token";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProtoConvertError {
    #[error("invalid ulid string: {0}")]
    InvalidUlid(String),
    #[error("expected 32 bytes, got {0}")]
    InvalidLength(usize),
    #[error("invalid ring delta tag: {0}")]
    InvalidRingDeltaTag(u8),
}

pub fn parse_ulid(ulid_str: &str) -> Result<Ulid, ProtoConvertError> {
    Ulid::from_string(ulid_str).map_err(|_| ProtoConvertError::InvalidUlid(ulid_str.to_string()))
}

pub fn proto_ulid_to_group(id: &ProtoUlid) -> Result<GroupId, ProtoConvertError> {
    parse_ulid(&id.value).map(GroupId)
}

pub fn group_to_proto_ulid(id: &GroupId) -> ProtoUlid {
    ProtoUlid {
        value: id.to_string(),
    }
}

fn expect_32(bytes: &[u8]) -> Result<[u8; 32], ProtoConvertError> {
    bytes
        .try_into()
        .map_err(|_| ProtoConvertError::InvalidLength(bytes.len()))
}

pub fn hash32_to_ring_hash(h: &Hash32) -> Result<RingHash, ProtoConvertError> {
    Ok(RingHash(expect_32(&h.value)?))
}

pub fn hash32_to_content_hash(h: &Hash32) -> Result<ContentHash, ProtoConvertError> {
    Ok(ContentHash(expect_32(&h.value)?))
}

pub fn hash32_to_event_id(h: &Hash32) -> Result<EventId, ProtoConvertError> {
    Ok(EventId(expect_32(&h.value)?))
}

pub fn event_id_to_hash32(id: &EventId) -> Hash32 {
    Hash32 {
        value: id.0.to_vec(),
    }
}

pub fn nazgul_pub_from_proto(
    pk: &NazgulMasterPublicKey,
) -> Result<MasterPublicKey, ProtoConvertError> {
    Ok(MasterPublicKey(expect_32(&pk.value)?))
}

pub fn rage_pub_from_proto(pk: &RagePublicKey) -> Result<[u8; 32], ProtoConvertError> {
    expect_32(&pk.value)
}

pub fn ring_hash_to_hash32(h: &RingHash) -> Hash32 {
    Hash32 {
        value: h.0.to_vec(),
    }
}

pub fn content_hash_to_hash32(h: &ContentHash) -> Hash32 {
    Hash32 {
        value: h.0.to_vec(),
    }
}

pub fn master_pub_to_proto(pk: &MasterPublicKey) -> NazgulMasterPublicKey {
    NazgulMasterPublicKey {
        value: pk.0.to_vec(),
    }
}

pub fn ulid_to_proto(id: &Ulid) -> ProtoUlid {
    ProtoUlid {
        value: id.to_string(),
    }
}

/// Encode a ring delta into the opaque bytes used by gRPC ring streaming.
/// Format: 1-byte tag (0=add, 1=remove) + 32-byte master public key.
pub fn ring_delta_to_bytes(delta: &RingDelta) -> Vec<u8> {
    let mut buf = Vec::with_capacity(33);
    match delta {
        RingDelta::Add(pk) => {
            buf.push(0u8);
            buf.extend_from_slice(&pk.0);
        }
        RingDelta::Remove(pk) => {
            buf.push(1u8);
            buf.extend_from_slice(&pk.0);
        }
    }
    buf
}

/// Decode a ring delta from the opaque bytes used by gRPC ring streaming.
pub fn ring_delta_from_bytes(bytes: &[u8]) -> Result<RingDelta, ProtoConvertError> {
    if bytes.len() != 33 {
        return Err(ProtoConvertError::InvalidLength(bytes.len()));
    }

    let tag = bytes[0];
    let pk = MasterPublicKey(expect_32(&bytes[1..])?);
    match tag {
        0 => Ok(RingDelta::Add(pk)),
        1 => Ok(RingDelta::Remove(pk)),
        other => Err(ProtoConvertError::InvalidRingDeltaTag(other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::MasterPublicKey;
    use crate::ring_log::RingDelta;

    #[test]
    fn ulid_roundtrip() {
        let u = Ulid::new();
        let p = ulid_to_proto(&u);
        let back = parse_ulid(&p.value).unwrap();
        assert_eq!(u, back);
    }

    #[test]
    fn hash32_length_validation() {
        let h = Hash32 {
            value: vec![1u8; 31],
        };
        assert!(matches!(
            hash32_to_ring_hash(&h),
            Err(ProtoConvertError::InvalidLength(31))
        ));
    }

    #[test]
    fn pubkey_length_validation() {
        let bad = NazgulMasterPublicKey {
            value: vec![0u8; 10],
        };
        assert!(matches!(
            nazgul_pub_from_proto(&bad),
            Err(ProtoConvertError::InvalidLength(10))
        ));
    }

    #[test]
    fn ring_delta_roundtrip() {
        let pk = MasterPublicKey([7u8; 32]);
        for delta in [RingDelta::Add(pk), RingDelta::Remove(pk)] {
            let encoded = ring_delta_to_bytes(&delta);
            let decoded = ring_delta_from_bytes(&encoded).expect("decode");
            assert_eq!(delta, decoded);
        }
    }

    #[test]
    fn ring_delta_rejects_bad_length() {
        let bad = vec![0u8; 10];
        assert!(matches!(
            ring_delta_from_bytes(&bad),
            Err(ProtoConvertError::InvalidLength(10))
        ));
    }

    #[test]
    fn ring_delta_rejects_bad_tag() {
        let mut bad = vec![9u8];
        bad.extend_from_slice(&[0u8; 32]);
        assert!(matches!(
            ring_delta_from_bytes(&bad),
            Err(ProtoConvertError::InvalidRingDeltaTag(9))
        ));
    }
}
