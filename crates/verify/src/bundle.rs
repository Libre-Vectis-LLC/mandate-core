//! Poll verification bundle.
//!
//! A [`PollBundle`] packages everything needed to independently verify a poll:
//! the raw poll-creation event, all vote events, the ring of public keys, and
//! the key material required to decrypt poll content.
//!
//! Serialisation uses Protocol Buffers via [`prost::Message`].

use prost::Message;
use thiserror::Error;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors that can occur while encoding or decoding a [`PollBundle`].
#[derive(Debug, Error)]
pub enum BundleError {
    /// The supplied bytes could not be decoded as a valid `PollBundle`.
    #[error("failed to decode PollBundle: {0}")]
    Decode(#[from] prost::DecodeError),
}

// ---------------------------------------------------------------------------
// PollBundle
// ---------------------------------------------------------------------------

/// A single poll option definition with its identifier and display text.
#[derive(Clone, PartialEq, Message)]
pub struct OptionDef {
    /// Machine-readable option identifier (e.g., "opt-0").
    #[prost(string, tag = "1")]
    pub option_id: String,

    /// Human-readable option text in Simplified Chinese (source language).
    /// Traditional Chinese is derived at runtime via OpenCC.
    #[prost(string, tag = "2")]
    pub option_text_zhs: String,
}

/// Self-contained bundle for offline poll verification.
///
/// Contains the raw protocol events, ring member public keys, HKDF derivation
/// path components, and the derived `k_poll` needed to decrypt poll content.
#[derive(Clone, PartialEq, Message)]
pub struct PollBundle {
    /// Raw bytes of the `PollCreate` event.
    #[prost(bytes = "vec", tag = "1")]
    pub poll_event_raw: Vec<u8>,

    /// Raw bytes of each `VoteCast` event.
    #[prost(bytes = "vec", repeated, tag = "2")]
    pub vote_events_raw: Vec<Vec<u8>>,

    /// Nazgul master public keys of ring members (bs58-encoded).
    #[prost(string, repeated, tag = "3")]
    pub ring_member_pubs: Vec<String>,

    /// Organization identifier — HKDF derivation path component.
    #[prost(string, tag = "4")]
    pub org_id: String,

    /// Poll ULID — HKDF derivation path component.
    #[prost(string, tag = "5")]
    pub poll_ulid: String,

    /// Hex-encoded `k_poll` for decrypting poll content.
    #[prost(string, tag = "6")]
    pub poll_key_hex: String,

    /// Human-readable poll title (decrypted from poll event or provided directly).
    /// Empty string for bundles created before this field was added.
    #[prost(string, tag = "7")]
    pub poll_title: String,

    /// Poll option definitions with human-readable text.
    /// Empty for bundles created before this field was added.
    #[prost(message, repeated, tag = "8")]
    pub option_definitions: Vec<OptionDef>,

    /// Raw bytes of each `VoteRevocation` event.
    /// Empty for bundles created before vote revocation was added.
    #[prost(bytes = "vec", repeated, tag = "9")]
    pub revocation_events_raw: Vec<Vec<u8>>,
}

impl PollBundle {
    /// Serialise the bundle to a protobuf byte vector.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.encode_to_vec()
    }

    /// Deserialise a bundle from protobuf bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, BundleError> {
        Self::decode(data).map_err(BundleError::from)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a representative bundle for testing.
    fn sample_bundle() -> PollBundle {
        PollBundle {
            poll_event_raw: vec![0x01, 0x02, 0x03],
            vote_events_raw: vec![vec![0x0A, 0x0B], vec![0x0C, 0x0D, 0x0E]],
            ring_member_pubs: vec![
                "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ".into(),
                "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy".into(),
            ],
            org_id: "org_01JTEST".into(),
            poll_ulid: "01JTEST_POLL".into(),
            poll_key_hex: "deadbeefcafebabe".into(),
            poll_title: "Test Poll Title".into(),
            option_definitions: vec![
                OptionDef {
                    option_id: "opt-0".into(),
                    option_text_zhs: "Option A".into(),
                },
                OptionDef {
                    option_id: "opt-1".into(),
                    option_text_zhs: "Option B".into(),
                },
            ],
            revocation_events_raw: Vec::new(),
        }
    }

    #[test]
    fn test_roundtrip_encode_decode() {
        let original = sample_bundle();
        let bytes = original.to_bytes();
        let decoded =
            PollBundle::from_bytes(&bytes).expect("decoding a valid bundle should succeed");
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_invalid_bytes_returns_error() {
        // Garbage bytes that are not valid protobuf.
        let garbage = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        let result = PollBundle::from_bytes(&garbage);
        assert!(result.is_err(), "decoding garbage should fail");
        let err = result.unwrap_err();
        assert!(
            matches!(err, BundleError::Decode(_)),
            "expected BundleError::Decode, got: {err:?}"
        );
    }

    #[test]
    fn test_empty_bundle_roundtrip() {
        // Default (all fields empty/zero) should still round-trip.
        let empty = PollBundle {
            poll_event_raw: Vec::new(),
            vote_events_raw: Vec::new(),
            ring_member_pubs: Vec::new(),
            org_id: String::new(),
            poll_ulid: String::new(),
            poll_key_hex: String::new(),
            poll_title: String::new(),
            option_definitions: Vec::new(),
            revocation_events_raw: Vec::new(),
        };
        let bytes = empty.to_bytes();
        let decoded =
            PollBundle::from_bytes(&bytes).expect("decoding an empty bundle should succeed");
        assert_eq!(empty, decoded);
    }

    // -----------------------------------------------------------------------
    // Malformed input tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_corrupted_protobuf_truncated() {
        // Take valid protobuf bytes and truncate them mid-field to simulate
        // corruption (e.g., partial download).
        let bundle = sample_bundle();
        let full_bytes = bundle.to_bytes();
        assert!(
            full_bytes.len() > 10,
            "sample bundle must produce >10 bytes"
        );

        let truncated = &full_bytes[..full_bytes.len() / 2];
        let result = PollBundle::from_bytes(truncated);
        assert!(result.is_err(), "truncated protobuf should fail to decode");
    }

    #[test]
    fn test_empty_bytes_decode_succeeds_as_default() {
        // An empty protobuf message decodes to default field values in prost.
        let result = PollBundle::from_bytes(&[]);
        // Empty bytes are valid protobuf (all fields default).
        assert!(
            result.is_ok(),
            "empty bytes are valid protobuf (all-default message)"
        );
        let bundle = result.unwrap();
        assert!(bundle.poll_event_raw.is_empty());
        assert!(bundle.vote_events_raw.is_empty());
        assert!(bundle.ring_member_pubs.is_empty());
        assert!(bundle.org_id.is_empty());
    }

    #[test]
    fn test_bundle_with_duplicate_ring_member_pubs() {
        // Protobuf doesn't enforce uniqueness — duplicates round-trip faithfully.
        let bundle = PollBundle {
            poll_event_raw: vec![0x01],
            vote_events_raw: Vec::new(),
            ring_member_pubs: vec![
                "DuplicateKey123".into(),
                "DuplicateKey123".into(),
                "UniqueKey456".into(),
            ],
            org_id: "org_01JTEST".into(),
            poll_ulid: "01JTEST_POLL".into(),
            poll_key_hex: "cafe".into(),
            poll_title: String::new(),
            option_definitions: Vec::new(),
            revocation_events_raw: Vec::new(),
        };

        let bytes = bundle.to_bytes();
        let decoded =
            PollBundle::from_bytes(&bytes).expect("duplicate ring members should round-trip");
        assert_eq!(decoded.ring_member_pubs.len(), 3);
        assert_eq!(decoded.ring_member_pubs[0], decoded.ring_member_pubs[1]);
    }

    #[test]
    fn test_large_bundle_roundtrip() {
        // Stress test with many votes and ring members.
        let bundle = PollBundle {
            poll_event_raw: vec![0xAA; 1024],
            vote_events_raw: (0..100).map(|i| vec![i as u8; 64]).collect(),
            ring_member_pubs: (0..50).map(|i| format!("pubkey_{i:04}")).collect(),
            org_id: "org_STRESS_TEST".into(),
            poll_ulid: "01JSTRESS_POLL".into(),
            poll_key_hex: "0".repeat(64),
            poll_title: "Stress Test Poll".into(),
            option_definitions: Vec::new(),
            revocation_events_raw: Vec::new(),
        };

        let bytes = bundle.to_bytes();
        let decoded = PollBundle::from_bytes(&bytes).expect("large bundle should round-trip");
        assert_eq!(decoded, bundle);
        assert_eq!(decoded.vote_events_raw.len(), 100);
        assert_eq!(decoded.ring_member_pubs.len(), 50);
    }

    #[test]
    fn test_backward_compat_old_bundle_without_new_fields() {
        // Simulate a bundle encoded WITHOUT tags 7, 8, and 9 (old format).
        // Prost decodes missing fields as defaults (empty string, empty vec).
        let old_format = PollBundle {
            poll_event_raw: vec![0x01],
            vote_events_raw: vec![vec![0x0A]],
            ring_member_pubs: vec!["key123".into()],
            org_id: "org_OLD".into(),
            poll_ulid: "01JOLD".into(),
            poll_key_hex: "cafe".into(),
            poll_title: String::new(),
            option_definitions: Vec::new(),
            revocation_events_raw: Vec::new(),
        };
        let bytes = old_format.to_bytes();

        // Manually strip tags 7, 8, and 9 by encoding only fields 1-6.
        // Since poll_title, option_definitions, and revocation_events_raw
        // are empty, they won't appear in the encoded bytes. Decoding
        // should still work.
        let decoded = PollBundle::from_bytes(&bytes).expect("old-format bundle should decode");
        assert!(decoded.poll_title.is_empty());
        assert!(decoded.option_definitions.is_empty());
        assert!(decoded.revocation_events_raw.is_empty());
    }

    #[test]
    fn test_option_def_roundtrip() {
        let bundle = PollBundle {
            poll_event_raw: vec![0x01],
            vote_events_raw: Vec::new(),
            ring_member_pubs: Vec::new(),
            org_id: String::new(),
            poll_ulid: String::new(),
            poll_key_hex: String::new(),
            poll_title: "Test Title".into(),
            option_definitions: vec![
                OptionDef {
                    option_id: "a".into(),
                    option_text_zhs: "\u{8d5e}\u{6210}".into(),
                },
                OptionDef {
                    option_id: "b".into(),
                    option_text_zhs: "\u{53cd}\u{5bf9}".into(),
                },
            ],
            revocation_events_raw: Vec::new(),
        };
        let bytes = bundle.to_bytes();
        let decoded = PollBundle::from_bytes(&bytes).expect("option_def bundle should round-trip");
        assert_eq!(decoded.poll_title, "Test Title");
        assert_eq!(decoded.option_definitions.len(), 2);
        assert_eq!(decoded.option_definitions[0].option_id, "a");
        assert_eq!(
            decoded.option_definitions[0].option_text_zhs,
            "\u{8d5e}\u{6210}"
        );
        assert_eq!(decoded.option_definitions[1].option_id, "b");
    }

    #[test]
    fn test_unicode_fields_roundtrip() {
        // Verify that Unicode strings in string fields survive protobuf round-trip.
        let bundle = PollBundle {
            poll_event_raw: vec![0x01],
            vote_events_raw: Vec::new(),
            ring_member_pubs: vec!["\u{6295}\u{7968}\u{4eba}\u{516c}\u{9470}".into()],
            org_id: "\u{7ec4}\u{7ec7}_01JTEST".into(),
            poll_ulid: "\u{6295}\u{7968}_01J".into(),
            poll_key_hex: "deadbeef".into(),
            poll_title: "\u{6d4b}\u{8bd5}\u{6295}\u{7968}".into(),
            option_definitions: Vec::new(),
            revocation_events_raw: Vec::new(),
        };

        let bytes = bundle.to_bytes();
        let decoded = PollBundle::from_bytes(&bytes).expect("unicode fields should round-trip");
        assert_eq!(
            decoded.ring_member_pubs[0],
            "\u{6295}\u{7968}\u{4eba}\u{516c}\u{9470}"
        );
        assert_eq!(decoded.org_id, "\u{7ec4}\u{7ec7}_01JTEST");
        assert_eq!(decoded.poll_ulid, "\u{6295}\u{7968}_01J");
    }
}
