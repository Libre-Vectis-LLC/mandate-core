use crate::ids::{MasterPublicKey, OrganizationId, RingHash};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RingUpdate {
    pub org_id: OrganizationId,
    pub ring_hash: RingHash,
    pub operations: Vec<RingOperation>,
}

/// Reference to a verified credential
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CredentialRef {
    /// Credential ID (ULID format)
    pub credential_id: String,
    /// Credential type: "government_id", "org_membership", "custom", etc.
    pub credential_type: String,
    /// Unix timestamp (milliseconds) when verified
    pub verified_at: u64,
}

/// Identity source - how the member was onboarded
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum IdentitySource {
    /// Telegram-based identity (default for backward compatibility)
    #[default]
    Telegram,
    /// Standalone mode identity (invite-based registration)
    Standalone,
    /// Other identity sources for extensibility
    Other(String),
}

/// Unified member identity metadata
/// Embedded in RingOperation::AddMember, covered by signature
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MemberIdentity {
    /// External identity identifier
    /// - Telegram: tg_user_id (e.g., "123456789")
    /// - Standalone: standalone_user_id (ULID)
    pub external_id: Option<String>,

    /// Display name
    /// - Telegram: tg_username
    /// - Standalone: user-defined name
    pub display_name: Option<String>,

    /// Credential reference (if verified)
    pub credential_ref: Option<CredentialRef>,

    /// Identity source (required)
    pub source: IdentitySource,
}

impl MemberIdentity {
    /// Create legacy identity for backward compatibility with old data
    /// Old RingOperation::AddMember events had no identity field
    pub fn legacy() -> Self {
        MemberIdentity {
            external_id: None,
            display_name: None,
            credential_ref: None,
            source: IdentitySource::Telegram, // Old data was all Telegram
        }
    }

    /// Create a Telegram identity
    pub fn telegram(tg_user_id: impl Into<String>, tg_username: Option<String>) -> Self {
        MemberIdentity {
            external_id: Some(tg_user_id.into()),
            display_name: tg_username,
            credential_ref: None,
            source: IdentitySource::Telegram,
        }
    }

    /// Create a Standalone identity
    pub fn standalone(user_id: impl Into<String>, display_name: Option<String>) -> Self {
        MemberIdentity {
            external_id: Some(user_id.into()),
            display_name,
            credential_ref: None,
            source: IdentitySource::Standalone,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RingOperation {
    /// Add a member to the ring
    AddMember {
        /// Member's Nazgul master public key
        public_key: MasterPublicKey,
        /// Member identity metadata (required)
        /// For backward compatibility, old events without identity field
        /// will deserialize with MemberIdentity::legacy()
        #[serde(default = "MemberIdentity::legacy")]
        identity: MemberIdentity,
    },
    /// Remove a member from the ring
    RemoveMember {
        /// Member's Nazgul master public key
        public_key: MasterPublicKey,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to create a test public key
    fn test_public_key() -> MasterPublicKey {
        MasterPublicKey([1u8; 32])
    }

    /// Helper to create a second test public key (different from first)
    fn test_public_key_2() -> MasterPublicKey {
        MasterPublicKey([2u8; 32])
    }

    #[test]
    fn test_ring_operation_old_format_deserialize() {
        // Old format: AddMember without identity field
        let old_json = r#"{
            "AddMember": {
                "public_key": [1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]
            }
        }"#;

        let operation: RingOperation =
            serde_json::from_str(old_json).expect("Should deserialize old format successfully");

        match operation {
            RingOperation::AddMember {
                public_key,
                identity,
            } => {
                assert_eq!(public_key, test_public_key());
                // Should default to legacy identity
                assert_eq!(identity, MemberIdentity::legacy());
                assert_eq!(identity.source, IdentitySource::Telegram);
                assert!(identity.external_id.is_none());
                assert!(identity.display_name.is_none());
                assert!(identity.credential_ref.is_none());
            }
            _ => panic!("Expected AddMember variant"),
        }
    }

    #[test]
    fn test_ring_operation_new_format_roundtrip() {
        // Test Telegram identity
        let telegram_op = RingOperation::AddMember {
            public_key: test_public_key(),
            identity: MemberIdentity::telegram("123456789", Some("alice".to_string())),
        };

        let json = serde_json::to_string(&telegram_op).expect("Should serialize");
        let deserialized: RingOperation = serde_json::from_str(&json).expect("Should deserialize");
        assert_eq!(telegram_op, deserialized);

        // Test Standalone identity
        let standalone_op = RingOperation::AddMember {
            public_key: test_public_key_2(),
            identity: MemberIdentity::standalone(
                "01HN12J345678M9ABCDEFGHJK0".to_string(),
                Some("Bob".to_string()),
            ),
        };

        let json = serde_json::to_string(&standalone_op).expect("Should serialize");
        let deserialized: RingOperation = serde_json::from_str(&json).expect("Should deserialize");
        assert_eq!(standalone_op, deserialized);

        // Verify identity fields are preserved
        if let RingOperation::AddMember { identity, .. } = deserialized {
            assert_eq!(identity.source, IdentitySource::Standalone);
            assert_eq!(
                identity.external_id,
                Some("01HN12J345678M9ABCDEFGHJK0".to_string())
            );
            assert_eq!(identity.display_name, Some("Bob".to_string()));
        } else {
            panic!("Expected AddMember variant");
        }
    }

    #[test]
    fn test_ring_operation_identity_serializes_all_fields() {
        // Create identity with all fields including credential_ref
        let credential = CredentialRef {
            credential_id: "01HN12J345678M9ABCDEFGHJK0".to_string(),
            credential_type: "government_id".to_string(),
            verified_at: 1704067200000, // 2024-01-01 00:00:00 UTC
        };

        let mut identity = MemberIdentity::standalone(
            "01HN12J345678M9ABCDEFGHJK1".to_string(),
            Some("Carol".to_string()),
        );
        identity.credential_ref = Some(credential.clone());

        let operation = RingOperation::AddMember {
            public_key: test_public_key(),
            identity: identity.clone(),
        };

        let json = serde_json::to_string_pretty(&operation).expect("Should serialize");

        // Verify all fields are present in JSON
        assert!(json.contains("\"external_id\""));
        assert!(json.contains("\"01HN12J345678M9ABCDEFGHJK1\""));
        assert!(json.contains("\"display_name\""));
        assert!(json.contains("\"Carol\""));
        assert!(json.contains("\"credential_ref\""));
        assert!(json.contains("\"credential_id\""));
        assert!(json.contains("\"01HN12J345678M9ABCDEFGHJK0\""));
        assert!(json.contains("\"credential_type\""));
        assert!(json.contains("\"government_id\""));
        assert!(json.contains("\"verified_at\""));
        assert!(json.contains("1704067200000"));
        assert!(json.contains("\"source\""));
        assert!(json.contains("\"Standalone\""));

        // Roundtrip test
        let deserialized: RingOperation = serde_json::from_str(&json).expect("Should deserialize");
        assert_eq!(operation, deserialized);

        // Verify credential_ref is preserved
        if let RingOperation::AddMember { identity, .. } = deserialized {
            assert!(identity.credential_ref.is_some());
            let cred = identity.credential_ref.unwrap();
            assert_eq!(cred.credential_id, credential.credential_id);
            assert_eq!(cred.credential_type, credential.credential_type);
            assert_eq!(cred.verified_at, credential.verified_at);
        } else {
            panic!("Expected AddMember variant");
        }
    }

    #[test]
    fn test_remove_member_unchanged() {
        // RemoveMember should work as before (no identity field)
        let operation = RingOperation::RemoveMember {
            public_key: test_public_key(),
        };

        let json = serde_json::to_string(&operation).expect("Should serialize");
        let deserialized: RingOperation = serde_json::from_str(&json).expect("Should deserialize");

        assert_eq!(operation, deserialized);

        // Verify it only has public_key field
        assert!(json.contains("\"RemoveMember\""));
        assert!(json.contains("\"public_key\""));
        assert!(!json.contains("\"identity\""));
    }

    #[test]
    fn test_identity_source_variants() {
        // Test all IdentitySource variants serialize/deserialize correctly
        let telegram = IdentitySource::Telegram;
        let standalone = IdentitySource::Standalone;
        let other = IdentitySource::Other("github".to_string());

        let telegram_json = serde_json::to_string(&telegram).expect("Should serialize");
        let standalone_json = serde_json::to_string(&standalone).expect("Should serialize");
        let other_json = serde_json::to_string(&other).expect("Should serialize");

        assert_eq!(telegram_json, "\"Telegram\"");
        assert_eq!(standalone_json, "\"Standalone\"");
        assert!(other_json.contains("\"Other\""));
        assert!(other_json.contains("\"github\""));

        // Roundtrip
        let deserialized: IdentitySource =
            serde_json::from_str(&telegram_json).expect("Should deserialize");
        assert_eq!(deserialized, telegram);

        let deserialized: IdentitySource =
            serde_json::from_str(&standalone_json).expect("Should deserialize");
        assert_eq!(deserialized, standalone);

        let deserialized: IdentitySource =
            serde_json::from_str(&other_json).expect("Should deserialize");
        assert_eq!(deserialized, other);
    }

    #[test]
    fn test_member_identity_default() {
        // Test that IdentitySource::Telegram is the default
        let identity: IdentitySource = Default::default();
        assert_eq!(identity, IdentitySource::Telegram);
    }

    #[test]
    fn test_ring_operation_identity_affects_signature_bytes() {
        // Create two RingOperations with same public_key but different identity fields
        let public_key = test_public_key();

        let op1 = RingOperation::AddMember {
            public_key,
            identity: MemberIdentity::telegram("user1", Some("alice".to_string())),
        };

        let op2 = RingOperation::AddMember {
            public_key,
            identity: MemberIdentity::telegram("user2", Some("bob".to_string())),
        };

        // Serialize both to JSON (which is used for signing via canonical_json)
        let json1 = serde_json::to_string(&op1).expect("Should serialize op1");
        let json2 = serde_json::to_string(&op2).expect("Should serialize op2");

        // The serialized bytes MUST be different because identity differs
        assert_ne!(
            json1, json2,
            "Different identity fields must produce different serialized bytes"
        );

        // Verify the difference is due to identity, not public_key
        assert!(json1.contains("\"user1\""));
        assert!(json1.contains("\"alice\""));
        assert!(json2.contains("\"user2\""));
        assert!(json2.contains("\"bob\""));
    }

    #[test]
    fn test_identity_source_other_roundtrip() {
        // Test IdentitySource::Other(String) variant roundtrip
        let mut identity = MemberIdentity::legacy();
        identity.source = IdentitySource::Other("custom_source".to_string());
        identity.external_id = Some("custom_id_123".to_string());
        identity.display_name = Some("Custom User".to_string());

        let operation = RingOperation::AddMember {
            public_key: test_public_key(),
            identity: identity.clone(),
        };

        // Serialize to JSON
        let json = serde_json::to_string(&operation).expect("Should serialize");

        // Verify JSON contains the custom source
        assert!(json.contains("\"Other\""));
        assert!(json.contains("\"custom_source\""));

        // Deserialize back
        let deserialized: RingOperation = serde_json::from_str(&json).expect("Should deserialize");

        // Verify fields match
        if let RingOperation::AddMember {
            identity: deserialized_identity,
            ..
        } = deserialized
        {
            assert_eq!(
                deserialized_identity.source,
                IdentitySource::Other("custom_source".to_string())
            );
            assert_eq!(
                deserialized_identity.external_id,
                Some("custom_id_123".to_string())
            );
            assert_eq!(
                deserialized_identity.display_name,
                Some("Custom User".to_string())
            );
        } else {
            panic!("Expected AddMember variant");
        }
    }

    #[test]
    fn test_ring_operation_empty_optional_fields() {
        // Create MemberIdentity with all optional fields as None
        let identity = MemberIdentity {
            external_id: None,
            display_name: None,
            credential_ref: None,
            source: IdentitySource::Standalone, // Only required field
        };

        let operation = RingOperation::AddMember {
            public_key: test_public_key(),
            identity: identity.clone(),
        };

        // Verify serialization works
        let json = serde_json::to_string(&operation).expect("Should serialize");

        // Verify deserialization works
        let deserialized: RingOperation = serde_json::from_str(&json).expect("Should deserialize");

        // Verify comparison works (PartialEq)
        assert_eq!(operation, deserialized);

        // Verify all None fields are preserved
        if let RingOperation::AddMember {
            identity: deserialized_identity,
            ..
        } = deserialized
        {
            assert!(deserialized_identity.external_id.is_none());
            assert!(deserialized_identity.display_name.is_none());
            assert!(deserialized_identity.credential_ref.is_none());
            assert_eq!(deserialized_identity.source, IdentitySource::Standalone);
        } else {
            panic!("Expected AddMember variant");
        }
    }
}
