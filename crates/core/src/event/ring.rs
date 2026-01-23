use crate::ids::{GroupId, MasterPublicKey, RingHash};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RingUpdate {
    pub group_id: GroupId,
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

    /// Organization internal ID (applicable to both modes)
    pub organization_id: Option<String>,

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
            organization_id: None,
            credential_ref: None,
            source: IdentitySource::Telegram, // Old data was all Telegram
        }
    }

    /// Create a Telegram identity
    pub fn telegram(tg_user_id: impl Into<String>, tg_username: Option<String>) -> Self {
        MemberIdentity {
            external_id: Some(tg_user_id.into()),
            display_name: tg_username,
            organization_id: None,
            credential_ref: None,
            source: IdentitySource::Telegram,
        }
    }

    /// Create a Standalone identity
    pub fn standalone(
        user_id: impl Into<String>,
        display_name: Option<String>,
        organization_id: Option<String>,
    ) -> Self {
        MemberIdentity {
            external_id: Some(user_id.into()),
            display_name,
            organization_id,
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
