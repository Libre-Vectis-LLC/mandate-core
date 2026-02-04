use crate::crypto::signature::Signature;
use crate::hashing::event_hash_sha3_256;
use crate::hashing::CanonicalHashError;
use crate::ids::{ContentHash, EventId, EventUlid, OrganizationId, RingHash};
use serde::{Deserialize, Serialize};

// Submodules
mod ban;
mod message;
mod poll;
mod ring;
mod vote;

// Re-export all public types
pub use ban::{BanCreate, BanRevoke, BanScope, ProofOfInnocence};
pub use message::AnonymousMessage;
pub use poll::{Poll, PollOption, PollQuestion, PollQuestionKind};
pub use ring::{CredentialRef, IdentitySource, MemberIdentity, RingOperation, RingUpdate};
pub use vote::{Vote, VoteSelection};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Event {
    pub event_ulid: EventUlid,
    pub previous_event_hash: EventId,
    pub org_id: OrganizationId,
    /// Monotonic sequence assigned by storage; not part of content hash.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sequence_no: Option<i64>,
    pub processed_at: u64,
    pub serialization_version: u8,
    pub event_type: EventType,
    pub signature: Option<Signature>,
}

impl Event {
    /// Compute the canonical content hash of the event (excludes signature and storage metadata).
    pub fn content_hash(&self) -> Result<ContentHash, CanonicalHashError> {
        event_hash_sha3_256(self)
    }

    /// Produce the canonical bytes used for signing.
    ///
    /// Excludes the following fields from signature calculation:
    /// - `signature`: Obviously not part of its own signature
    /// - `sequence_no`: Assigned by server after event is received
    /// - `previous_event_hash`: Server handles chain integrity; allows O(n) concurrent sends
    ///
    /// Security note: Chain integrity is enforced by Party A's Edge and Bot monitoring.
    /// The server will auto-fill the correct `previous_event_hash` before storing.
    pub fn to_signing_bytes(&self) -> Result<Vec<u8>, CanonicalHashError> {
        let mut clone = self.clone();
        clone.signature = None;
        clone.sequence_no = None;
        // Exclude previous_event_hash from signature to enable server-side chain management.
        // This allows concurrent event submissions without O(n²) re-signing on ChainMismatch.
        clone.previous_event_hash = EventId([0u8; 32]);
        crate::hashing::canonical_json(&clone)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum EventType {
    PollCreate(Poll),
    VoteCast(Vote),
    MessageCreate(AnonymousMessage),
    RingUpdate(RingUpdate),
    BanCreate(BanCreate),
    BanRevoke(BanRevoke),
    ProofOfInnocence(ProofOfInnocence),
}

impl EventType {
    /// Returns the ring hash associated with this event type, if stored in the event body.
    ///
    /// For most event types, this is the `ring_hash` field.
    /// For `ProofOfInnocence`, this returns `historical_ring_hash`.
    /// For `BanRevoke`, returns `None` because the ring hash comes from the signature.
    pub fn ring_hash(&self) -> Option<RingHash> {
        match self {
            EventType::PollCreate(p) => Some(p.ring_hash),
            EventType::VoteCast(v) => Some(v.ring_hash),
            EventType::MessageCreate(m) => Some(m.ring_hash),
            EventType::RingUpdate(r) => Some(r.ring_hash),
            EventType::BanCreate(b) => Some(b.ring_hash),
            EventType::BanRevoke(_) => None,
            EventType::ProofOfInnocence(p) => Some(p.historical_ring_hash),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::ciphertext::Ciphertext;
    use crate::crypto::signature::{sign_contextual, SignatureKind, StorageMode};
    use crate::hashing::ring_hash_sha3_256;
    use crate::ids::{KeyImage, MasterPublicKey};
    use crate::test_utils::test_org_id;
    use nazgul::keypair::KeyPair;
    use nazgul::ring::Ring;
    use rand::rngs::OsRng;
    use ulid::Ulid;

    fn make_ring(size: usize) -> (KeyPair, Ring) {
        let mut csprng = OsRng;
        let signer = KeyPair::generate(&mut csprng);
        let mut members: Vec<_> = (0..size - 1)
            .map(|_| *KeyPair::generate(&mut csprng).public())
            .collect();
        members.push(*signer.public());
        (signer, Ring::new(members))
    }

    #[test]
    fn event_signature_roundtrip() {
        let (signer, ring) = make_ring(4);
        let msg = b"audit";
        let sig = sign_contextual(
            SignatureKind::Anonymous,
            StorageMode::Compact,
            &signer,
            &ring,
            msg,
        )
        .expect("sign");

        let event = Event {
            event_ulid: EventUlid(Ulid::new()),
            previous_event_hash: EventId([0u8; 32]),
            org_id: test_org_id(),
            sequence_no: Some(0),
            processed_at: 123,
            serialization_version: 1,
            event_type: EventType::MessageCreate(AnonymousMessage {
                org_id: test_org_id(),
                ring_hash: ring_hash_sha3_256(&ring),
                message_id: "m1".into(),
                content: Ciphertext(b"hello".to_vec()),
                sent_at: 123,
            }),
            signature: Some(sig),
        };

        let json = serde_json::to_string(&event).expect("serialize");
        let decoded: Event = serde_json::from_str(&json).expect("deserialize");
        let sig = decoded.signature.expect("signature present");
        assert!(sig.verify(Some(&ring), msg).expect("verify"));
    }

    #[test]
    fn poll_hash_sorts_questions_and_options() {
        let poll_unsorted = Poll {
            org_id: test_org_id(),
            ring_hash: RingHash([1u8; 32]),
            poll_id: "poll".into(),
            created_at: 1,
            instructions: None,
            deadline: None,
            questions: vec![
                PollQuestion {
                    question_id: "q2".into(),
                    title: Ciphertext(b"t2".to_vec()),
                    kind: PollQuestionKind::SingleChoice {
                        options: vec![
                            PollOption {
                                id: "b".into(),
                                text: Ciphertext(b"b".to_vec()),
                            },
                            PollOption {
                                id: "a".into(),
                                text: Ciphertext(b"a".to_vec()),
                            },
                        ],
                    },
                },
                PollQuestion {
                    question_id: "q1".into(),
                    title: Ciphertext(b"t1".to_vec()),
                    kind: PollQuestionKind::FillInTheBlank,
                },
            ],
        };

        let mut poll_sorted = poll_unsorted.clone();
        poll_sorted
            .questions
            .sort_by(|a, b| a.question_id.cmp(&b.question_id));
        if let PollQuestionKind::SingleChoice { options } = &mut poll_sorted.questions[1].kind {
            options.sort_by(|a, b| a.id.cmp(&b.id));
        }

        let h1 = poll_unsorted.hash().expect("hash unsorted");
        let h2 = poll_sorted.hash().expect("hash sorted");
        assert_eq!(h1, h2, "poll hash must be independent of ID ordering");
    }

    #[test]
    fn vote_hash_sorts_selections_and_option_ids() {
        let vote_unsorted = Vote {
            org_id: test_org_id(),
            ring_hash: RingHash([2u8; 32]),
            poll_id: "p".into(),
            poll_hash: ContentHash([3u8; 32]),
            poll_ring_hash: RingHash([2u8; 32]),
            selections: vec![
                VoteSelection {
                    question_id: "q2".into(),
                    option_ids: vec!["b".into(), "a".into()],
                    write_in: None,
                },
                VoteSelection {
                    question_id: "q1".into(),
                    option_ids: vec!["y".into(), "x".into()],
                    write_in: Some(Ciphertext(b"w".to_vec())),
                },
            ],
        };

        let mut vote_sorted = vote_unsorted.clone();
        vote_sorted
            .selections
            .sort_by(|a, b| a.question_id.cmp(&b.question_id));
        vote_sorted
            .selections
            .iter_mut()
            .for_each(|s| s.option_ids.sort());

        let h1 = vote_unsorted.hash().expect("hash unsorted");
        let h2 = vote_sorted.hash().expect("hash sorted");
        assert_eq!(h1, h2, "vote hash must be independent of ID ordering");
    }

    #[test]
    fn event_hash_ignores_signature_field() {
        let (signer, ring) = make_ring(3);
        let base_event = Event {
            event_ulid: EventUlid(Ulid::new()),
            previous_event_hash: EventId([8u8; 32]),
            org_id: test_org_id(),
            sequence_no: Some(1),
            processed_at: 10,
            serialization_version: 1,
            event_type: EventType::MessageCreate(AnonymousMessage {
                org_id: test_org_id(),
                ring_hash: RingHash([7u8; 32]),
                message_id: "m".into(),
                content: Ciphertext(b"hi".to_vec()),
                sent_at: 10,
            }),
            signature: None,
        };

        let mut signed = base_event.clone();
        let sig = sign_contextual(
            SignatureKind::Anonymous,
            StorageMode::Compact,
            &signer,
            &ring,
            b"msg",
        )
        .expect("sign");
        signed.signature = Some(sig);

        let h_base = base_event.content_hash().expect("hash base");
        let h_signed = signed.content_hash().expect("hash signed");
        assert_eq!(h_base, h_signed, "signature must not affect content hash");
    }

    #[test]
    fn event_hash_ignores_sequence_no_field() {
        let base_event = Event {
            event_ulid: EventUlid(Ulid::new()),
            previous_event_hash: EventId([9u8; 32]),
            org_id: test_org_id(),
            sequence_no: None,
            processed_at: 42,
            serialization_version: 1,
            event_type: EventType::MessageCreate(AnonymousMessage {
                org_id: test_org_id(),
                ring_hash: RingHash([7u8; 32]),
                message_id: "m".into(),
                content: Ciphertext(b"hi".to_vec()),
                sent_at: 42,
            }),
            signature: None,
        };

        let mut with_sequence = base_event.clone();
        with_sequence.sequence_no = Some(123);

        let h_base = base_event.content_hash().expect("hash base");
        let h_seq = with_sequence.content_hash().expect("hash with sequence");
        assert_eq!(h_base, h_seq, "sequence_no must not affect content hash");
    }

    #[test]
    fn event_type_ring_hash_extraction() {
        let ring_hash = RingHash([42u8; 32]);
        let historical_hash = RingHash([99u8; 32]);
        let org = test_org_id();

        // Test each event type returns correct ring_hash
        let poll = EventType::PollCreate(Poll {
            org_id: org,
            ring_hash,
            poll_id: "p1".into(),
            questions: vec![],
            created_at: 1,
            instructions: None,
            deadline: None,
        });
        assert_eq!(poll.ring_hash(), Some(ring_hash));

        let vote = EventType::VoteCast(Vote {
            org_id: org,
            ring_hash,
            poll_id: "p1".into(),
            poll_hash: ContentHash([0u8; 32]),
            poll_ring_hash: ring_hash,
            selections: vec![],
        });
        assert_eq!(vote.ring_hash(), Some(ring_hash));

        let msg = EventType::MessageCreate(AnonymousMessage {
            org_id: org,
            ring_hash,
            message_id: "m1".into(),
            content: Ciphertext(b"test".to_vec()),
            sent_at: 1,
        });
        assert_eq!(msg.ring_hash(), Some(ring_hash));

        let ring_update = EventType::RingUpdate(RingUpdate {
            org_id: org,
            ring_hash,
            operations: vec![],
        });
        assert_eq!(ring_update.ring_hash(), Some(ring_hash));

        let ban_create = EventType::BanCreate(BanCreate {
            org_id: org,
            ring_hash,
            target: KeyImage::default(),
            reason: "test".into(),
            scope: BanScope::BanAll,
        });
        assert_eq!(ban_create.ring_hash(), Some(ring_hash));

        let ban_revoke = EventType::BanRevoke(BanRevoke {
            org_id: org,
            ban_event_id: EventId([0u8; 32]),
        });
        assert_eq!(ban_revoke.ring_hash(), None);

        // ProofOfInnocence uses historical_ring_hash
        let proof = EventType::ProofOfInnocence(ProofOfInnocence {
            org_id: org,
            historical_ring_hash: historical_hash,
        });
        assert_eq!(proof.ring_hash(), Some(historical_hash));
    }

    #[test]
    fn signing_bytes_excludes_previous_event_hash() {
        // Two events identical except for previous_event_hash
        let event1 = Event {
            event_ulid: EventUlid(Ulid::from_string("01ARYZ6S41TSV4RRFFQ69G5FAV").unwrap()),
            previous_event_hash: EventId([1u8; 32]),
            org_id: test_org_id(),
            sequence_no: None,
            processed_at: 100,
            serialization_version: 1,
            event_type: EventType::MessageCreate(AnonymousMessage {
                org_id: test_org_id(),
                ring_hash: RingHash([7u8; 32]),
                message_id: "m1".into(),
                content: Ciphertext(b"test message".to_vec()),
                sent_at: 100,
            }),
            signature: None,
        };

        let mut event2 = event1.clone();
        event2.previous_event_hash = EventId([2u8; 32]);

        let bytes1 = event1.to_signing_bytes().expect("signing bytes 1");
        let bytes2 = event2.to_signing_bytes().expect("signing bytes 2");

        assert_eq!(
            bytes1, bytes2,
            "Different previous_event_hash should produce identical signing bytes"
        );
    }

    // Backward compatibility tests for RingOperation serialization

    #[test]
    fn test_ring_operation_deserialize_legacy_format_no_identity() {
        // Old format: AddMember without identity field
        // This simulates data persisted before the identity field was added
        let json = r#"{
            "AddMember": {
                "public_key": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
            }
        }"#;

        let op: RingOperation = serde_json::from_str(json).expect("should deserialize");

        match op {
            RingOperation::AddMember {
                public_key,
                identity,
            } => {
                // Verify public key deserialized correctly
                assert_eq!(public_key.0, [0u8; 32]);

                // Verify identity defaults to legacy()
                assert_eq!(identity.source, IdentitySource::Telegram);
                assert!(identity.external_id.is_none());
                assert!(identity.display_name.is_none());
                assert!(identity.credential_ref.is_none());
            }
            _ => panic!("expected AddMember"),
        }
    }

    #[test]
    fn test_ring_operation_roundtrip_with_identity() {
        // New format with full identity metadata
        let identity = MemberIdentity {
            external_id: Some("123456".to_string()),
            display_name: Some("Alice".to_string()),
            credential_ref: None,
            source: IdentitySource::Standalone,
        };

        let op = RingOperation::AddMember {
            public_key: MasterPublicKey([42u8; 32]),
            identity: identity.clone(),
        };

        // Serialize and deserialize
        let json = serde_json::to_string(&op).expect("should serialize");
        let deserialized: RingOperation = serde_json::from_str(&json).expect("should deserialize");

        match deserialized {
            RingOperation::AddMember {
                public_key,
                identity: id,
            } => {
                assert_eq!(public_key.0, [42u8; 32]);
                assert_eq!(id.external_id, Some("123456".to_string()));
                assert_eq!(id.display_name, Some("Alice".to_string()));
                assert_eq!(id.source, IdentitySource::Standalone);
            }
            _ => panic!("expected AddMember"),
        }
    }

    #[test]
    fn test_ring_operation_remove_member_unchanged() {
        // Verify RemoveMember works as before (no identity field)
        let op = RingOperation::RemoveMember {
            public_key: MasterPublicKey([99u8; 32]),
        };

        let json = serde_json::to_string(&op).expect("should serialize");
        let deserialized: RingOperation = serde_json::from_str(&json).expect("should deserialize");

        match deserialized {
            RingOperation::RemoveMember { public_key } => {
                assert_eq!(public_key.0, [99u8; 32]);
            }
            _ => panic!("expected RemoveMember"),
        }
    }

    #[test]
    fn test_member_identity_telegram_constructor() {
        let id = MemberIdentity::telegram("12345".to_string(), Some("alice".to_string()));

        assert_eq!(id.external_id, Some("12345".to_string()));
        assert_eq!(id.display_name, Some("alice".to_string()));
        assert_eq!(id.source, IdentitySource::Telegram);
        assert!(id.credential_ref.is_none());
    }

    #[test]
    fn test_member_identity_telegram_constructor_no_username() {
        let id = MemberIdentity::telegram("67890".to_string(), None);

        assert_eq!(id.external_id, Some("67890".to_string()));
        assert!(id.display_name.is_none());
        assert_eq!(id.source, IdentitySource::Telegram);
    }

    #[test]
    fn test_member_identity_standalone_constructor() {
        let id = MemberIdentity::standalone(
            "01ARZ3NDEKTSV4RRFFQ69G5FAV".to_string(),
            Some("Bob".to_string()),
        );

        assert_eq!(
            id.external_id,
            Some("01ARZ3NDEKTSV4RRFFQ69G5FAV".to_string())
        );
        assert_eq!(id.display_name, Some("Bob".to_string()));
        assert_eq!(id.source, IdentitySource::Standalone);
        assert!(id.credential_ref.is_none());
    }

    #[test]
    fn test_member_identity_standalone_constructor_minimal() {
        // Standalone identity with only user_id
        let id = MemberIdentity::standalone("01ARZ3NDEKTSV4RRFFQ69G5FAV".to_string(), None);

        assert_eq!(
            id.external_id,
            Some("01ARZ3NDEKTSV4RRFFQ69G5FAV".to_string())
        );
        assert!(id.display_name.is_none());
        assert_eq!(id.source, IdentitySource::Standalone);
    }

    #[test]
    fn test_member_identity_legacy_constructor() {
        let id = MemberIdentity::legacy();

        assert!(id.external_id.is_none());
        assert!(id.display_name.is_none());
        assert!(id.credential_ref.is_none());
        assert_eq!(id.source, IdentitySource::Telegram);
    }

    #[test]
    fn test_ring_operation_with_credential_ref() {
        // Test AddMember with verified credential
        let credential = CredentialRef {
            credential_id: "01CRED123456789".to_string(),
            credential_type: "government_id".to_string(),
            verified_at: 1704067200000, // 2024-01-01 00:00:00 UTC
        };

        let identity = MemberIdentity {
            external_id: Some("user123".to_string()),
            display_name: Some("Charlie".to_string()),
            credential_ref: Some(credential.clone()),
            source: IdentitySource::Standalone,
        };

        let op = RingOperation::AddMember {
            public_key: MasterPublicKey([77u8; 32]),
            identity,
        };

        // Serialize and deserialize
        let json = serde_json::to_string(&op).expect("should serialize");
        let deserialized: RingOperation = serde_json::from_str(&json).expect("should deserialize");

        match deserialized {
            RingOperation::AddMember { identity, .. } => {
                let cred = identity.credential_ref.expect("credential should exist");
                assert_eq!(cred.credential_id, "01CRED123456789");
                assert_eq!(cred.credential_type, "government_id");
                assert_eq!(cred.verified_at, 1704067200000);
            }
            _ => panic!("expected AddMember"),
        }
    }

    #[test]
    fn test_ring_update_signature_covers_identity_field() {
        // Test that changing identity field invalidates the signature
        // This ensures the signature covers the identity field and prevents tampering

        let (signer, ring) = make_ring(3);
        let org = test_org_id();
        let ring_hash = ring_hash_sha3_256(&ring);

        let identity1 = MemberIdentity::telegram("12345".to_string(), Some("alice".to_string()));
        let identity2 = MemberIdentity::standalone("user789".to_string(), Some("bob".to_string()));

        // Create event with identity1 and sign it
        let mut event = Event {
            event_ulid: EventUlid(Ulid::from_string("01ARYZ6S41TSV4RRFFQ69G5FAV").unwrap()),
            previous_event_hash: EventId([0u8; 32]),
            org_id: org,
            sequence_no: None,
            processed_at: 100,
            serialization_version: 1,
            event_type: EventType::RingUpdate(RingUpdate {
                org_id: org,
                ring_hash,
                operations: vec![RingOperation::AddMember {
                    public_key: MasterPublicKey([42u8; 32]),
                    identity: identity1,
                }],
            }),
            signature: None,
        };

        // Sign the event with identity1
        let signing_bytes = event.to_signing_bytes().expect("signing bytes");
        let sig = sign_contextual(
            SignatureKind::Authoritative,
            StorageMode::Compact,
            &signer,
            &ring,
            &signing_bytes,
        )
        .expect("sign event");
        event.signature = Some(sig.clone());

        // Modify the identity to identity2
        if let EventType::RingUpdate(ref mut ru) = event.event_type {
            ru.operations[0] = RingOperation::AddMember {
                public_key: MasterPublicKey([42u8; 32]),
                identity: identity2,
            };
        }

        // Verify that the signature is now invalid for the modified event
        let modified_signing_bytes = event.to_signing_bytes().expect("modified signing bytes");
        let verification_result = sig.verify(Some(&ring), &modified_signing_bytes);

        assert!(
            verification_result.is_ok() && !verification_result.unwrap(),
            "Signature should be invalid after identity modification (signature must cover identity field)"
        );
    }

    #[test]
    fn test_ring_update_signature_covers_identity_changes() {
        // Test that modifying different fields of identity invalidates the signature
        // This is a more granular test to ensure all identity fields are covered

        let (signer, ring) = make_ring(3);
        let org = test_org_id();
        let ring_hash = ring_hash_sha3_256(&ring);

        let base_identity =
            MemberIdentity::standalone("user123".to_string(), Some("Alice".to_string()));

        let create_event = |identity: MemberIdentity| -> Event {
            Event {
                event_ulid: EventUlid(Ulid::from_string("01ARYZ6S41TSV4RRFFQ69G5FAV").unwrap()),
                previous_event_hash: EventId([0u8; 32]),
                org_id: org,
                sequence_no: None,
                processed_at: 100,
                serialization_version: 1,
                event_type: EventType::RingUpdate(RingUpdate {
                    org_id: org,
                    ring_hash,
                    operations: vec![RingOperation::AddMember {
                        public_key: MasterPublicKey([42u8; 32]),
                        identity,
                    }],
                }),
                signature: None,
            }
        };

        // Create and sign the base event
        let base_event = create_event(base_identity.clone());
        let base_bytes = base_event.to_signing_bytes().expect("base signing bytes");
        let base_sig = sign_contextual(
            SignatureKind::Authoritative,
            StorageMode::Compact,
            &signer,
            &ring,
            &base_bytes,
        )
        .expect("sign base event");

        // Test 1: Change external_id
        let mut modified = base_identity.clone();
        modified.external_id = Some("different_id".to_string());
        let modified_event = create_event(modified);
        let modified_bytes = modified_event
            .to_signing_bytes()
            .expect("modified external_id");
        let result = base_sig.verify(Some(&ring), &modified_bytes);
        assert!(
            result.is_ok() && !result.unwrap(),
            "Signature should be invalid after changing external_id"
        );

        // Test 2: Change display_name
        let mut modified = base_identity.clone();
        modified.display_name = Some("Bob".to_string());
        let modified_event = create_event(modified);
        let modified_bytes = modified_event
            .to_signing_bytes()
            .expect("modified display_name");
        let result = base_sig.verify(Some(&ring), &modified_bytes);
        assert!(
            result.is_ok() && !result.unwrap(),
            "Signature should be invalid after changing display_name"
        );

        // Test 3: Change source
        let mut modified = base_identity.clone();
        modified.source = IdentitySource::Telegram;
        let modified_event = create_event(modified);
        let modified_bytes = modified_event.to_signing_bytes().expect("modified source");
        let result = base_sig.verify(Some(&ring), &modified_bytes);
        assert!(
            result.is_ok() && !result.unwrap(),
            "Signature should be invalid after changing source"
        );
    }
}
