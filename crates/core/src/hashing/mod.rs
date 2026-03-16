//! Hashing helpers for mandate content hashes and protocol digests.
//!
//! - Default 256-bit digest: SHA3-256.
//! - Default 64-byte protocol digest: BLAKE3-XOF-512.
//! - Provides helpers for raw bytes, ciphertexts, and ring consensus hashes
//!   using nazgul's `Ring::consensus_hash`.

mod blake3;
pub mod canonical;
pub mod event_hashing;
pub mod primitives;

// Re-export public API
pub use blake3::Blake3_512;
pub use canonical::{canonical_content_hash_sha3_256, canonical_json, CanonicalHashError};
pub use event_hashing::{event_hash_sha3_256, poll_hash_sha3_256, vote_hash_sha3_256};
pub use primitives::{
    blake3_512_bytes, content_hash_bytes, content_hash_ciphertext, domain, ring_hash,
    sha3_256_bytes, Blake3_512Digest, DigestAlgorithm, Hash256, Hash512, Sha3_256Digest,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::ciphertext::Ciphertext;
    use crate::test_utils::test_org_id;
    use curve25519_dalek::ristretto::RistrettoPoint;
    use hex::encode;
    use nazgul::ring::{Ring, RingHash};
    use proptest::prelude::*;
    use serde::Serialize;
    use serde_json::Value;
    fn point(label: &[u8]) -> RistrettoPoint {
        RistrettoPoint::hash_from_bytes::<Blake3_512>(label)
    }

    #[test]
    fn sha3_256_deterministic() {
        let h1 = sha3_256_bytes(b"mandate");
        let h2 = sha3_256_bytes(b"mandate");
        assert_eq!(h1, h2);
    }

    #[test]
    fn ring_hash_order_invariant() {
        let p1 = point(b"member-1");
        let p2 = point(b"member-2");
        let p3 = point(b"member-3");

        let ring_a = Ring::new(vec![p1, p2, p3]);
        let ring_b = Ring::new(vec![p3, p1, p2]);

        let ha = ring_hash(&ring_a);
        let hb = ring_hash(&ring_b);

        assert_eq!(ha, hb, "ring hash should be independent of input order");
    }

    #[test]
    fn content_hash_ciphertext_matches_bytes() {
        let payload = b"sealed".to_vec();
        let ct = Ciphertext(payload.clone());
        assert_eq!(
            content_hash_ciphertext(&ct).0,
            content_hash_bytes(&payload).0
        );
    }

    #[derive(Serialize)]
    struct DemoObj {
        b: u8,
        a: u8,
    }

    #[test]
    fn canonical_json_sorts_keys_and_hashes() {
        let obj1 = DemoObj { a: 1, b: 2 };
        let obj2 = DemoObj { b: 2, a: 1 };

        let j1 = canonical_json(&obj1).expect("json");
        let j2 = canonical_json(&obj2).expect("json");
        assert_eq!(j1, j2, "canonical JSON must be order independent");

        let h1 = canonical_content_hash_sha3_256(domain::EVENT, &obj1).expect("hash");
        let h2 = canonical_content_hash_sha3_256(domain::EVENT, &obj2).expect("hash");
        assert_eq!(h1, h2, "hash should ignore map insertion order");
    }

    #[test]
    fn domain_separation_alters_hash() {
        let obj = DemoObj { a: 7, b: 9 };
        let h_event =
            canonical_content_hash_sha3_256(domain::EVENT, &obj).expect("hash event domain");
        let h_poll = canonical_content_hash_sha3_256(domain::POLL, &obj).expect("hash poll domain");
        assert_ne!(h_event, h_poll, "domain separator must change digest");
    }

    #[derive(Serialize)]
    struct WithArray {
        items: Vec<u8>,
    }

    #[test]
    fn arrays_preserve_order() {
        let ascending = WithArray {
            items: vec![1, 2, 3],
        };
        let descending = WithArray {
            items: vec![3, 2, 1],
        };

        let h1 = canonical_content_hash_sha3_256(domain::EVENT, &ascending).expect("hash");
        let h2 = canonical_content_hash_sha3_256(domain::EVENT, &descending).expect("hash");
        assert_ne!(h1, h2, "array order must remain significant");
    }

    proptest! {
        #[test]
        fn canonical_json_order_invariant_prop(kvs in prop::collection::hash_map("[a-z]{1,6}", 0u8..16u8, 1..8)) {
            // Build two maps with different insertion orders but same entries.
            let mut map_a = serde_json::Map::new();
            for (k, v) in kvs.iter() {
                map_a.insert(k.clone(), Value::from(*v as u64));
            }
            let mut keys: Vec<_> = kvs.keys().cloned().collect();
            keys.reverse();
            let mut map_b = serde_json::Map::new();
            for k in keys {
                let v = kvs.get(&k).unwrap();
                map_b.insert(k.clone(), Value::from(*v as u64));
            }

            let a = canonical_json(&Value::Object(map_a)).expect("canon a");
            let b = canonical_json(&Value::Object(map_b)).expect("canon b");
            prop_assert_eq!(a, b);
        }

        /// Property: SHA3-256 hash is deterministic.
        /// The same input bytes always produce the same hash output.
        #[test]
        fn prop_sha3_256_deterministic(data in prop::collection::vec(any::<u8>(), 0..1024)) {
            let hash1 = sha3_256_bytes(&data);
            let hash2 = sha3_256_bytes(&data);
            prop_assert_eq!(hash1, hash2);
        }

        /// Property: BLAKE3-XOF-512 hash is deterministic.
        /// The same input bytes always produce the same hash output.
        #[test]
        fn prop_blake3_512_deterministic(data in prop::collection::vec(any::<u8>(), 0..1024)) {
            let hash1 = blake3_512_bytes(&data);
            let hash2 = blake3_512_bytes(&data);
            prop_assert_eq!(hash1, hash2);
        }

        /// Property: Different inputs produce different hashes (collision resistance).
        /// Two different input bytes should produce different hashes with very high probability.
        #[test]
        fn prop_sha3_256_collision_resistance(
            data1 in prop::collection::vec(any::<u8>(), 1..512),
            data2 in prop::collection::vec(any::<u8>(), 1..512),
        ) {
            prop_assume!(data1 != data2);
            let hash1 = sha3_256_bytes(&data1);
            let hash2 = sha3_256_bytes(&data2);
            prop_assert_ne!(hash1, hash2);
        }

        /// Property: Content hash for ciphertext matches hash of raw bytes.
        /// Hashing a ciphertext should be equivalent to hashing its underlying bytes.
        #[test]
        fn prop_content_hash_ciphertext_consistency(
            payload in prop::collection::vec(any::<u8>(), 0..512),
        ) {
            let ciphertext = Ciphertext(payload.clone());
            let hash_ct = content_hash_ciphertext(&ciphertext);
            let hash_bytes = content_hash_bytes(&payload);
            prop_assert_eq!(hash_ct, hash_bytes);
        }

        /// Property: Ring hash is deterministic for the same ring.
        /// Computing ring hash multiple times for the same ring yields identical results.
        #[test]
        fn prop_ring_hash_deterministic(ring_size in 2usize..20) {
            let mut members = Vec::new();
            for i in 0..ring_size {
                let label = format!("member-{i}");
                members.push(point(label.as_bytes()));
            }
            let ring = Ring::new(members);

            let hash1 = ring_hash(&ring);
            let hash2 = ring_hash(&ring);

            prop_assert_eq!(hash1, hash2);
        }

        /// Property: Canonical JSON hashing is order-invariant for objects.
        /// Objects with the same key-value pairs but different insertion orders
        /// should hash to the same value.
        #[test]
        fn prop_canonical_hash_order_invariant(
            kvs in prop::collection::hash_map("[a-z]{1,8}", 0u32..1000u32, 1..10),
        ) {
            use serde_json::json;

            // Create two JSON objects with different insertion orders
            let mut obj1 = serde_json::Map::new();
            for (k, v) in kvs.iter() {
                obj1.insert(k.clone(), json!(v));
            }

            let mut keys: Vec<_> = kvs.keys().cloned().collect();
            keys.reverse();
            let mut obj2 = serde_json::Map::new();
            for k in keys {
                let v = kvs.get(&k).unwrap();
                obj2.insert(k.clone(), json!(v));
            }

            let hash1 = canonical_content_hash_sha3_256(
                domain::EVENT,
                &Value::Object(obj1)
            ).expect("hash obj1");

            let hash2 = canonical_content_hash_sha3_256(
                domain::EVENT,
                &Value::Object(obj2)
            ).expect("hash obj2");

            prop_assert_eq!(hash1, hash2);
        }

        /// Property: Domain separation produces different hashes.
        /// The same content with different domain prefixes should produce different hashes.
        #[test]
        fn prop_domain_separation(
            data in prop::collection::vec(any::<u8>(), 1..256),
        ) {
            let hash_event = Sha3_256Digest::hash_with_domain(domain::EVENT, &data);
            let hash_poll = Sha3_256Digest::hash_with_domain(domain::POLL, &data);
            let hash_vote = Sha3_256Digest::hash_with_domain(domain::VOTE, &data);

            // All three should be different
            prop_assert_ne!(hash_event, hash_poll);
            prop_assert_ne!(hash_event, hash_vote);
            prop_assert_ne!(hash_poll, hash_vote);
        }

        /// Property: Arrays preserve order in canonical JSON.
        /// Two arrays with the same elements but different orders should hash differently.
        #[test]
        fn prop_canonical_json_array_order_significant(
            items in prop::collection::vec(0u32..100u32, 2..10),
        ) {
            let mut reversed = items.clone();
            reversed.reverse();

            // Only test if reversing actually changes the array (not a palindrome)
            prop_assume!(items != reversed);

            let hash1 = canonical_content_hash_sha3_256(
                domain::EVENT,
                &items
            ).expect("hash items");

            let hash2 = canonical_content_hash_sha3_256(
                domain::EVENT,
                &reversed
            ).expect("hash reversed");

            prop_assert_ne!(hash1, hash2);
        }

        /// Property: Hash output length is always correct.
        /// SHA3-256 should always produce 32 bytes, BLAKE3-XOF-512 should always produce 64 bytes.
        #[test]
        fn prop_hash_output_length(data in prop::collection::vec(any::<u8>(), 0..512)) {
            let hash256 = sha3_256_bytes(&data);
            let hash512 = blake3_512_bytes(&data);

            prop_assert_eq!(hash256.as_bytes().len(), 32);
            prop_assert_eq!(hash512.as_bytes().len(), 64);
        }
    }

    #[test]
    fn golden_content_hash() {
        let h = content_hash_bytes(b"mandate");
        assert_eq!(
            encode(h.0),
            "5baed7d21dfe60b2a6bc50770f83d4c6e3ded56bb474784a1b7847c8c83c0dc2"
        );
    }

    #[test]
    fn golden_ring_hash() {
        let p1 = point(b"member-a");
        let p2 = point(b"member-b");
        let ring = Ring::new(vec![p1, p2]);
        let h = ring_hash(&ring);
        assert_eq!(
            encode(h.0),
            "6af8b2f99f33bbe9dc4139fea0f81e2db17f18643f3c80a447ffeb68849ec6ce"
        );
    }

    #[test]
    fn golden_poll_hash() {
        let poll = PollFixture::poll();
        let h = poll_hash_sha3_256(&poll).expect("hash poll");
        assert_eq!(
            encode(h.0),
            "934517455d282b9f66f189ce4bbf0b9b2ac4c36071f502624705b856324454b9"
        );
    }

    #[derive(Clone)]
    struct PollFixture;

    impl PollFixture {
        fn poll() -> crate::event::Poll {
            crate::event::Poll {
                org_id: test_org_id(),
                ring_hash: RingHash([0x11; 32]),
                poll_id: "poll-1".into(),
                created_at: 42,
                instructions: Some(Ciphertext(b"how-to".to_vec())),
                deadline: None,
                sealed_duration_secs: None,
                verification_window_secs: None,
                questions: vec![
                    crate::event::PollQuestion {
                        question_id: "q1".into(),
                        title: Ciphertext(b"title".to_vec()),
                        kind: crate::event::PollQuestionKind::MultipleChoice {
                            options: vec![
                                crate::event::PollOption {
                                    id: "b".into(),
                                    text: Ciphertext(b"opt-b".to_vec()),
                                },
                                crate::event::PollOption {
                                    id: "a".into(),
                                    text: Ciphertext(b"opt-a".to_vec()),
                                },
                            ],
                            max: 2,
                        },
                    },
                    crate::event::PollQuestion {
                        question_id: "q2".into(),
                        title: Ciphertext(b"second".to_vec()),
                        kind: crate::event::PollQuestionKind::FillInTheBlank,
                    },
                ],
            }
        }
    }
}
