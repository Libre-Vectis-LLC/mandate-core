use super::manager::*;
use crate::ids::{EventUlid, OrganizationId, RingHash};
use crate::test_utils::{
    event_ulid_from_str, org_id_from_str, TEST_EVENT_ULID_STR, TEST_MNEMONIC, TEST_ORG_ID_STR,
};
use age::x25519::Identity as RageIdentity;
use nazgul::keypair::KeyPair as NazgulKeyPair;
use std::io::Write;

// Golden vector for length-prefixed info() encoding. Update if info() encoding changes.
const GOLDEN_ORG_SHARED_SECRET_HEX: &str =
    "528b73d2c79cf44b481aabc75365403511fbaf986bf475bfa869af8a75a3cd7b";
// Golden vector for length-prefixed info() encoding. Update if info() encoding changes.
const GOLDEN_DELEGATE_KEY_HEX: &str =
    "8d4eade191e9a054f3616e356f77716b7ecea113191a9174fdf79e5006215908";
// Golden vector for length-prefixed info() encoding. Update if info() encoding changes.
const GOLDEN_MEMBER_SESSION_KEY_HEX: &str =
    "3d87103479fb08c17a7d742b7daf7b883fd9b80da3b2daf48500ffd75cb79800";
// Golden vector for length-prefixed info() encoding. Update if info() encoding changes.
const GOLDEN_POLL_SIGNING_KEY_HEX: &str =
    "b8d6b80eb231118701d9550c82e4420b52fc0b4b888f50b12c82806121c25c0b";
// Golden vector for length-prefixed info() encoding. Update if info() encoding changes.
const GOLDEN_EVENT_KEY_HEX: &str =
    "f739c2b7153c97c3ee4ae56bc70ce951f110eae496cac3fce7151b030ce6368c";
// Golden vector for length-prefixed info() encoding. Update if info() encoding changes.
const GOLDEN_POLL_KEY_HEX: &str =
    "bfae7f7baa1f020b9e93265dabdbc41de82464fc14addb0157f87477efe1b201";
const GOLDEN_POLL_ID: &str = "golden-poll-id";
const GOLDEN_POLL_EVENT_ULID_STR: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAY";

fn golden_key_manager() -> KeyManager {
    KeyManager::from_mnemonic(TEST_MNEMONIC, None).expect("valid test mnemonic")
}

fn golden_org_id() -> OrganizationId {
    org_id_from_str(TEST_ORG_ID_STR)
}

fn golden_ring_hash() -> RingHash {
    RingHash([0x11; 32])
}

fn golden_event_ulid() -> EventUlid {
    event_ulid_from_str(TEST_EVENT_ULID_STR)
}

fn golden_poll_event_ulid() -> EventUlid {
    event_ulid_from_str(GOLDEN_POLL_EVENT_ULID_STR)
}

fn derive_event_key_bytes_for_test(shared_secret: &[u8; 32], event_ulid: &EventUlid) -> [u8; 32] {
    let info = info(LABEL_EVENT_KEY, &[&event_ulid.to_bytes()]);
    KdfAlgorithm::Sha3_256.expand::<32>(shared_secret, &info)
}

#[test]
fn golden_org_shared_secret() {
    let actual_hex = hex::encode(golden_key_manager().derive_org_shared_secret(&golden_org_id()));
    assert_eq!(
        actual_hex, GOLDEN_ORG_SHARED_SECRET_HEX,
        "update GOLDEN_ORG_SHARED_SECRET_HEX to {actual_hex}"
    );
}

#[test]
fn golden_delegate_key() {
    let actual_hex = hex::encode(
        golden_key_manager()
            .derive_delegate_signing_key(&golden_org_id())
            .as_keypair()
            .secret()
            .expect("delegate keypair includes secret")
            .to_bytes(),
    );
    assert_eq!(
        actual_hex, GOLDEN_DELEGATE_KEY_HEX,
        "update GOLDEN_DELEGATE_KEY_HEX to {actual_hex}"
    );
}

#[test]
fn golden_member_session_key() {
    let actual_hex = hex::encode(
        golden_key_manager()
            .derive_member_session_key(&golden_org_id(), &golden_ring_hash())
            .as_keypair()
            .secret()
            .expect("session keypair includes secret")
            .to_bytes(),
    );
    assert_eq!(
        actual_hex, GOLDEN_MEMBER_SESSION_KEY_HEX,
        "update GOLDEN_MEMBER_SESSION_KEY_HEX to {actual_hex}"
    );
}

#[test]
fn golden_poll_signing_key() {
    let actual_hex = hex::encode(
        golden_key_manager()
            .derive_member_poll_signing_key(&golden_org_id(), &golden_ring_hash(), GOLDEN_POLL_ID)
            .as_keypair()
            .secret()
            .expect("poll-signing keypair includes secret")
            .to_bytes(),
    );
    assert_eq!(
        actual_hex, GOLDEN_POLL_SIGNING_KEY_HEX,
        "update GOLDEN_POLL_SIGNING_KEY_HEX to {actual_hex}"
    );
}

#[test]
fn golden_event_key() {
    let km = golden_key_manager();
    let shared_secret = km.derive_org_shared_secret(&golden_org_id());
    let event_ulid = golden_event_ulid();
    let event_key_bytes = derive_event_key_bytes_for_test(&shared_secret, &event_ulid);
    let identity = derive_event_identity(&shared_secret, &event_ulid);

    assert_eq!(
        identity.to_public().as_bytes(),
        RageIdentity::from_secret_bytes(event_key_bytes)
            .to_public()
            .as_bytes(),
        "event identity must match the derived event key bytes"
    );

    let actual_hex = hex::encode(event_key_bytes);
    assert_eq!(
        actual_hex, GOLDEN_EVENT_KEY_HEX,
        "update GOLDEN_EVENT_KEY_HEX to {actual_hex}"
    );
}

#[test]
fn golden_poll_key() {
    let km = golden_key_manager();
    let shared_secret = km.derive_org_shared_secret(&golden_org_id());
    let poll_event_ulid = golden_poll_event_ulid();
    let poll_key_bytes = derive_poll_key_bytes(&shared_secret, &poll_event_ulid);
    let identity = derive_poll_identity(&shared_secret, &poll_event_ulid);

    assert_eq!(
        identity.to_public().as_bytes(),
        RageIdentity::from_secret_bytes(poll_key_bytes)
            .to_public()
            .as_bytes(),
        "poll identity must match the derived poll key bytes"
    );

    let actual_hex = hex::encode(poll_key_bytes);
    assert_eq!(
        actual_hex, GOLDEN_POLL_KEY_HEX,
        "update GOLDEN_POLL_KEY_HEX to {actual_hex}"
    );
}

#[test]
fn test_mnemonic_roundtrip() {
    let mut rng = rand::thread_rng();
    let (km1, phrase) = KeyManager::new_random(&mut rng).unwrap();
    let km2 = KeyManager::from_mnemonic(&phrase, None).unwrap();

    assert_eq!(km1.master_seed, km2.master_seed);
}

#[test]
fn test_deterministic_derivations() {
    let mut rng = rand::thread_rng();
    let (km, _) = KeyManager::new_random(&mut rng).unwrap();

    let nazgul1 = km.derive_nazgul_master_keypair();
    let nazgul2 = km.derive_nazgul_master_keypair();
    assert_eq!(nazgul1.0.public(), nazgul2.0.public());

    let rage1 = km.derive_rage_identity();
    let rage2 = km.derive_rage_identity();
    assert_eq!(rage1.to_public().to_string(), rage2.to_public().to_string());
}

#[test]
fn test_org_isolation() {
    let mut rng = rand::thread_rng();
    let (km, _) = KeyManager::new_random(&mut rng).unwrap();
    let g1 = org_id_from_str("01ARZ3NDEKTSV4RRFFQ69G5FAV");
    let g2 = org_id_from_str("01ARZ3NDEKTSV4RRFFQ69G5FAY");
    let r1 = RingHash([1u8; 32]);
    let r2 = RingHash([2u8; 32]);

    // Shared Secret Isolation
    let s1 = km.derive_org_shared_secret(&g1);
    let s2 = km.derive_org_shared_secret(&g2);
    assert_ne!(s1, s2);

    // Member Session Key Isolation (org + ring)
    let m1 = km.derive_member_session_key(&g1, &r1);
    let m2 = km.derive_member_session_key(&g2, &r1);
    let m3 = km.derive_member_session_key(&g1, &r2);
    assert_ne!(m1.public(), m2.public());
    assert_ne!(m1.public(), m3.public());

    // Delegate Key Isolation
    let d1 = km.derive_delegate_signing_key(&g1);
    let d2 = km.derive_delegate_signing_key(&g2);
    assert_ne!(d1.public(), d2.public());
}

#[test]
fn test_non_hardened_delegation_verification() {
    let mut rng = rand::thread_rng();
    let (km, _) = KeyManager::new_random(&mut rng).unwrap();
    let org_id = org_id_from_str("01ARZ3NDEKTSV4RRFFQ69G5FAZ");

    // Owner derives delegate private key
    let delegate_sk = km.derive_delegate_signing_key(&org_id);

    // Verifier derives delegate public key from Owner Public Key + Context
    let owner_pk = km.derive_nazgul_master_keypair();
    // Public-only derivation using KeyPair::from_public_key_only
    let verifier_kp = NazgulKeyPair::from_public_key_only(*owner_pk.0.public());
    let derived_pk = verifier_kp.derive_delegate(&org_id);

    assert_eq!(
        delegate_sk.public(),
        derived_pk.public(),
        "Public key derivation must match private key derivation"
    );
}

#[test]
fn test_event_encryption_roundtrip_age() {
    let shared_secret = [42u8; 32];
    let ulid = event_ulid_from_str("01ARZ3NDEKTSV4RRFFQ69G5FAV");

    let event_id = derive_event_identity(&shared_secret, &ulid);
    let plaintext = b"Hello Age World";

    let encrypted = encrypt_event_content(&event_id, plaintext).unwrap();

    let decrypted = decrypt_event_content(&event_id, &encrypted).unwrap();
    assert_eq!(plaintext.to_vec(), decrypted);
}

#[test]
fn test_event_key_uniqueness() {
    let shared_secret = [42u8; 32];
    let k1 = derive_event_identity(
        &shared_secret,
        &event_ulid_from_str("01ARZ3NDEKTSV4RRFFQ69G5FAV"),
    );
    let k2 = derive_event_identity(
        &shared_secret,
        &event_ulid_from_str("01ARZ3NDEKTSV4RRFFQ69G5FAY"),
    );
    assert_ne!(k1.to_public().to_string(), k2.to_public().to_string());
}

#[test]
fn poll_identity_reused_for_votes() {
    let shared_secret = [9u8; 32];
    let poll_ulid = event_ulid_from_str("01ARZ3NDEKTSV4RRFFQ69G5FAV");
    let k_poll = derive_poll_identity(&shared_secret, &poll_ulid);
    let vote_cast = derive_poll_identity(&shared_secret, &poll_ulid);
    assert_eq!(
        k_poll.to_public().to_string(),
        vote_cast.to_public().to_string(),
        "PollCreate and VoteCast must reuse the same poll-scoped key"
    );
}

#[test]
fn poll_key_bytes_matches_identity() {
    let shared_secret = [9u8; 32];
    let poll_ulid = event_ulid_from_str("01ARZ3NDEKTSV4RRFFQ69G5FAV");
    // Derive using identity method
    let k_poll_identity = derive_poll_identity(&shared_secret, &poll_ulid);
    // Derive using raw bytes method
    let k_poll_bytes = derive_poll_key_bytes(&shared_secret, &poll_ulid);
    // Create identity from raw bytes
    let k_poll_from_bytes = RageIdentity::from_secret_bytes(k_poll_bytes);
    assert_eq!(
        k_poll_identity.to_public().to_string(),
        k_poll_from_bytes.to_public().to_string(),
        "derive_poll_key_bytes must produce same key as derive_poll_identity"
    );
}

#[test]
fn public_derivation_matches_private_for_member_session() {
    let mut rng = rand::thread_rng();
    let (km, _) = KeyManager::new_random(&mut rng).unwrap();
    let org = org_id_from_str("01ARZ3NDEKTSV4RRFFQ69G5FB0");
    let ring = RingHash([7u8; 32]);

    let private = km.derive_member_session_key(&org, &ring);
    let public = NazgulKeyPair::from_public_key_only(*km.derive_nazgul_master_keypair().0.public())
        .derive_session(&org, &ring);

    assert_eq!(
        private.public(),
        public.public(),
        "public-only derivation must equal private derivation"
    );
}

#[test]
fn poll_signing_key_isolated_by_poll_id() {
    let mut rng = rand::thread_rng();
    let (km, _) = KeyManager::new_random(&mut rng).unwrap();
    let org = org_id_from_str("01ARZ3NDEKTSV4RRFFQ69G5FB1");
    let ring = RingHash([8u8; 32]);

    let poll_a = km.derive_member_poll_signing_key(&org, &ring, "poll-a");
    let poll_b = km.derive_member_poll_signing_key(&org, &ring, "poll-b");

    assert_ne!(
        poll_a.public(),
        poll_b.public(),
        "poll-signing keys must differ across poll_id"
    );
}

#[test]
fn public_derivation_matches_private_for_poll_signing() {
    let mut rng = rand::thread_rng();
    let (km, _) = KeyManager::new_random(&mut rng).unwrap();
    let org = org_id_from_str("01ARZ3NDEKTSV4RRFFQ69G5FB2");
    let ring = RingHash([9u8; 32]);
    let poll_id = "poll-derive-match";

    let private = km.derive_member_poll_signing_key(&org, &ring, poll_id);
    let public = NazgulKeyPair::from_public_key_only(*km.derive_nazgul_master_keypair().0.public())
        .derive_poll_signing(&org, &ring, poll_id);

    assert_eq!(
        private.public(),
        public.public(),
        "public-only poll derivation must equal private derivation"
    );
}

#[test]
fn key_blob_roundtrip() {
    let mut rng = rand::thread_rng();
    let (km, _) = KeyManager::new_random(&mut rng).unwrap();
    let shared = km.derive_org_shared_secret(&org_id_from_str("01ARZ3NDEKTSV4RRFFQ69G5FAV"));

    let recipient = km.derive_rage_identity().to_public();
    let blob = encrypt_shared_secret_for_recipient(&shared, &recipient).expect("encrypt");

    let recovered =
        decrypt_shared_secret(&km.derive_rage_identity(), &blob).expect("decrypt roundtrip");
    assert_eq!(shared, recovered, "shared secret must roundtrip");
}

#[test]
fn key_blob_rejects_bad_prefix() {
    let mut rng = rand::thread_rng();
    let (km, _) = KeyManager::new_random(&mut rng).unwrap();
    let identity = km.derive_rage_identity();
    // craft blob with wrong plaintext
    let bad_plain = b"wrong".to_vec();
    let recipients = [Box::new(identity.to_public()) as Box<dyn age::Recipient>];
    let encryptor =
        age::Encryptor::with_recipients(recipients.iter().map(|r| r.as_ref())).expect("encryptor");
    let mut blob = Vec::new();
    {
        let mut writer = encryptor.wrap_output(&mut blob).expect("writer");
        writer.write_all(&bad_plain).expect("write");
        writer.finish().expect("finish");
    }

    let err = decrypt_shared_secret(&identity, &blob).expect_err("should fail prefix check");
    assert!(
        err.to_string().contains("invalid key blob"),
        "must surface invalid payload"
    );
}
