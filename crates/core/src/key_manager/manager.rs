use crate::ids::{EventUlid, GroupId, RingHash};
use age::x25519::Identity as RageIdentity;
use anyhow::Result;
use bip39::{Language, Mnemonic};
use hkdf::Hkdf;
use nazgul::keypair::KeyPair as NazgulKeyPair;
use nazgul::scalar::Scalar;
use nazgul::traits::Derivable;
use rand::{CryptoRng, RngCore};
use sha3::{Sha3_256, Sha3_512};
use std::io::{Read, Write};
use zeroize::{Zeroize, ZeroizeOnDrop};

const LABEL_IDENTITY: &[u8] = b"mandate-identity-v1";
const LABEL_RAGE_MASTER: &[u8] = b"mandate-rage-master";
const LABEL_GROUP_SHARED: &[u8] = b"mandate-group-shared-v1";
const LABEL_DELEGATE: &[u8] = b"mandate-delegate-signer-v1";
const LABEL_MEMBER_SESSION: &[u8] = b"mandate-member-session-v1";
const LABEL_EVENT_KEY: &[u8] = b"mandate-event-key-v1";
const LABEL_POLL_KEY: &[u8] = b"mandate-poll-key-v1";

#[derive(Clone, Copy)]
pub enum KdfAlgorithm {
    Sha3_256,
    Sha3_512,
}

impl KdfAlgorithm {
    pub fn expand<const N: usize>(self, ikm: &[u8], info: &[u8]) -> [u8; N] {
        match self {
            KdfAlgorithm::Sha3_256 => hkdf_sha3_256::<N>(ikm, info),
            KdfAlgorithm::Sha3_512 => hkdf_sha3_512::<N>(ikm, info),
        }
    }
}

/// HKDF-SHA3-256 key derivation.
///
/// # Panics
/// Panics if N > 8160 bytes (255 * 32-byte hash output). All current usages
/// derive 32-byte keys, which is well within limits.
fn hkdf_sha3_256<const N: usize>(ikm: &[u8], info: &[u8]) -> [u8; N] {
    const MAX_OUTPUT: usize = 255 * 32; // SHA3-256 hash length
    const { assert!(N <= MAX_OUTPUT, "HKDF output exceeds maximum") };

    let hkdf = Hkdf::<Sha3_256>::new(None, ikm);
    let mut okm = [0u8; N];
    hkdf.expand(info, &mut okm)
        .expect("HKDF expand infallible for N <= 8160");
    okm
}

/// HKDF-SHA3-512 key derivation.
///
/// # Panics
/// Panics if N > 16320 bytes (255 * 64-byte hash output). All current usages
/// derive 32-byte keys, which is well within limits.
fn hkdf_sha3_512<const N: usize>(ikm: &[u8], info: &[u8]) -> [u8; N] {
    const MAX_OUTPUT: usize = 255 * 64; // SHA3-512 hash length
    const { assert!(N <= MAX_OUTPUT, "HKDF output exceeds maximum") };

    let hkdf = Hkdf::<Sha3_512>::new(None, ikm);
    let mut okm = [0u8; N];
    hkdf.expand(info, &mut okm)
        .expect("HKDF expand infallible for N <= 16320");
    okm
}

fn info(label: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let total_len: usize = label.len() + parts.iter().map(|p| p.len()).sum::<usize>();
    let mut buf = Vec::with_capacity(total_len);
    buf.extend_from_slice(label);
    for p in parts {
        buf.extend_from_slice(p);
    }
    buf
}

const KEY_BLOB_PREFIX: &[u8] = b"mandate:kshared:v1|";

/// Long-term master Nazgul keypair (identity), distinct from derived keys.
#[derive(Clone, Debug)]
pub struct MasterNazgulKeyPair(pub NazgulKeyPair);

/// Delegate signing keypair derived per group.
#[derive(Clone, Debug)]
pub struct DelegateNazgulKeyPair(pub NazgulKeyPair);

/// Session keypair derived per (group, ring) for member signatures.
#[derive(Clone, Debug)]
pub struct SessionNazgulKeyPair(pub NazgulKeyPair);

impl DelegateNazgulKeyPair {
    pub fn as_keypair(&self) -> &NazgulKeyPair {
        &self.0
    }

    pub fn public(&self) -> &curve25519_dalek::ristretto::RistrettoPoint {
        self.0.public()
    }
}

impl SessionNazgulKeyPair {
    pub fn as_keypair(&self) -> &NazgulKeyPair {
        &self.0
    }

    pub fn public(&self) -> &curve25519_dalek::ristretto::RistrettoPoint {
        self.0.public()
    }
}

/// Derivation helpers implemented directly on `NazgulKeyPair` so both
/// full and public-only keypairs can reuse the same API.
pub trait MandateDerivable {
    fn derive_delegate(&self, group_id: &GroupId) -> DelegateNazgulKeyPair;
    fn derive_session(&self, group_id: &GroupId, ring_hash: &RingHash) -> SessionNazgulKeyPair;
}

impl MandateDerivable for NazgulKeyPair {
    fn derive_delegate(&self, group_id: &GroupId) -> DelegateNazgulKeyPair {
        let ctx = info(LABEL_DELEGATE, &[&group_id.to_bytes()]);
        DelegateNazgulKeyPair(self.derive_child::<Sha3_512>(&ctx))
    }

    fn derive_session(&self, group_id: &GroupId, ring_hash: &RingHash) -> SessionNazgulKeyPair {
        let ctx = info(LABEL_MEMBER_SESSION, &[&group_id.to_bytes(), &ring_hash.0]);
        SessionNazgulKeyPair(self.derive_child::<Sha3_512>(&ctx))
    }
}

/// Manages the root master seed and derives application-specific keys.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct KeyManager {
    master_seed: [u8; 64],
}

impl KeyManager {
    /// Create a new KeyManager from a BIP39 mnemonic phrase.
    pub fn from_mnemonic(phrase: &str, passphrase: Option<&str>) -> Result<Self> {
        // bip39 v2 uses parse or parse_in
        let mnemonic = Mnemonic::parse_in(Language::English, phrase)
            .map_err(|e| anyhow::anyhow!("Invalid mnemonic: {:?}", e))?;
        let seed = mnemonic.to_seed(passphrase.unwrap_or(""));
        Ok(Self { master_seed: seed })
    }

    /// Generate a new random mnemonic and KeyManager.
    pub fn new_random<R: RngCore + CryptoRng>(rng: &mut R) -> Result<(Self, String)> {
        // Generate 24 words (256 bits entropy)
        let mnemonic = Mnemonic::generate_in_with(rng, Language::English, 24)
            .map_err(|e| anyhow::anyhow!("Failed to generate mnemonic: {:?}", e))?;

        let phrase = mnemonic.to_string();
        let seed = mnemonic.to_seed("");
        Ok((Self { master_seed: seed }, phrase))
    }

    /// Derive the user's long-term Nazgul master keypair (for signing).
    /// Path: HKDF(MasterSeed, "mandate-identity-v1")
    pub fn derive_nazgul_master_keypair(&self) -> MasterNazgulKeyPair {
        let mut okm = KdfAlgorithm::Sha3_256.expand::<32>(&self.master_seed, LABEL_IDENTITY);
        let scalar = Scalar::from_bytes_mod_order(okm);
        okm.zeroize();
        let keypair = NazgulKeyPair::new(scalar);
        MasterNazgulKeyPair(keypair)
    }

    /// Derive the user's long-term Rage identity (for decrypting key blobs).
    /// Path: HKDF(MasterSeed, "mandate-rage-master")
    pub fn derive_rage_identity(&self) -> RageIdentity {
        let mut okm = KdfAlgorithm::Sha3_256.expand::<32>(&self.master_seed, LABEL_RAGE_MASTER);
        let id = RageIdentity::from_secret_bytes(okm);
        okm.zeroize();
        id
    }

    /// (Owner Only) Deterministically derive the Group Shared Secret ($K_{shared}$).
    /// This key is distributed to members via "One Bucket Per Person".
    /// Path: HKDF(MasterSeed, "mandate-group-shared-v1" || GroupId)
    pub fn derive_group_shared_secret(&self, group_id: &GroupId) -> [u8; 32] {
        let info = info(LABEL_GROUP_SHARED, &[&group_id.to_bytes()]);
        KdfAlgorithm::Sha3_256.expand::<32>(&self.master_seed, &info)
    }

    /// (Owner Only) Derive the Delegate Signing Key using non-hardened derivation.
    /// This allows the server to verify delegation without seeing the private key.
    /// Child = Parent + Hash("mandate-delegate-signer-v1" || GroupId)
    pub fn derive_delegate_signing_key(&self, group_id: &GroupId) -> DelegateNazgulKeyPair {
        let parent = self.derive_nazgul_master_keypair();
        parent.0.derive_delegate(group_id)
    }

    /// Derive a member session key (non-hardened) using group_id || ring_hash as context.
    /// This aligns with the design where clients sign per-ring with a derived key,
    /// and servers can mirror the public derivation.
    pub fn derive_member_session_key(
        &self,
        group_id: &GroupId,
        ring_hash: &RingHash,
    ) -> SessionNazgulKeyPair {
        let parent = self.derive_nazgul_master_keypair();
        parent.0.derive_session(group_id, ring_hash)
    }
}

/// Helper to derive an Event Ephemeral Identity ($K_{event}$) from the Group Shared Secret.
/// Path: HKDF(SharedSecret, ULID)
/// Returns a full RageIdentity, which can act as both Sender (encrypt) and Receiver (decrypt).
pub fn derive_event_identity(shared_secret: &[u8; 32], event_ulid: &EventUlid) -> RageIdentity {
    let info = info(LABEL_EVENT_KEY, &[&event_ulid.to_bytes()]);
    let mut okm = KdfAlgorithm::Sha3_256.expand::<32>(shared_secret, &info);
    let id = RageIdentity::from_secret_bytes(okm);
    okm.zeroize();
    id
}

/// Derive a poll-level symmetric identity reused by VoteCast events, keyed by the
/// PollCreate event ULID to avoid per-vote key inflation.
pub fn derive_poll_identity(shared_secret: &[u8; 32], poll_event_ulid: &EventUlid) -> RageIdentity {
    let info = info(LABEL_POLL_KEY, &[&poll_event_ulid.to_bytes()]);
    let mut okm = KdfAlgorithm::Sha3_256.expand::<32>(shared_secret, &info);
    let id = RageIdentity::from_secret_bytes(okm);
    okm.zeroize();
    id
}

/// Encrypt the group-shared secret for a specific recipient (one bucket per person).
pub fn encrypt_shared_secret_for_recipient(
    shared_secret: &[u8; 32],
    recipient: &age::x25519::Recipient,
) -> Result<Vec<u8>> {
    let mut plaintext = Vec::with_capacity(KEY_BLOB_PREFIX.len() + shared_secret.len());
    plaintext.extend_from_slice(KEY_BLOB_PREFIX);
    plaintext.extend_from_slice(shared_secret);

    let recipients = [Box::new(recipient.clone()) as Box<dyn age::Recipient>];
    let encryptor = age::Encryptor::with_recipients(recipients.iter().map(|r| r.as_ref()))
        .expect("valid recipient");

    let mut ciphertext = Vec::new();
    {
        let mut writer = encryptor.wrap_output(&mut ciphertext)?;
        writer.write_all(&plaintext)?;
        writer.finish()?;
    }

    Ok(ciphertext)
}

/// Decrypt a shared-secret bucket; validates the prefix to prevent misuse.
pub fn decrypt_shared_secret(identity: &RageIdentity, blob: &[u8]) -> Result<[u8; 32]> {
    let decryptor = age::Decryptor::new(blob)?;
    let mut reader = decryptor
        .decrypt(std::iter::once(identity as &dyn age::Identity))
        .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))?;

    let mut plaintext = Vec::new();
    reader.read_to_end(&mut plaintext)?;

    if plaintext.len() != KEY_BLOB_PREFIX.len() + 32 || !plaintext.starts_with(KEY_BLOB_PREFIX) {
        return Err(anyhow::anyhow!("invalid key blob payload"));
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&plaintext[KEY_BLOB_PREFIX.len()..]);
    Ok(key)
}

/// Encrypt event content using standard age encryption (X25519).
/// Uses the event identity's public key as the recipient.
pub fn encrypt_event_content(identity: &RageIdentity, plaintext: &[u8]) -> Result<Vec<u8>> {
    let recipient = identity.to_public();
    let recipients = [Box::new(recipient) as Box<dyn age::Recipient>];

    let encryptor = age::Encryptor::with_recipients(recipients.iter().map(|r| r.as_ref()))
        .expect("valid recipient");

    let mut ciphertext = Vec::new();
    // Wrap in a block to ensure writer is finished/flushed
    {
        let mut writer = encryptor.wrap_output(&mut ciphertext)?;
        writer.write_all(plaintext)?;
        writer.finish()?;
    }

    Ok(ciphertext)
}

/// Decrypt event content using standard age decryption.
/// Uses the derived event identity to decrypt.
pub fn decrypt_event_content(identity: &RageIdentity, payload: &[u8]) -> Result<Vec<u8>> {
    let decryptor = age::Decryptor::new(payload)?;

    let mut reader = decryptor
        .decrypt(std::iter::once(identity as &dyn age::Identity))
        .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))?;

    let mut plaintext = Vec::new();
    reader.read_to_end(&mut plaintext)?;

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ulid::Ulid;

    fn gid(label: &str) -> GroupId {
        GroupId(Ulid::from_string(label).expect("static ulid"))
    }

    fn eid(label: &str) -> EventUlid {
        EventUlid(Ulid::from_string(label).expect("static ulid"))
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
    fn test_group_isolation() {
        let mut rng = rand::thread_rng();
        let (km, _) = KeyManager::new_random(&mut rng).unwrap();
        let g1 = gid("01ARZ3NDEKTSV4RRFFQ69G5FAV");
        let g2 = gid("01ARZ3NDEKTSV4RRFFQ69G5FAY");
        let r1 = RingHash([1u8; 32]);
        let r2 = RingHash([2u8; 32]);

        // Shared Secret Isolation
        let s1 = km.derive_group_shared_secret(&g1);
        let s2 = km.derive_group_shared_secret(&g2);
        assert_ne!(s1, s2);

        // Member Session Key Isolation (group + ring)
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
        let group_id = gid("01ARZ3NDEKTSV4RRFFQ69G5FAZ");

        // Owner derives delegate private key
        let delegate_sk = km.derive_delegate_signing_key(&group_id);

        // Verifier derives delegate public key from Owner Public Key + Context
        let owner_pk = km.derive_nazgul_master_keypair();
        // Public-only derivation using KeyPair::from_public_key_only
        let verifier_kp = NazgulKeyPair::from_public_key_only(*owner_pk.0.public());
        let derived_pk = verifier_kp.derive_delegate(&group_id);

        assert_eq!(
            delegate_sk.public(),
            derived_pk.public(),
            "Public key derivation must match private key derivation"
        );
    }

    #[test]
    fn test_event_encryption_roundtrip_age() {
        let shared_secret = [42u8; 32];
        let ulid = eid("01ARZ3NDEKTSV4RRFFQ69G5FAV");

        let event_id = derive_event_identity(&shared_secret, &ulid);
        let plaintext = b"Hello Age World";

        let encrypted = encrypt_event_content(&event_id, plaintext).unwrap();

        let decrypted = decrypt_event_content(&event_id, &encrypted).unwrap();
        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_event_key_uniqueness() {
        let shared_secret = [42u8; 32];
        let k1 = derive_event_identity(&shared_secret, &eid("01ARZ3NDEKTSV4RRFFQ69G5FAV"));
        let k2 = derive_event_identity(&shared_secret, &eid("01ARZ3NDEKTSV4RRFFQ69G5FAY"));
        assert_ne!(k1.to_public().to_string(), k2.to_public().to_string());
    }

    #[test]
    fn poll_identity_reused_for_votes() {
        let shared_secret = [9u8; 32];
        let poll_ulid = eid("01ARZ3NDEKTSV4RRFFQ69G5FAV");
        let k_poll = derive_poll_identity(&shared_secret, &poll_ulid);
        let vote_cast = derive_poll_identity(&shared_secret, &poll_ulid);
        assert_eq!(
            k_poll.to_public().to_string(),
            vote_cast.to_public().to_string(),
            "PollCreate and VoteCast must reuse the same poll-scoped key"
        );
    }

    #[test]
    fn public_derivation_matches_private_for_member_session() {
        let mut rng = rand::thread_rng();
        let (km, _) = KeyManager::new_random(&mut rng).unwrap();
        let group = gid("01ARZ3NDEKTSV4RRFFQ69G5FB0");
        let ring = RingHash([7u8; 32]);

        let private = km.derive_member_session_key(&group, &ring);
        let public =
            NazgulKeyPair::from_public_key_only(*km.derive_nazgul_master_keypair().0.public())
                .derive_session(&group, &ring);

        assert_eq!(
            private.public(),
            public.public(),
            "public-only derivation must equal private derivation"
        );
    }

    #[test]
    fn key_blob_roundtrip() {
        let mut rng = rand::thread_rng();
        let (km, _) = KeyManager::new_random(&mut rng).unwrap();
        let shared = km.derive_group_shared_secret(&gid("01ARZ3NDEKTSV4RRFFQ69G5FAV"));

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
        let encryptor = age::Encryptor::with_recipients(recipients.iter().map(|r| r.as_ref()))
            .expect("encryptor");
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
}
