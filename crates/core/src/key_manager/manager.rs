use crate::hashing::Blake3_512;
use crate::ids::{EventUlid, OrganizationId, RingHash};
use age::x25519::Identity as RageIdentity;
use bip39::{Language, Mnemonic};
use hkdf::{Hkdf, SimpleHkdf};
use nazgul::keypair::KeyPair as NazgulKeyPair;
use nazgul::ring::Ring;
use nazgul::scalar::Scalar;
use nazgul::traits::Derivable;
use rand::{CryptoRng, RngCore};
use sha3::Sha3_256;
use std::io::{Read, Write};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[derive(Debug, Error)]
pub enum KeyManagerError {
    #[error("invalid mnemonic: {0}")]
    InvalidMnemonic(String),

    #[error("failed to generate mnemonic: {0}")]
    MnemonicGeneration(String),

    #[error("decryption failed: {0}")]
    Decryption(String),

    #[error("invalid key blob payload")]
    InvalidKeyBlob,

    #[error("encryption failed: {0}")]
    Encryption(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("age decrypt error: {0}")]
    AgeDecrypt(#[from] age::DecryptError),
}

const LABEL_IDENTITY: &[u8] = b"mandate-identity-v1";
const LABEL_RAGE_MASTER: &[u8] = b"mandate-rage-master";
const LABEL_ORG_SHARED: &[u8] = b"mandate-org-shared-v1";
const LABEL_DELEGATE: &[u8] = b"mandate-delegate-signer-v1";
const LABEL_MEMBER_SESSION: &[u8] = b"mandate-member-session-v1";
const LABEL_MEMBER_POLL_SIGNING: &[u8] = b"mandate-member-poll-signing-v1";
pub(crate) const LABEL_EVENT_KEY: &[u8] = b"mandate-event-key-v1";
const LABEL_POLL_KEY: &[u8] = b"mandate-poll-key-v1";

#[derive(Clone, Copy)]
pub enum KdfAlgorithm {
    Sha3_256,
    Blake3_512,
}

impl KdfAlgorithm {
    pub fn expand<const N: usize>(self, ikm: &[u8], info: &[u8]) -> [u8; N] {
        match self {
            KdfAlgorithm::Sha3_256 => hkdf_sha3_256::<N>(ikm, info),
            KdfAlgorithm::Blake3_512 => hkdf_blake3_512::<N>(ikm, info),
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
    // SAFETY: Const assertion above guarantees N <= 8160 (255 * 32).
    // HKDF expand is infallible for valid output lengths.
    hkdf.expand(info, &mut okm)
        .expect("HKDF expand infallible for N <= 8160");
    okm
}

/// HKDF-BLAKE3-XOF-512 key derivation.
///
/// # Panics
/// Panics if N > 16320 bytes (255 * 64-byte hash output). All current usages
/// derive 32-byte keys, which is well within limits.
fn hkdf_blake3_512<const N: usize>(ikm: &[u8], info: &[u8]) -> [u8; N] {
    const MAX_OUTPUT: usize = 255 * 64; // BLAKE3-XOF-512 hash length
    const { assert!(N <= MAX_OUTPUT, "HKDF output exceeds maximum") };

    let hkdf = SimpleHkdf::<Blake3_512>::new(None, ikm);
    let mut okm = [0u8; N];
    // SAFETY: Const assertion above guarantees N <= 16320 (255 * 64).
    // HKDF expand is infallible for valid output lengths.
    hkdf.expand(info, &mut okm)
        .expect("HKDF expand infallible for N <= 16320");
    okm
}

pub(crate) fn info(label: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let total_len: usize = 4 + label.len() + parts.iter().map(|p| 4 + p.len()).sum::<usize>();
    let mut buf = Vec::with_capacity(total_len);

    buf.extend_from_slice(&(label.len() as u32).to_be_bytes());
    buf.extend_from_slice(label);
    for p in parts {
        buf.extend_from_slice(&(p.len() as u32).to_be_bytes());
        buf.extend_from_slice(p);
    }
    buf
}

const KEY_BLOB_PREFIX: &[u8] = b"mandate:kshared:v1|";
const ACCESS_TOKEN_BLOB_PREFIX: &[u8] = b"mandate:edge-access:v1|";

/// Long-term master Nazgul keypair (identity), distinct from derived keys.
#[derive(Clone, Debug)]
pub struct MasterNazgulKeyPair(pub NazgulKeyPair);

/// Delegate signing keypair derived per org.
#[derive(Clone, Debug)]
pub struct DelegateNazgulKeyPair(pub NazgulKeyPair);

/// Session keypair derived per (org, ring) for member signatures.
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
    fn derive_delegate(&self, org_id: &OrganizationId) -> DelegateNazgulKeyPair;
    fn derive_session(&self, org_id: &OrganizationId, ring_hash: &RingHash)
        -> SessionNazgulKeyPair;
    fn derive_poll_signing(
        &self,
        org_id: &OrganizationId,
        poll_ring_hash: &RingHash,
        poll_id: &str,
    ) -> SessionNazgulKeyPair;
}

impl MandateDerivable for NazgulKeyPair {
    fn derive_delegate(&self, org_id: &OrganizationId) -> DelegateNazgulKeyPair {
        let ctx = info(LABEL_DELEGATE, &[&org_id.to_bytes()]);
        DelegateNazgulKeyPair(self.derive_child::<Blake3_512>(&ctx))
    }

    fn derive_session(
        &self,
        org_id: &OrganizationId,
        ring_hash: &RingHash,
    ) -> SessionNazgulKeyPair {
        let ctx = info(LABEL_MEMBER_SESSION, &[&org_id.to_bytes(), &ring_hash.0]);
        SessionNazgulKeyPair(self.derive_child::<Blake3_512>(&ctx))
    }

    fn derive_poll_signing(
        &self,
        org_id: &OrganizationId,
        poll_ring_hash: &RingHash,
        poll_id: &str,
    ) -> SessionNazgulKeyPair {
        let ctx = poll_signing_context(org_id, poll_ring_hash, poll_id);
        SessionNazgulKeyPair(self.derive_child::<Blake3_512>(&ctx))
    }
}

/// Manages the root master seed and derives application-specific keys.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct KeyManager {
    pub(crate) master_seed: [u8; 64],
}

impl KeyManager {
    /// Create a new KeyManager from a BIP39 mnemonic phrase.
    pub fn from_mnemonic(phrase: &str, passphrase: Option<&str>) -> Result<Self, KeyManagerError> {
        // bip39 v2 uses parse or parse_in
        let mnemonic = Mnemonic::parse_in(Language::English, phrase)
            .map_err(|e| KeyManagerError::InvalidMnemonic(format!("{e:?}")))?;
        let seed = mnemonic.to_seed(passphrase.unwrap_or(""));
        Ok(Self { master_seed: seed })
    }

    /// Generate a new random mnemonic and KeyManager.
    pub fn new_random<R: RngCore + CryptoRng>(
        rng: &mut R,
    ) -> Result<(Self, String), KeyManagerError> {
        // Generate 24 words (256 bits entropy)
        let mnemonic = Mnemonic::generate_in_with(rng, Language::English, 24)
            .map_err(|e| KeyManagerError::MnemonicGeneration(format!("{e:?}")))?;

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

    /// (Owner Only) Deterministically derive the Organization Shared Secret ($K_{shared}$).
    /// This key is distributed to members via "One Bucket Per Person".
    /// Path: HKDF(MasterSeed, "mandate-org-shared-v1" || OrganizationId)
    pub fn derive_org_shared_secret(&self, org_id: &OrganizationId) -> [u8; 32] {
        let info = info(LABEL_ORG_SHARED, &[&org_id.to_bytes()]);
        KdfAlgorithm::Sha3_256.expand::<32>(&self.master_seed, &info)
    }

    /// (Owner Only) Derive the Delegate Signing Key using non-hardened derivation.
    /// This allows the server to verify delegation without seeing the private key.
    /// Child = Parent + Hash("mandate-delegate-signer-v1" || OrganizationId)
    pub fn derive_delegate_signing_key(&self, org_id: &OrganizationId) -> DelegateNazgulKeyPair {
        let parent = self.derive_nazgul_master_keypair();
        parent.0.derive_delegate(org_id)
    }

    /// Derive a member session key (non-hardened) using org_id || ring_hash as context.
    /// This aligns with the design where clients sign per-ring with a derived key,
    /// and servers can mirror the public derivation.
    pub fn derive_member_session_key(
        &self,
        org_id: &OrganizationId,
        ring_hash: &RingHash,
    ) -> SessionNazgulKeyPair {
        let parent = self.derive_nazgul_master_keypair();
        parent.0.derive_session(org_id, ring_hash)
    }

    /// Derive a member poll-signing key scoped to (org, poll_ring_hash, poll_id).
    /// This prevents cross-poll key-image linkability while preserving deterministic
    /// public derivation on the server side.
    pub fn derive_member_poll_signing_key(
        &self,
        org_id: &OrganizationId,
        poll_ring_hash: &RingHash,
        poll_id: &str,
    ) -> SessionNazgulKeyPair {
        let parent = self.derive_nazgul_master_keypair();
        parent
            .0
            .derive_poll_signing(org_id, poll_ring_hash, poll_id)
    }
}

fn poll_signing_context(
    org_id: &OrganizationId,
    poll_ring_hash: &RingHash,
    poll_id: &str,
) -> Vec<u8> {
    info(
        LABEL_MEMBER_POLL_SIGNING,
        &[&org_id.to_bytes(), &poll_ring_hash.0, poll_id.as_bytes()],
    )
}

/// Derive the per-poll signing ring from a membership ring of master public keys.
///
/// Each member public key is non-hardenedly derived using the same poll-scoped
/// context as the client-side signer key.
pub fn derive_poll_signing_ring(
    org_id: &OrganizationId,
    poll_ring_hash: &RingHash,
    poll_id: &str,
    member_ring: &Ring,
) -> Ring {
    let members = member_ring
        .members()
        .iter()
        .map(|member| {
            let public_only = NazgulKeyPair::from_public_key_only(*member);
            *public_only
                .derive_poll_signing(org_id, poll_ring_hash, poll_id)
                .public()
        })
        .collect::<Vec<_>>();
    Ring::new(members)
}

/// Helper to derive an Event Ephemeral Identity ($K_{event}$) from the Organization Shared Secret.
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

/// Derive the raw 32-byte poll key bytes for external audit purposes.
///
/// This returns the same key material used by [`derive_poll_identity`], but as raw bytes
/// instead of a RageIdentity. This allows auditors to decrypt a specific poll and its
/// votes without needing K_shared (which would allow decryption of ALL org data).
///
/// # Security
///
/// The returned key should be treated as sensitive and zeroized after use.
/// Consider using [`zeroize::Zeroize`] on the returned array when done.
///
/// # Example
///
/// ```ignore
/// let k_poll = derive_poll_key_bytes(&k_shared, &poll_event_ulid);
/// let k_poll_hex = hex::encode(&k_poll);
/// // Share k_poll_hex with auditor
/// k_poll.zeroize();
/// ```
pub fn derive_poll_key_bytes(shared_secret: &[u8; 32], poll_event_ulid: &EventUlid) -> [u8; 32] {
    let info = info(LABEL_POLL_KEY, &[&poll_event_ulid.to_bytes()]);
    KdfAlgorithm::Sha3_256.expand::<32>(shared_secret, &info)
}

/// Encrypt the org-shared secret for a specific recipient (one bucket per person).
pub fn encrypt_shared_secret_for_recipient(
    shared_secret: &[u8; 32],
    recipient: &age::x25519::Recipient,
) -> Result<Vec<u8>, KeyManagerError> {
    let mut plaintext = Zeroizing::new(Vec::with_capacity(
        KEY_BLOB_PREFIX.len() + shared_secret.len(),
    ));
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
pub fn decrypt_shared_secret(
    identity: &RageIdentity,
    blob: &[u8],
) -> Result<[u8; 32], KeyManagerError> {
    let decryptor = age::Decryptor::new(blob)?;
    let mut reader = decryptor
        .decrypt(std::iter::once(identity as &dyn age::Identity))
        .map_err(|e| KeyManagerError::Decryption(e.to_string()))?;

    let mut plaintext = Zeroizing::new(Vec::new());
    reader.read_to_end(&mut plaintext)?;

    if plaintext.len() != KEY_BLOB_PREFIX.len() + 32 || !plaintext.starts_with(KEY_BLOB_PREFIX) {
        return Err(KeyManagerError::InvalidKeyBlob);
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&plaintext[KEY_BLOB_PREFIX.len()..]);
    Ok(key)
}

/// Encrypt an Edge access token for a specific recipient (one bucket per person).
///
/// Uses the same age/X25519 pattern as `encrypt_shared_secret_for_recipient`
/// but with a distinct prefix to prevent cross-use of key blobs.
pub fn encrypt_access_token_for_recipient(
    token: &[u8; 32],
    recipient: &age::x25519::Recipient,
) -> Result<Vec<u8>, KeyManagerError> {
    let mut plaintext = Zeroizing::new(Vec::with_capacity(
        ACCESS_TOKEN_BLOB_PREFIX.len() + token.len(),
    ));
    plaintext.extend_from_slice(ACCESS_TOKEN_BLOB_PREFIX);
    plaintext.extend_from_slice(token);

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

/// Decrypt an Edge access token blob; validates the prefix to prevent misuse.
pub fn decrypt_access_token_blob(
    identity: &RageIdentity,
    blob: &[u8],
) -> Result<[u8; 32], KeyManagerError> {
    let decryptor = age::Decryptor::new(blob)?;
    let mut reader = decryptor
        .decrypt(std::iter::once(identity as &dyn age::Identity))
        .map_err(|e| KeyManagerError::Decryption(e.to_string()))?;

    let mut plaintext = Zeroizing::new(Vec::new());
    reader.read_to_end(&mut plaintext)?;

    if plaintext.len() != ACCESS_TOKEN_BLOB_PREFIX.len() + 32
        || !plaintext.starts_with(ACCESS_TOKEN_BLOB_PREFIX)
    {
        return Err(KeyManagerError::InvalidKeyBlob);
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&plaintext[ACCESS_TOKEN_BLOB_PREFIX.len()..]);
    Ok(key)
}

/// Encrypt event content using standard age encryption (X25519).
/// Uses the event identity's public key as the recipient.
pub fn encrypt_event_content(
    identity: &RageIdentity,
    plaintext: &[u8],
) -> Result<Vec<u8>, KeyManagerError> {
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
pub fn decrypt_event_content(
    identity: &RageIdentity,
    payload: &[u8],
) -> Result<Vec<u8>, KeyManagerError> {
    let decryptor = age::Decryptor::new(payload)?;

    let mut reader = decryptor
        .decrypt(std::iter::once(identity as &dyn age::Identity))
        .map_err(|e| KeyManagerError::Decryption(e.to_string()))?;

    let mut plaintext = Vec::new();
    reader.read_to_end(&mut plaintext)?;

    Ok(plaintext)
}
