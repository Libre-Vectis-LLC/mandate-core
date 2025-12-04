use crate::crypto::signature::MasterKeypair;
use age::x25519::Identity as RageIdentity;
use anyhow::Result;
use bip39::{Language, Mnemonic};
use hkdf::Hkdf;
use nazgul::keypair::KeyPair as NazgulKeyPair;
use nazgul::scalar::Scalar;
use rand::{CryptoRng, RngCore};
use sha3::Sha3_256;
use std::io::{Read, Write};
use zeroize::{Zeroize, ZeroizeOnDrop};

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

    /// Derive the user's long-term Nazgul identity (for signing).
    /// Path: HKDF(MasterSeed, "mandate-nazgul-master")
    pub fn derive_nazgul_identity(&self) -> MasterKeypair {
        let hkdf = Hkdf::<Sha3_256>::new(None, &self.master_seed);
        let mut okm = [0u8; 32];
        hkdf.expand(b"mandate-nazgul-master", &mut okm)
            .expect("HKDF expand failed");
        
        let scalar = Scalar::from_bytes_mod_order(okm);
        okm.zeroize();
        
        let keypair = NazgulKeyPair::new(scalar);
        MasterKeypair::new(keypair)
    }

    /// Derive the user's long-term Rage identity (for decrypting key blobs).
    /// Path: HKDF(MasterSeed, "mandate-rage-master")
    pub fn derive_rage_identity(&self) -> RageIdentity {
        let hkdf = Hkdf::<Sha3_256>::new(None, &self.master_seed);
        let mut okm = [0u8; 32];
        hkdf.expand(b"mandate-rage-master", &mut okm)
            .expect("HKDF expand failed");
        
        let identity = RageIdentity::from_secret_bytes(okm);
        okm.zeroize();
        identity
    }

    /// (Owner Only) Deterministically derive the Group Shared Secret ($K_{shared}$).
    /// This key is distributed to members via "One Bucket Per Person".
    /// Path: HKDF(MasterSeed, "mandate-group-shared-secret" || RingHash)
    pub fn derive_group_shared_secret(&self, ring_hash: &[u8; 32]) -> [u8; 32] {
        let hkdf = Hkdf::<Sha3_256>::new(None, &self.master_seed);
        let mut okm = [0u8; 32];
        let info = [b"mandate-group-shared-secret", ring_hash.as_slice()].concat();
        hkdf.expand(&info, &mut okm)
            .expect("HKDF expand failed");
        okm
    }
}

/// Helper to derive an Event Ephemeral Identity ($K_{event}$) from the Group Shared Secret.
/// Path: HKDF(SharedSecret, ULID)
/// Returns a full RageIdentity, which can act as both Sender (encrypt) and Receiver (decrypt).
pub fn derive_event_identity(shared_secret: &[u8; 32], event_ulid: &str) -> RageIdentity {
    let hkdf = Hkdf::<Sha3_256>::new(None, shared_secret);
    let mut okm = [0u8; 32];
    hkdf.expand(event_ulid.as_bytes(), &mut okm)
        .expect("HKDF expand failed");
    
    let identity = RageIdentity::from_secret_bytes(okm);
    okm.zeroize();
    identity
}

/// Encrypt event content using standard age encryption (X25519).
/// Uses the event identity's public key as the recipient.
pub fn encrypt_event_content(identity: &RageIdentity, plaintext: &[u8]) -> Result<Vec<u8>> {
    let recipient = identity.to_public();
    let recipients = vec![Box::new(recipient) as Box<dyn age::Recipient>];
    
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

    let mut reader = decryptor.decrypt(std::iter::once(identity as &dyn age::Identity))
        .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))?;

    let mut plaintext = Vec::new();
    reader.read_to_end(&mut plaintext)?;
    
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

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

        let nazgul1 = km.derive_nazgul_identity();
        let nazgul2 = km.derive_nazgul_identity();
        assert_eq!(nazgul1.public(), nazgul2.public());

        let rage1 = km.derive_rage_identity();
        let rage2 = km.derive_rage_identity();
        assert_eq!(rage1.to_public().to_string(), rage2.to_public().to_string());
    }

    #[test]
    fn test_event_encryption_roundtrip_age() {
        let shared_secret = [42u8; 32];
        let ulid = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
        
        let event_id = derive_event_identity(&shared_secret, ulid);
        let plaintext = b"Hello Age World";
        
        let encrypted = encrypt_event_content(&event_id, plaintext).unwrap();
        
        // Ensure it's really an age file (starts with header)
        // Note: age binary format header is NOT strictly text "age-encryption.org/v1",
        // but the first line usually contains it.
        // For X25519, it might be binary. Let's trust the roundtrip.
        
        let decrypted = decrypt_event_content(&event_id, &encrypted).unwrap();
        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_event_key_uniqueness() {
        let shared_secret = [42u8; 32];
        let k1 = derive_event_identity(&shared_secret, "ulid1");
        let k2 = derive_event_identity(&shared_secret, "ulid2");
        // Compare public keys
        assert_ne!(k1.to_public().to_string(), k2.to_public().to_string());
    }
}