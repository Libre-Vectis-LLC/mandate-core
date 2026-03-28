//! PollBundle generation with real BLSAG ring signatures.
//!
//! Creates a PollCreate event and VoteCast events with genuine BLSAG
//! signatures, then packages them into a PollBundle protobuf.

use std::collections::HashMap;
use std::io::Write as _;
use std::path::Path;

use mandate_core::crypto::ciphertext::Ciphertext;
use mandate_core::crypto::signature::{sign_contextual, SignatureKind, StorageMode};
use mandate_core::event::{
    Event, EventType, Poll, PollOption, PollQuestion, PollQuestionKind, Vote, VoteSelection,
};
use mandate_core::hashing::ring_hash;
use mandate_core::ids::{EventId, EventUlid, OrganizationId, RingHash};
use mandate_core::key_manager::manager::derive_poll_signing_ring;
use mandate_core::key_manager::{derive_poll_key_bytes, encrypt_event_content, MandateDerivable};
use mandate_verify::bundle::{OptionDef, PollBundle};
use nazgul::keypair::KeyPair as NazgulKeyPair;
use nazgul::ring::Ring;
use nazgul::traits::LocalByteConvertible;
use rand::seq::SliceRandom;

use crate::config::BountyConfig;
use crate::solution_bundle::SolutionBundle;

/// Generate the PollBundle and write it to `output`.
pub fn generate_poll_bundle(
    config: &BountyConfig,
    bundle: &SolutionBundle,
    output: &Path,
) -> anyhow::Result<()> {
    let org_id: OrganizationId = config
        .poll
        .org_id
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid org_id: {}", config.poll.org_id))?;

    let poll_event_ulid = EventUlid(
        ulid::Ulid::from_string(&config.poll.poll_ulid)
            .map_err(|e| anyhow::anyhow!("invalid poll_ulid: {e}"))?,
    );

    // Reconstruct keypairs from the solution bundle.
    let keypairs = reconstruct_keypairs(bundle)?;

    // Build master ring from all voter public keys.
    let pub_keys: Vec<curve25519_dalek::ristretto::RistrettoPoint> =
        keypairs.iter().map(|kp| *kp.public()).collect();
    let master_ring = Ring::new(pub_keys);
    let master_ring_hash = ring_hash(&master_ring);

    // Derive k_shared (for the bounty, use SHA3-256 of org_id like production.rs).
    let k_shared: [u8; 32] = {
        use sha3::Digest;
        sha3::Sha3_256::digest(config.poll.org_id.as_bytes()).into()
    };

    // Derive poll encryption key.
    let poll_key_bytes = derive_poll_key_bytes(&k_shared, &poll_event_ulid);
    let poll_identity = age::x25519::Identity::from_secret_bytes(poll_key_bytes);
    let poll_key_hex = hex::encode(poll_key_bytes);

    // Helper: encrypt plaintext with the poll key.
    let encrypt = |plaintext: &[u8]| -> anyhow::Result<Ciphertext> {
        let ct = encrypt_event_content(&poll_identity, plaintext)
            .map_err(|e| anyhow::anyhow!("age encryption failed: {e}"))?;
        Ok(Ciphertext(ct))
    };

    // Build PollCreate event.
    let poll = build_poll(config, org_id, master_ring_hash, &encrypt)?;
    let poll_hash = poll
        .hash()
        .map_err(|e| anyhow::anyhow!("failed to hash poll: {e}"))?;

    // Sign PollCreate with the first voter's keypair (any ring member works).
    let poll_event_raw =
        sign_poll_create(org_id, poll_event_ulid, &poll, &keypairs[0], &master_ring)?;

    eprintln!("    PollCreate signed");

    // Derive per-poll signing ring.
    let poll_id = &config.poll.poll_ulid;
    let vote_ring = derive_poll_signing_ring(&org_id, &master_ring_hash, poll_id, &master_ring);
    let vote_ring_hash = ring_hash(&vote_ring);

    // Validate that every solution option is a known config option ID.
    let valid_option_ids: std::collections::HashSet<&str> = config
        .poll
        .options
        .iter()
        .map(|opt| opt.id.as_str())
        .collect();
    for entry in &bundle.solution {
        anyhow::ensure!(
            valid_option_ids.contains(entry.option.as_str()),
            "solution option {:?} is not a valid poll option ID (valid: {:?})",
            entry.option,
            valid_option_ids
        );
    }

    // Build pubkey -> option_id mapping for vote generation.
    let vote_map: HashMap<&str, &str> = bundle
        .solution
        .iter()
        .map(|e| (e.pubkey_bs58.as_str(), e.option.as_str()))
        .collect();

    // Sign all VoteCast events in randomized order.
    //
    // Each VoteCast event contains a ULID with a millisecond timestamp from
    // `Ulid::new()`.  If we iterated `keypairs` sequentially, the monotonic
    // ULID timestamps would directly encode each voter's index — an attacker
    // could sort by timestamp to recover the voter → vote mapping.
    //
    // To simulate realistic server-side reception order (where voters submit
    // at unpredictable times through Tor), we shuffle the generation order so
    // that ULID timestamps are decorrelated from the keypair array index.
    let mut gen_order: Vec<usize> = (0..keypairs.len()).collect();
    gen_order.shuffle(&mut rand::rngs::OsRng);

    let mut vote_events_raw: Vec<Vec<u8>> = Vec::with_capacity(keypairs.len());
    for (progress, &voter_idx) in gen_order.iter().enumerate() {
        let kp = &keypairs[voter_idx];
        let pubkey_bs58 = LocalByteConvertible::to_base58(kp.public());
        let option_id = vote_map
            .get(pubkey_bs58.as_str())
            .ok_or_else(|| anyhow::anyhow!("voter {voter_idx} pubkey not found in solution"))?;

        let vote_signer = kp.derive_poll_signing(&org_id, &master_ring_hash, poll_id);
        let event_bytes = sign_vote_cast(
            org_id,
            vote_ring_hash,
            master_ring_hash,
            poll_id,
            poll_hash,
            option_id,
            vote_signer.as_keypair(),
            &vote_ring,
        )?;
        vote_events_raw.push(event_bytes);

        if (progress + 1) % 100 == 0 || progress + 1 == keypairs.len() {
            eprintln!("    VoteCast signed: {}/{}", progress + 1, keypairs.len());
        }
    }

    // Defense in depth: shuffle the final array as well.
    vote_events_raw.shuffle(&mut rand::rngs::OsRng);

    // Build PollBundle.
    let ring_member_pubs: Vec<String> = {
        let mut pubs: Vec<String> = keypairs
            .iter()
            .map(|kp| bs58::encode(kp.public().compress().as_bytes()).into_string())
            .collect();
        pubs.sort();
        pubs
    };

    let option_definitions: Vec<OptionDef> = config
        .poll
        .options
        .iter()
        .map(|opt| OptionDef {
            option_id: opt.id.clone(),
            option_text_zhs: opt.text_zh.clone(),
        })
        .collect();

    let poll_bundle = PollBundle {
        poll_event_raw,
        vote_events_raw,
        ring_member_pubs,
        org_id: config.poll.org_id.clone(),
        poll_ulid: config.poll.poll_ulid.clone(),
        poll_key_hex,
        poll_title: config.poll.title_zh.clone(),
        option_definitions,
        revocation_events_raw: Vec::new(),
    };

    // Write bundle.
    let bytes = poll_bundle.to_bytes();
    let mut f = std::fs::File::create(output)?;
    f.write_all(&bytes)?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Reconstruct NazgulKeyPairs from the SolutionBundle's private key material.
fn reconstruct_keypairs(bundle: &SolutionBundle) -> anyhow::Result<Vec<NazgulKeyPair>> {
    let mut keypairs = Vec::with_capacity(bundle.voter_private_keys.len());
    for (i, vpk) in bundle.voter_private_keys.iter().enumerate() {
        let kp = NazgulKeyPair::from_base58(vpk.scalar_bs58.clone())
            .map_err(|e| anyhow::anyhow!("failed to reconstruct keypair {i}: {e}"))?;

        // Verify the reconstructed public key matches.
        let reconstructed_pub = LocalByteConvertible::to_base58(kp.public());
        anyhow::ensure!(
            reconstructed_pub == vpk.pubkey_bs58,
            "keypair {i}: reconstructed pubkey ({reconstructed_pub}) does not match expected ({})",
            vpk.pubkey_bs58
        );

        keypairs.push(kp);
    }
    Ok(keypairs)
}

/// Build the Poll struct with encrypted fields.
fn build_poll(
    config: &BountyConfig,
    org_id: OrganizationId,
    master_ring_hash: RingHash,
    encrypt: &dyn Fn(&[u8]) -> anyhow::Result<Ciphertext>,
) -> anyhow::Result<Poll> {
    let options: Vec<PollOption> = config
        .poll
        .options
        .iter()
        .map(|opt| {
            Ok(PollOption {
                id: opt.id.clone(),
                text: encrypt(opt.text_zh.as_bytes())?,
            })
        })
        .collect::<anyhow::Result<Vec<_>>>()?;

    let poll = Poll {
        org_id,
        ring_hash: master_ring_hash,
        poll_id: config.poll.poll_ulid.clone(),
        questions: vec![PollQuestion {
            question_id: "q1".to_string(),
            title: encrypt(config.poll.title_zh.as_bytes())?,
            kind: PollQuestionKind::MultipleChoice { options, max: 1 },
        }],
        created_at: 1,
        instructions: None,
        deadline: None,
        sealed_duration_secs: None,
        verification_window_secs: None,
    };

    Ok(poll)
}

/// Create and sign a PollCreate event, returning the serialized bytes.
fn sign_poll_create(
    org_id: OrganizationId,
    poll_event_ulid: EventUlid,
    poll: &Poll,
    signer: &NazgulKeyPair,
    ring: &Ring,
) -> anyhow::Result<Vec<u8>> {
    let mut event = Event {
        event_ulid: poll_event_ulid,
        previous_event_hash: EventId([0u8; 32]),
        org_id,
        sequence_no: None,
        processed_at: 0,
        serialization_version: 1,
        event_type: EventType::PollCreate(poll.clone()),
        signature: None,
    };

    let signing_bytes = event
        .to_signing_bytes()
        .map_err(|e| anyhow::anyhow!("PollCreate signing bytes: {e}"))?;

    let sig = sign_contextual(
        SignatureKind::Anonymous,
        StorageMode::Archival,
        signer,
        ring,
        &signing_bytes,
    )
    .map_err(|e| anyhow::anyhow!("PollCreate sign failed: {e}"))?;

    event.signature = Some(sig);
    let bytes = serde_json::to_vec(&event)?;
    Ok(bytes)
}

/// Create and sign a VoteCast event, returning the serialized bytes.
#[allow(clippy::too_many_arguments)]
fn sign_vote_cast(
    org_id: OrganizationId,
    vote_ring_hash: RingHash,
    master_ring_hash: RingHash,
    poll_id: &str,
    poll_hash: mandate_core::ids::ContentHash,
    option_id: &str,
    vote_signer: &NazgulKeyPair,
    vote_ring: &Ring,
) -> anyhow::Result<Vec<u8>> {
    let vote = Vote {
        org_id,
        ring_hash: vote_ring_hash,
        poll_id: poll_id.to_string(),
        poll_hash,
        poll_ring_hash: master_ring_hash,
        selections: vec![VoteSelection {
            question_id: "q1".into(),
            option_ids: vec![option_id.to_string()],
            write_in: None,
        }],
    };

    let mut event = Event {
        event_ulid: EventUlid(ulid::Ulid::new()),
        previous_event_hash: EventId([0u8; 32]),
        org_id,
        sequence_no: None,
        processed_at: 0,
        serialization_version: 1,
        event_type: EventType::VoteCast(vote),
        signature: None,
    };

    let signing_bytes = event
        .to_signing_bytes()
        .map_err(|e| anyhow::anyhow!("VoteCast signing bytes: {e}"))?;

    let sig = sign_contextual(
        SignatureKind::Anonymous,
        StorageMode::Compact,
        vote_signer,
        vote_ring,
        &signing_bytes,
    )
    .map_err(|e| anyhow::anyhow!("VoteCast sign failed: {e}"))?;

    event.signature = Some(sig);
    let bytes = serde_json::to_vec(&event)?;
    Ok(bytes)
}
