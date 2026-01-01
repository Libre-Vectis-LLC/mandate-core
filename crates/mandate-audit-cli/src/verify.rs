use anyhow::{Context, Result};
use mandate_core::crypto::signature::Signature;
use mandate_core::event::{Event, EventType, Poll, Vote};
use mandate_core::ids::{ContentHash, EventUlid, RingHash};
use serde::Serialize;
use std::collections::{BTreeMap, HashMap, HashSet};

use crate::client::{AuditClient, EventRecord};
use crate::ring_cache::RingLogCache;

#[derive(Debug, Serialize)]
pub struct VerificationIssue {
    pub sequence_no: i64,
    pub event_ulid: String,
    pub kind: String,
    pub details: String,
}

#[derive(Debug, Serialize)]
pub struct VerificationReport {
    pub group_id: String,
    pub total_events: usize,
    pub event_type_counts: BTreeMap<String, usize>,
    pub chain_verified: bool,
    pub signature_verified: bool,
    pub vote_key_images_verified: bool,
    pub poll_hash_verified: bool,
    pub issues: Vec<VerificationIssue>,
}

pub async fn verify_events(
    client: &mut AuditClient,
    group_id: &str,
    start_seq: i64,
    limit: u32,
) -> Result<VerificationReport> {
    let mut ring_cache = RingLogCache::build(client, group_id, limit)
        .await
        .context("build ring log")?;

    let mut issues = Vec::new();
    let mut total_events = 0usize;
    let mut event_type_counts: BTreeMap<String, usize> = BTreeMap::new();

    let mut last_seq = start_seq;
    let mut last_hash: Option<ContentHash> = None;
    let mut chain_verified = true;
    let mut signature_verified = true;
    let mut vote_key_images_verified = true;
    let mut poll_hash_verified = true;

    let mut poll_hashes: HashMap<String, (ContentHash, RingHash, EventUlid)> = HashMap::new();
    let mut vote_key_images: HashMap<String, HashSet<[u8; 32]>> = HashMap::new();

    loop {
        let records = client
            .stream_events(group_id, last_seq, limit)
            .await
            .context("stream events")?;
        if records.is_empty() {
            break;
        }

        for record in records {
            total_events += 1;
            last_seq = record.sequence_no;

            match process_record(
                &record,
                &mut ring_cache,
                &mut poll_hashes,
                &mut vote_key_images,
                start_seq,
                &mut last_hash,
            ) {
                Ok(event_type_name) => {
                    *event_type_counts.entry(event_type_name).or_insert(0) += 1;
                }
                Err(issue) => {
                    if issue.kind.contains("chain") {
                        chain_verified = false;
                    }
                    if issue.kind.contains("signature") {
                        signature_verified = false;
                    }
                    if issue.kind.contains("vote_key_image") {
                        vote_key_images_verified = false;
                    }
                    if issue.kind.contains("poll_hash") {
                        poll_hash_verified = false;
                    }
                    issues.push(issue);
                }
            }
        }
    }

    Ok(VerificationReport {
        group_id: group_id.to_string(),
        total_events,
        event_type_counts,
        chain_verified,
        signature_verified,
        vote_key_images_verified,
        poll_hash_verified,
        issues,
    })
}

fn process_record(
    record: &EventRecord,
    ring_cache: &mut RingLogCache,
    poll_hashes: &mut HashMap<String, (ContentHash, RingHash, EventUlid)>,
    vote_key_images: &mut HashMap<String, HashSet<[u8; 32]>>,
    start_seq: i64,
    last_hash: &mut Option<ContentHash>,
) -> std::result::Result<String, VerificationIssue> {
    let event: Event =
        serde_json::from_slice(&record.event_bytes).map_err(|e| VerificationIssue {
            sequence_no: record.sequence_no,
            event_ulid: "<parse-failed>".to_string(),
            kind: "parse".to_string(),
            details: format!("event_bytes JSON parse failed: {e}"),
        })?;

    let event_ulid = event.event_ulid.to_string();
    let event_type_name = event_type_name(&event.event_type);

    verify_chain(record.sequence_no, &event, start_seq, last_hash)?;

    verify_signature(record.sequence_no, &event, ring_cache)?;

    if let EventType::PollCreate(poll) = &event.event_type {
        handle_poll(record.sequence_no, &event.event_ulid, poll, poll_hashes)?;
    }

    if let EventType::VoteCast(vote) = &event.event_type {
        handle_vote(
            record.sequence_no,
            &event_ulid,
            vote,
            &event.signature,
            poll_hashes,
            vote_key_images,
        )?;
    }

    Ok(event_type_name.to_string())
}

fn verify_chain(
    sequence_no: i64,
    event: &Event,
    start_seq: i64,
    last_hash: &mut Option<ContentHash>,
) -> std::result::Result<(), VerificationIssue> {
    let content_hash = event.content_hash().map_err(|e| VerificationIssue {
        sequence_no,
        event_ulid: event.event_ulid.to_string(),
        kind: "chain_hash".to_string(),
        details: format!("content hash failed: {e}"),
    })?;

    if last_hash.is_none() && start_seq <= -1 {
        if event.previous_event_hash.0 != [0u8; 32] {
            return Err(VerificationIssue {
                sequence_no,
                event_ulid: event.event_ulid.to_string(),
                kind: "chain_genesis".to_string(),
                details: format!(
                    "expected zero prev hash, got {}",
                    hex::encode(event.previous_event_hash.0)
                ),
            });
        }
    } else if let Some(prev) = last_hash {
        if event.previous_event_hash.0 != prev.0 {
            return Err(VerificationIssue {
                sequence_no,
                event_ulid: event.event_ulid.to_string(),
                kind: "chain_mismatch".to_string(),
                details: format!(
                    "prev hash mismatch expected={}, got={}",
                    hex::encode(prev.0),
                    hex::encode(event.previous_event_hash.0)
                ),
            });
        }
    }

    *last_hash = Some(content_hash);
    Ok(())
}

fn verify_signature(
    sequence_no: i64,
    event: &Event,
    ring_cache: &mut RingLogCache,
) -> std::result::Result<(), VerificationIssue> {
    let sig = event.signature.as_ref().ok_or_else(|| VerificationIssue {
        sequence_no,
        event_ulid: event.event_ulid.to_string(),
        kind: "signature_missing".to_string(),
        details: "event signature missing".to_string(),
    })?;

    let ring_hash = event.event_type.ring_hash();
    if sig.ring_hash() != ring_hash {
        return Err(VerificationIssue {
            sequence_no,
            event_ulid: event.event_ulid.to_string(),
            kind: "signature_ring_hash".to_string(),
            details: format!(
                "signature ring hash mismatch sig={}, event={}",
                hex::encode(sig.ring_hash().0),
                hex::encode(ring_hash.0)
            ),
        });
    }

    let ring = ring_cache
        .ring_for_hash(&ring_hash)
        .map_err(|e| VerificationIssue {
            sequence_no,
            event_ulid: event.event_ulid.to_string(),
            kind: "signature_ring_lookup".to_string(),
            details: e.to_string(),
        })?;

    let msg = event.to_signing_bytes().map_err(|e| VerificationIssue {
        sequence_no,
        event_ulid: event.event_ulid.to_string(),
        kind: "signature_serialization".to_string(),
        details: format!("canonical bytes failed: {e}"),
    })?;

    let ok = sig
        .verify(Some(&ring), &msg)
        .map_err(|e| VerificationIssue {
            sequence_no,
            event_ulid: event.event_ulid.to_string(),
            kind: "signature_verify".to_string(),
            details: format!("signature verify error: {e}"),
        })?;

    if !ok {
        return Err(VerificationIssue {
            sequence_no,
            event_ulid: event.event_ulid.to_string(),
            kind: "signature_invalid".to_string(),
            details: "signature verification returned false".to_string(),
        });
    }

    Ok(())
}

fn handle_poll(
    sequence_no: i64,
    event_ulid: &EventUlid,
    poll: &Poll,
    poll_hashes: &mut HashMap<String, (ContentHash, RingHash, EventUlid)>,
) -> std::result::Result<(), VerificationIssue> {
    let hash = poll.hash().map_err(|e| VerificationIssue {
        sequence_no,
        event_ulid: event_ulid.to_string(),
        kind: "poll_hash".to_string(),
        details: format!("poll hash failed: {e}"),
    })?;

    poll_hashes.insert(poll.poll_id.clone(), (hash, poll.ring_hash, *event_ulid));
    Ok(())
}

fn handle_vote(
    sequence_no: i64,
    event_ulid: &str,
    vote: &Vote,
    signature: &Option<Signature>,
    poll_hashes: &mut HashMap<String, (ContentHash, RingHash, EventUlid)>,
    vote_key_images: &mut HashMap<String, HashSet<[u8; 32]>>,
) -> std::result::Result<(), VerificationIssue> {
    if let Some((expected_hash, expected_ring, _poll_ulid)) = poll_hashes.get(&vote.poll_id) {
        if vote.poll_hash.0 != expected_hash.0 {
            return Err(VerificationIssue {
                sequence_no,
                event_ulid: event_ulid.to_string(),
                kind: "poll_hash_mismatch".to_string(),
                details: format!(
                    "vote poll hash mismatch expected={}, got={}",
                    hex::encode(expected_hash.0),
                    hex::encode(vote.poll_hash.0)
                ),
            });
        }
        if vote.ring_hash != *expected_ring {
            return Err(VerificationIssue {
                sequence_no,
                event_ulid: event_ulid.to_string(),
                kind: "poll_ring_hash_mismatch".to_string(),
                details: format!(
                    "vote ring hash mismatch expected={}, got={}",
                    hex::encode(expected_ring.0),
                    hex::encode(vote.ring_hash.0)
                ),
            });
        }
    } else {
        return Err(VerificationIssue {
            sequence_no,
            event_ulid: event_ulid.to_string(),
            kind: "poll_hash_missing".to_string(),
            details: format!("poll_id {} not found before vote", vote.poll_id),
        });
    }

    let sig = signature.as_ref().ok_or_else(|| VerificationIssue {
        sequence_no,
        event_ulid: event_ulid.to_string(),
        kind: "vote_key_image_missing".to_string(),
        details: "vote signature missing".to_string(),
    })?;

    let key_image_bytes = sig.key_image().compress().to_bytes();
    let entry = vote_key_images.entry(vote.poll_id.clone()).or_default();
    if entry.contains(&key_image_bytes) {
        return Err(VerificationIssue {
            sequence_no,
            event_ulid: event_ulid.to_string(),
            kind: "vote_key_image_duplicate".to_string(),
            details: format!("duplicate key image for poll {}", vote.poll_id),
        });
    }
    entry.insert(key_image_bytes);

    Ok(())
}

fn event_type_name(event_type: &EventType) -> &'static str {
    match event_type {
        EventType::PollCreate(_) => "PollCreate",
        EventType::VoteCast(_) => "VoteCast",
        EventType::MessageCreate(_) => "MessageCreate",
        EventType::RingUpdate(_) => "RingUpdate",
        EventType::BanCreate(_) => "BanCreate",
        EventType::BanRevoke(_) => "BanRevoke",
        EventType::ProofOfInnocence(_) => "ProofOfInnocence",
    }
}
