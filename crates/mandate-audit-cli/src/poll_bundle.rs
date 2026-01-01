use anyhow::{Context, Result};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use mandate_core::event::{Event, EventType, Poll};
use mandate_core::key_manager::manager::derive_poll_key_bytes;
use secrecy::ExposeSecret;
use std::fs;
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

use crate::client::AuditClient;

#[derive(Debug, serde::Serialize)]
pub struct PollBundleManifest {
    pub group_id: String,
    pub poll_id: String,
    pub poll_event_ulid: String,
    pub poll_hash_hex: String,
    pub ring_hash_hex: String,
    pub poll_key_hex: String,
    pub poll_key_age_secret: String,
    pub vote_count: usize,
    pub votes: Vec<PollVoteEntry>,
}

#[derive(Debug, serde::Serialize)]
pub struct PollVoteEntry {
    pub event_ulid: String,
    pub sequence_no: i64,
    pub key_image_hex: Option<String>,
    pub event_json_path: String,
    pub event_bytes_path: String,
}

pub struct PollBundleOptions {
    pub group_id: String,
    pub poll_id: Option<String>,
    pub poll_event_ulid: Option<String>,
    pub k_shared_hex: String,
    pub output_dir: PathBuf,
    pub limit: u32,
}

pub async fn export_poll_bundle(
    client: &mut AuditClient,
    options: PollBundleOptions,
) -> Result<PollBundleManifest> {
    let k_shared = parse_hex_32(&options.k_shared_hex).context("invalid k_shared_hex")?;

    let mut poll_event: Option<(Event, Vec<u8>, i64)> = None;
    let mut poll_id_match: Option<String> = options.poll_id.clone();
    let mut votes: Vec<(Event, Vec<u8>, i64)> = Vec::new();

    let mut start_seq = -1;
    loop {
        let records = client
            .stream_events(&options.group_id, start_seq, options.limit)
            .await
            .context("stream events")?;
        if records.is_empty() {
            break;
        }
        for record in records {
            start_seq = record.sequence_no;
            if let Ok(event) = serde_json::from_slice::<Event>(&record.event_bytes) {
                match &event.event_type {
                    EventType::PollCreate(poll) => {
                        if matches_poll(&event, poll, &options) {
                            poll_id_match = Some(poll.poll_id.clone());
                            poll_event = Some((
                                event.clone(),
                                record.event_bytes.clone(),
                                record.sequence_no,
                            ));
                        }
                    }
                    EventType::VoteCast(vote) => {
                        if let Some(ref poll_id) = poll_id_match {
                            if vote.poll_id == *poll_id {
                                votes.push((
                                    event.clone(),
                                    record.event_bytes.clone(),
                                    record.sequence_no,
                                ));
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    let (poll_event, poll_bytes, _poll_seq) = poll_event.context("poll event not found")?;
    let poll = match &poll_event.event_type {
        EventType::PollCreate(poll) => poll,
        _ => anyhow::bail!("matched poll event is not PollCreate"),
    };

    let poll_hash = poll.hash().context("compute poll hash")?;
    let poll_key = derive_poll_key_bytes(&k_shared, &poll_event.event_ulid);
    let poll_key_hex = hex::encode(poll_key);
    let poll_key_age_secret = age::x25519::Identity::from_secret_bytes(poll_key).to_string();
    let poll_key_age = poll_key_age_secret.expose_secret().to_string();
    let mut poll_key_zeroize = poll_key;
    poll_key_zeroize.zeroize();

    fs::create_dir_all(&options.output_dir).context("create output dir")?;
    let votes_dir = options.output_dir.join("votes");
    fs::create_dir_all(&votes_dir).context("create votes dir")?;

    let poll_event_json_path = options.output_dir.join("poll_event.json");
    let poll_event_bytes_path = options.output_dir.join("poll_event.bytes.b64");
    write_json(&poll_event_json_path, &poll_event)?;
    write_base64(&poll_event_bytes_path, &poll_bytes)?;

    let mut vote_entries = Vec::new();
    for (idx, (event, bytes, seq)) in votes.iter().enumerate() {
        let event_ulid = event.event_ulid.to_string();
        let key_image_hex = event
            .signature
            .as_ref()
            .map(|sig| hex::encode(sig.key_image().compress().to_bytes()));
        let json_path = votes_dir.join(format!("vote-{}-{}.json", idx + 1, event_ulid));
        let bytes_path = votes_dir.join(format!("vote-{}-{}.bytes.b64", idx + 1, event_ulid));
        write_json(&json_path, event)?;
        write_base64(&bytes_path, bytes)?;

        vote_entries.push(PollVoteEntry {
            event_ulid,
            sequence_no: *seq,
            key_image_hex,
            event_json_path: json_path.display().to_string(),
            event_bytes_path: bytes_path.display().to_string(),
        });
    }

    let manifest = PollBundleManifest {
        group_id: options.group_id.clone(),
        poll_id: poll.poll_id.clone(),
        poll_event_ulid: poll_event.event_ulid.to_string(),
        poll_hash_hex: hex::encode(poll_hash.0),
        ring_hash_hex: hex::encode(poll.ring_hash.0),
        poll_key_hex,
        poll_key_age_secret: poll_key_age,
        vote_count: vote_entries.len(),
        votes: vote_entries,
    };

    let manifest_path = options.output_dir.join("bundle.json");
    write_json(&manifest_path, &manifest)?;

    Ok(manifest)
}

fn matches_poll(event: &Event, poll: &Poll, options: &PollBundleOptions) -> bool {
    if let Some(ref ulid) = options.poll_event_ulid {
        return event.event_ulid.to_string() == *ulid;
    }
    if let Some(ref poll_id) = options.poll_id {
        return poll.poll_id == *poll_id;
    }
    false
}

fn parse_hex_32(hex_str: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(hex_str).context("hex decode failed")?;
    let len = bytes.len();
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("expected 32 bytes, got {}", len))?;
    Ok(arr)
}

fn write_json<T: serde::Serialize>(path: &Path, value: &T) -> Result<()> {
    let json = serde_json::to_vec_pretty(value).context("serialize json")?;
    fs::write(path, json).with_context(|| format!("write {:?}", path))?;
    Ok(())
}

fn write_base64(path: &Path, bytes: &[u8]) -> Result<()> {
    let encoded = BASE64_STANDARD.encode(bytes);
    fs::write(path, encoded).with_context(|| format!("write {:?}", path))?;
    Ok(())
}
