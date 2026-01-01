use anyhow::{Context, Result};
use mandate_core::hashing::ring_hash_sha3_256;
use mandate_core::ids::RingHash;
use mandate_core::proto::ring_delta_from_bytes;
use mandate_core::ring_log::RingDeltaLog;
use mandate_proto::mandate::v1::RingDeltaEntry;
use nazgul::ring::Ring;
use std::collections::HashMap;

use crate::client::AuditClient;

pub struct RingLogCache {
    log: RingDeltaLog,
    cache: HashMap<RingHash, Ring>,
}

impl RingLogCache {
    pub async fn build(client: &mut AuditClient, group_id: &str, limit: u32) -> Result<Self> {
        let mut log = RingDeltaLog::default();
        let mut ring = Ring::new(Vec::new());
        let mut cache: HashMap<RingHash, Ring> = HashMap::new();

        let mut cursor: Vec<u8> = Vec::new();
        loop {
            let response = client
                .stream_ring(group_id, cursor.clone(), limit)
                .await
                .context("stream_ring failed")?;
            if response.entries.is_empty() {
                break;
            }
            for entry in response.entries {
                Self::apply_entry(&mut log, &mut ring, &mut cache, entry)?;
            }
            if response.next_ring_hash.is_empty() {
                break;
            }
            cursor = response.next_ring_hash;
        }

        Ok(Self { log, cache })
    }

    pub fn ring_for_hash(&mut self, ring_hash: &RingHash) -> Result<Ring> {
        if let Some(ring) = self.cache.get(ring_hash) {
            return Ok(ring.clone());
        }
        let ring = self
            .log
            .reconstruct(ring_hash, None)
            .context("ring reconstruction failed")?;
        self.cache.insert(*ring_hash, ring.clone());
        Ok(ring)
    }

    fn apply_entry(
        log: &mut RingDeltaLog,
        ring: &mut Ring,
        cache: &mut HashMap<RingHash, Ring>,
        entry: RingDeltaEntry,
    ) -> Result<()> {
        let expected = ring_hash_from_bytes(&entry.ring_hash)?;
        let mut last_hash: Option<RingHash> = None;
        for delta_bytes in entry.deltas {
            let delta = ring_delta_from_bytes(&delta_bytes).context("invalid ring delta")?;
            let (hash, _) = log.append(ring, delta).context("append ring delta")?;
            cache.insert(hash, ring.clone());
            last_hash = Some(hash);
        }
        if let Some(hash) = last_hash {
            if hash != expected {
                let computed = ring_hash_sha3_256(ring);
                anyhow::bail!(
                    "ring hash mismatch: entry={}, last_delta={}, computed={}",
                    hex::encode(expected.0),
                    hex::encode(hash.0),
                    hex::encode(computed.0)
                );
            }
        }
        Ok(())
    }
}

pub fn ring_hash_from_bytes(bytes: &[u8]) -> Result<RingHash> {
    let hash: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid ring hash length: {}", bytes.len()))?;
    Ok(RingHash(hash))
}
