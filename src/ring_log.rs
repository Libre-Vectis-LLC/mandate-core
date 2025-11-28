//! Ring delta log and reconstruction helpers (single-node, append-only).
//!
//! - Entries are `(RingHash, RingDelta)`; duplicate hashes are allowed (e.g., remove
//!   then re-add a member).
//! - No distributed/storage complexity: append-only vector plus in-memory index.
//! - Reconstruction picks the shortest forward/backward path between an anchor ring
//!   (optional) and the target hash.

use crate::hashing::ring_hash_sha3_256;
use crate::ids::{MasterPublicKey, RingHash};
use nazgul::ring::Ring;
use nazgul::traits::LocalByteConvertible;
use std::collections::HashMap;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RingDelta {
    Add(MasterPublicKey),
    Remove(MasterPublicKey),
}

#[derive(Debug, thiserror::Error)]
pub enum RingLogError {
    #[error("target ring hash not found in log")]
    TargetNotFound,
    #[error("anchor ring hash not found in log")]
    AnchorNotFound,
    #[error("invalid master public key bytes")]
    InvalidKey,
}

/// Append-only log of ring deltas.
#[derive(Default, Clone, Debug)]
pub struct RingDeltaLog {
    entries: Vec<(RingHash, RingDelta)>,
    index: HashMap<RingHash, Vec<usize>>, // hash -> positions
}

impl RingDeltaLog {
    /// Seed the log from a founder public key; first entry is the founder add.
    pub fn new(founder: MasterPublicKey) -> Result<Self, RingLogError> {
        let mut ring = Ring::new(vec![]);
        let mut entries = Vec::new();
        let mut index: HashMap<RingHash, Vec<usize>> = HashMap::new();

        let delta = RingDelta::Add(founder);
        apply_delta(&mut ring, &delta)?;
        let h = ring_hash_sha3_256(&ring);
        entries.push((h, delta));
        index.insert(h, vec![0]);

        Ok(Self { entries, index })
    }

    /// Append a delta, updating the provided ring in-place. Returns (new hash, index).
    pub fn append(
        &mut self,
        ring: &mut Ring,
        delta: RingDelta,
    ) -> Result<(RingHash, usize), RingLogError> {
        apply_delta(ring, &delta)?;
        let hash = ring_hash_sha3_256(ring);
        let idx = self.entries.len();
        self.entries.push((hash, delta));
        self.index.entry(hash).or_default().push(idx);
        Ok((hash, idx))
    }

    /// Reconstruct target ring via shortest forward/backward replay.
    /// If `anchor` is None, start from an empty ring.
    pub fn reconstruct(
        &self,
        target: &RingHash,
        anchor: Option<&Ring>,
    ) -> Result<Ring, RingLogError> {
        let target_positions = self.index.get(target).ok_or(RingLogError::TargetNotFound)?;

        let (mut ring, anchor_positions) = match anchor {
            Some(r) => {
                let h = ring_hash_sha3_256(r);
                let pos = self.index.get(&h).ok_or(RingLogError::AnchorNotFound)?;
                (r.clone(), pos.clone())
            }
            None => (Ring::new(vec![]), vec![0]),
        };

        // choose minimal distance pair
        let mut best: Option<(usize, usize, isize)> = None;
        for &a in &anchor_positions {
            for &t in target_positions {
                let dist = (t as isize - a as isize).abs();
                if best.map(|b| dist < b.2).unwrap_or(true) {
                    best = Some((a, t, dist));
                }
            }
        }
        // `best` is always set because both `target_positions` and `anchor_positions`
        // are non-empty: we validated the hashes via the index lookups above.
        let (a_idx, t_idx, _) =
            best.expect("non-empty anchor/target positions guaranteed by index lookups");

        if a_idx == t_idx {
            return Ok(ring);
        }

        if a_idx < t_idx {
            for (_, delta) in self.entries.iter().skip(a_idx + 1).take(t_idx - a_idx) {
                apply_delta(&mut ring, delta)?;
            }
        } else {
            for (_, delta) in self
                .entries
                .iter()
                .skip(t_idx + 1)
                .take(a_idx - t_idx)
                .rev()
            {
                apply_inverse_delta(&mut ring, delta)?;
            }
        }

        Ok(ring)
    }
}

fn apply_delta(ring: &mut Ring, delta: &RingDelta) -> Result<(), RingLogError> {
    match delta {
        RingDelta::Add(pk) => {
            let point = point_from(pk)?;
            ring.add_public_key(point);
        }
        RingDelta::Remove(pk) => {
            let point = point_from(pk)?;
            let _ = ring.remove_public_key(point);
        }
    }
    Ok(())
}

fn apply_inverse_delta(ring: &mut Ring, delta: &RingDelta) -> Result<(), RingLogError> {
    match delta {
        RingDelta::Add(pk) => {
            let point = point_from(pk)?;
            let _ = ring.remove_public_key(point);
        }
        RingDelta::Remove(pk) => {
            let point = point_from(pk)?;
            ring.add_public_key(point);
        }
    }
    Ok(())
}

fn point_from(pk: &MasterPublicKey) -> Result<nazgul::scalar::RistrettoPoint, RingLogError> {
    nazgul::scalar::RistrettoPoint::from_bytes(&pk.0).map_err(|_| RingLogError::InvalidKey)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nazgul::traits::LocalByteConvertible;
    use sha3::Sha3_512;

    fn mpk(label: &[u8]) -> MasterPublicKey {
        let point = nazgul::scalar::RistrettoPoint::hash_from_bytes::<Sha3_512>(label);
        MasterPublicKey(point.to_bytes())
    }

    #[test]
    fn reconstruct_chooses_shortest_path_forward() {
        let founder = nazgul::scalar::RistrettoPoint::hash_from_bytes::<Sha3_512>(b"a");
        let mut log = RingDeltaLog::new(MasterPublicKey(founder.to_bytes()))
            .expect("founder add cannot fail");
        let mut ring = Ring::new(vec![founder]);

        // Add b, c, remove b (b added again later)
        let (_h1, _) = log
            .append(&mut ring, RingDelta::Add(mpk(b"b")))
            .expect("append must succeed in test fixture");
        let (h2, _) = log
            .append(&mut ring, RingDelta::Add(mpk(b"c")))
            .expect("append must succeed in test fixture");
        let (_h3, _) = log
            .append(&mut ring, RingDelta::Remove(mpk(b"b")))
            .expect("append must succeed in test fixture");
        let (_h4, _) = log
            .append(&mut ring, RingDelta::Add(mpk(b"b")))
            .expect("append must succeed in test fixture");

        let restored = log
            .reconstruct(&h2, Some(&ring))
            .expect("reconstruct should succeed in test fixture");
        let ring_hash = ring_hash_sha3_256(&restored);
        assert_eq!(ring_hash, h2);
        assert_eq!(restored.members().len(), 3);
    }

    #[test]
    fn reconstruct_backward_path() {
        let genesis_point = nazgul::scalar::RistrettoPoint::hash_from_bytes::<Sha3_512>(b"a");
        let genesis = Ring::new(vec![genesis_point]);
        let mut log = RingDeltaLog::new(MasterPublicKey(genesis_point.to_bytes()))
            .expect("founder add cannot fail");
        let mut ring = genesis.clone();

        let (_h_anchor, _) = log
            .append(&mut ring, RingDelta::Add(mpk(b"b")))
            .expect("append must succeed in test fixture");
        let ring_at_h1 = ring.clone();
        let (_h2, _) = log
            .append(&mut ring, RingDelta::Add(mpk(b"c")))
            .expect("append must succeed in test fixture");

        let restored = log
            .reconstruct(&ring_hash_sha3_256(&genesis), Some(&ring_at_h1))
            .expect("reconstruct should succeed in test fixture");
        let ring_hash = ring_hash_sha3_256(&restored);
        assert_eq!(ring_hash, ring_hash_sha3_256(&genesis));
        assert_eq!(restored.members().len(), 1);

        assert!(log.index.get(&ring_hash_sha3_256(&ring_at_h1)).is_some());
    }
}
