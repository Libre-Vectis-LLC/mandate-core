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

    /// Latest ring hash if any entries exist.
    pub fn head_hash(&self) -> Option<&RingHash> {
        self.entries.last().map(|(h, _)| h)
    }

    /// First ring hash (after initial delta), if any entries exist.
    pub fn genesis_hash(&self) -> Option<&RingHash> {
        self.entries.first().map(|(h, _)| h)
    }

    /// Produce a delta path from an optional anchor to a target hash.
    pub fn delta_path(
        &self,
        anchor: Option<&RingHash>,
        target: &RingHash,
    ) -> Result<Vec<RingDelta>, RingLogError> {
        let anchored = anchor.is_some();
        let anchor_hash = anchor.copied().or_else(|| self.genesis_hash().copied());
        let anchor_hash = anchor_hash.ok_or(RingLogError::AnchorNotFound)?;

        let anchor_positions = self
            .index
            .get(&anchor_hash)
            .ok_or(RingLogError::AnchorNotFound)?;
        let target_positions = self.index.get(target).ok_or(RingLogError::TargetNotFound)?;

        let (a_idx, t_idx) = Self::shortest_indices(anchor_positions, target_positions)?;

        if a_idx == t_idx {
            // Same position: if unanchored, replay from the beginning to build the ring.
            if anchored {
                return Ok(Vec::new());
            }
            return Ok(self
                .entries
                .iter()
                .take(a_idx + 1)
                .map(|(_, d)| d.clone())
                .collect());
        }

        if a_idx < t_idx {
            // Forward path (anchor -> target).
            let start = if anchored { a_idx + 1 } else { 0 };
            let count = t_idx.saturating_sub(start) + 1;
            let deltas = self
                .entries
                .iter()
                .skip(start)
                .take(count)
                .map(|(_, d)| d.clone())
                .collect();
            Ok(deltas)
        } else {
            // Backward path: invert deltas in reverse order.
            let start = if anchored { t_idx + 1 } else { t_idx };
            let count = a_idx.saturating_sub(start) + 1;
            let deltas = self
                .entries
                .iter()
                .skip(start)
                .take(count)
                .rev()
                .map(|(_, d)| invert_delta(d))
                .collect();
            Ok(deltas)
        }
    }

    /// Reconstruct target ring via shortest forward/backward replay.
    /// If `anchor` is None, start from an empty ring.
    pub fn reconstruct(
        &self,
        target: &RingHash,
        anchor: Option<&Ring>,
    ) -> Result<Ring, RingLogError> {
        let (mut ring, span) = self.shortest_span(target, anchor)?;
        let (a_idx, t_idx, anchored) = span;

        if a_idx == t_idx {
            // Anchor None means we started from empty ring; need to apply deltas up to target.
            if anchor.is_none() {
                for (_, delta) in self.entries.iter().take(t_idx + 1) {
                    apply_delta(&mut ring, delta)?;
                }
            }
            return Ok(ring);
        }

        if a_idx < t_idx {
            // If no anchor was provided, the current ring may not correspond to any entry;
            // include the delta at a_idx. When anchor exists, start after the anchor.
            let start = if anchored { a_idx + 1 } else { a_idx };
            let count = t_idx.saturating_sub(start) + 1;
            for (_, delta) in self.entries.iter().skip(start).take(count) {
                apply_delta(&mut ring, delta)?;
            }
        } else {
            // Backward replay uses inverse deltas; include a_idx when anchor is absent.
            let start = if anchored { t_idx + 1 } else { t_idx };
            let count = a_idx.saturating_sub(start) + 1;
            for (_, delta) in self.entries.iter().skip(start).take(count).rev() {
                apply_inverse_delta(&mut ring, delta)?;
            }
        }

        Ok(ring)
    }

    /// Return (anchor_idx, target_idx, anchored_flag) for the minimal-distance pair.
    fn shortest_span(
        &self,
        target: &RingHash,
        anchor: Option<&Ring>,
    ) -> Result<(Ring, (usize, usize, bool)), RingLogError> {
        let target_positions = self.index.get(target).ok_or(RingLogError::TargetNotFound)?;

        let (ring, anchor_positions, anchored) = match anchor {
            Some(r) => {
                let h = ring_hash_sha3_256(r);
                let pos = self.index.get(&h).ok_or(RingLogError::AnchorNotFound)?;
                (r.clone(), pos.clone(), true)
            }
            None => {
                let empty = Ring::new(vec![]);
                let pos = if self.entries.is_empty() {
                    vec![]
                } else {
                    vec![0]
                };
                (empty, pos, false)
            }
        };

        if anchor_positions.is_empty() {
            return Err(RingLogError::AnchorNotFound);
        }

        let mut best: Option<(usize, usize, isize)> = None;
        for &a in &anchor_positions {
            for &t in target_positions {
                let dist = (t as isize - a as isize).abs();
                if best.map(|b| dist < b.2).unwrap_or(true) {
                    best = Some((a, t, dist));
                }
            }
        }

        let (a_idx, t_idx, _) =
            best.expect("non-empty anchor/target positions guaranteed by index lookups");

        Ok((ring, (a_idx, t_idx, anchored)))
    }

    fn shortest_indices(
        anchor_positions: &[usize],
        target_positions: &[usize],
    ) -> Result<(usize, usize), RingLogError> {
        let mut best: Option<(usize, usize, isize)> = None;
        for &a in anchor_positions {
            for &t in target_positions {
                let dist = (t as isize - a as isize).abs();
                if best.map(|b| dist < b.2).unwrap_or(true) {
                    best = Some((a, t, dist));
                }
            }
        }
        let (a, t, _) = best.ok_or(RingLogError::AnchorNotFound)?;
        Ok((a, t))
    }
}

pub(crate) fn apply_delta(ring: &mut Ring, delta: &RingDelta) -> Result<(), RingLogError> {
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

fn invert_delta(delta: &RingDelta) -> RingDelta {
    match delta {
        RingDelta::Add(pk) => RingDelta::Remove(*pk),
        RingDelta::Remove(pk) => RingDelta::Add(*pk),
    }
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

    #[test]
    fn founder_only_reconstruction() {
        let founder = mpk(b"founder");
        let log = RingDeltaLog::new(founder.clone()).expect("new log");

        let ring = Ring::new(vec![point_from(&founder).unwrap()]);
        let target_hash = ring_hash_sha3_256(&ring);

        let reconstructed = log.reconstruct(&target_hash, None).expect("reconstruct");
        assert_eq!(ring_hash_sha3_256(&reconstructed), target_hash);
        assert_eq!(reconstructed.members().len(), 1);
    }

    #[test]
    fn delta_path_backward_respects_target() {
        // Build a log: founder a, add b, add c. Anchor at h2 (after c), target at h1 (after b).
        let founder = mpk(b"a");
        let mut log = RingDeltaLog::new(founder.clone()).expect("founder add cannot fail");
        let mut ring = Ring::new(vec![point_from(&founder).unwrap()]);

        let (h1, _) = log
            .append(&mut ring, RingDelta::Add(mpk(b"b")))
            .expect("append b");
        let (h2, _) = log
            .append(&mut ring, RingDelta::Add(mpk(b"c")))
            .expect("append c");

        let path = log
            .delta_path(Some(&h2), &h1)
            .expect("delta path should exist");

        // Reconstruct anchor ring, then apply returned deltas; final hash must equal target (h1).
        let mut anchor_ring = log
            .reconstruct(&h2, None)
            .expect("anchor reconstruct should succeed");
        for delta in path {
            apply_delta(&mut anchor_ring, &delta).expect("delta apply");
        }
        let resulting_hash = ring_hash_sha3_256(&anchor_ring);
        assert_eq!(resulting_hash, h1, "backward path must land on target");
    }

    #[test]
    fn add_remove_add_replay() {
        let founder = mpk(b"founder");
        let member = mpk(b"member");
        let mut log = RingDeltaLog::new(founder.clone()).unwrap();
        let mut ring = Ring::new(vec![point_from(&founder).unwrap()]);

        // 1. Add
        log.append(&mut ring, RingDelta::Add(member.clone()))
            .unwrap();
        let hash_with_member = ring_hash_sha3_256(&ring);

        // 2. Remove
        log.append(&mut ring, RingDelta::Remove(member.clone()))
            .unwrap();
        assert_ne!(ring_hash_sha3_256(&ring), hash_with_member);

        // 3. Add again
        log.append(&mut ring, RingDelta::Add(member.clone()))
            .unwrap();
        let final_hash = ring_hash_sha3_256(&ring);

        // Verify state consistency
        assert_eq!(final_hash, hash_with_member);

        // Reconstruct from scratch
        let reconstructed = log.reconstruct(&final_hash, None).unwrap();
        assert_eq!(ring_hash_sha3_256(&reconstructed), final_hash);
        assert_eq!(reconstructed.members().len(), 2);
    }

    #[test]
    fn error_paths() {
        let founder = mpk(b"founder");
        let log = RingDeltaLog::new(founder).unwrap();

        // TargetNotFound
        let fake_hash = RingHash([0xff; 32]);
        let err = log.reconstruct(&fake_hash, None);
        assert!(matches!(err, Err(RingLogError::TargetNotFound)));

        // AnchorNotFound: use valid target but anchor not in index
        let valid_target_hash = log.entries[0].0;
        let alien_ring = Ring::new(vec![]);
        let err = log.reconstruct(&valid_target_hash, Some(&alien_ring));
        assert!(matches!(err, Err(RingLogError::AnchorNotFound)));
    }

    #[test]
    fn empty_log_behavior() {
        // Default log has empty entries/index
        let log = RingDeltaLog::default();
        let random_hash = RingHash([1u8; 32]);

        // Should fail finding target
        let err = log.reconstruct(&random_hash, None);
        assert!(matches!(err, Err(RingLogError::TargetNotFound)));
    }

    #[test]
    fn shortest_path_via_duplicates() {
        let a = mpk(b"A");
        let b = mpk(b"B");

        // States: {A}(idx0) -> {A,B}(idx1) -> {A}(idx2) -> {A,B}(idx3)
        let mut log = RingDeltaLog::new(a.clone()).unwrap();
        let mut ring = Ring::new(vec![point_from(&a).unwrap()]);

        log.append(&mut ring, RingDelta::Add(b.clone())).unwrap();
        let hash_ab = ring_hash_sha3_256(&ring);

        log.append(&mut ring, RingDelta::Remove(b.clone())).unwrap();
        let _hash_a = ring_hash_sha3_256(&ring);

        log.append(&mut ring, RingDelta::Add(b.clone())).unwrap();

        // anchor = {A} hash_a, target = hash_ab (appears twice)
        let anchor_ring = Ring::new(vec![point_from(&a).unwrap()]);
        let reconstructed = log.reconstruct(&hash_ab, Some(&anchor_ring)).unwrap();

        assert_eq!(ring_hash_sha3_256(&reconstructed), hash_ab);
        assert_eq!(reconstructed.members().len(), 2);
        assert!(reconstructed.members().contains(&point_from(&a).unwrap()));
        assert!(reconstructed.members().contains(&point_from(&b).unwrap()));
    }

    #[test]
    fn member_order_independence() {
        let a = mpk(b"A");
        let b = mpk(b"B");

        // Log 1: {A} -> +B
        let mut log1 = RingDeltaLog::new(a.clone()).unwrap();
        let mut ring1 = Ring::new(vec![point_from(&a).unwrap()]);
        log1.append(&mut ring1, RingDelta::Add(b.clone())).unwrap();
        let hash1 = ring_hash_sha3_256(&ring1);

        // Log 2: {B} -> +A
        let mut log2 = RingDeltaLog::new(b.clone()).unwrap();
        let mut ring2 = Ring::new(vec![point_from(&b).unwrap()]);
        log2.append(&mut ring2, RingDelta::Add(a.clone())).unwrap();
        let hash2 = ring_hash_sha3_256(&ring2);

        assert_eq!(hash1, hash2, "member ordering must be canonical");
    }
}
