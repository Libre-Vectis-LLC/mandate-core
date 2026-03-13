/// In-memory ring delta log and reconstruction.
use crate::ids::{OrganizationId, RingHash, TenantId};
use crate::ring_log::{RingDelta, RingDeltaLog, RingLogError};
use crate::storage::{NotFound, RingView, RingWriter, StorageError};
use async_trait::async_trait;
use nazgul::ring::Ring;
use nazgul::traits::LocalByteConvertible;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Default, Clone)]
pub struct InMemoryRings {
    rings: Arc<Mutex<HashMap<(TenantId, OrganizationId), RingState>>>,
}

#[derive(Clone)]
struct RingState {
    log: RingDeltaLog,
    current: Ring,
    current_hash: RingHash,
}

impl InMemoryRings {
    pub fn new() -> Self {
        Self {
            rings: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn inner(&self) -> parking_lot::MutexGuard<'_, HashMap<(TenantId, OrganizationId), RingState>> {
        self.rings.lock()
    }
}

#[async_trait]
impl RingView for InMemoryRings {
    async fn ring_by_hash(
        &self,
        tenant: TenantId,
        org_id: OrganizationId,
        hash: &RingHash,
    ) -> Result<Arc<Ring>, StorageError> {
        let mut map = self.inner();
        let key = (tenant, org_id);
        let state = map
            .get_mut(&key)
            .ok_or(StorageError::NotFound(NotFound::Ring {
                hash: *hash,
                tenant,
                org_id,
            }))?;

        if &state.current_hash == hash {
            return Ok(Arc::new(state.current.clone()));
        }

        let reconstructed = state
            .log
            .reconstruct(hash, Some(&state.current))
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        Ok(Arc::new(reconstructed))
    }

    async fn current_ring(
        &self,
        tenant: TenantId,
        org_id: OrganizationId,
    ) -> Result<Arc<Ring>, StorageError> {
        let map = self.inner();
        let key = (tenant, org_id);
        let state = map.get(&key).ok_or(StorageError::NotFound(NotFound::Ring {
            hash: RingHash([0; 32]),
            tenant,
            org_id,
        }))?;
        Ok(Arc::new(state.current.clone()))
    }

    async fn ring_delta_path(
        &self,
        tenant: TenantId,
        org_id: OrganizationId,
        ring_hash_current: Option<RingHash>,
        ring_hash_target: RingHash,
    ) -> Result<crate::storage::RingDeltaPath, StorageError> {
        let map = self.inner();
        let key = (tenant, org_id);
        let state = map.get(&key).ok_or(StorageError::NotFound(NotFound::Ring {
            hash: ring_hash_current.unwrap_or(ring_hash_target),
            tenant,
            org_id,
        }))?;

        let (from, deltas) = if let Some(anchor) = ring_hash_current {
            let deltas = state
                .log
                .delta_path(Some(&anchor), &ring_hash_target)
                .map_err(|e| match e {
                    RingLogError::TargetNotFound => StorageError::NotFound(NotFound::Ring {
                        hash: ring_hash_target,
                        tenant,
                        org_id,
                    }),
                    RingLogError::AnchorNotFound => StorageError::NotFound(NotFound::Ring {
                        hash: anchor,
                        tenant,
                        org_id,
                    }),
                    other => StorageError::Backend(other.to_string()),
                })?;
            (anchor, deltas)
        } else {
            let anchor = state
                .log
                .genesis_hash()
                .cloned()
                .unwrap_or(state.current_hash);
            let deltas = state
                .log
                .delta_path(None, &ring_hash_target)
                .map_err(|e| match e {
                    RingLogError::TargetNotFound => StorageError::NotFound(NotFound::Ring {
                        hash: ring_hash_target,
                        tenant,
                        org_id,
                    }),
                    RingLogError::AnchorNotFound => StorageError::NotFound(NotFound::Ring {
                        hash: anchor,
                        tenant,
                        org_id,
                    }),
                    other => StorageError::Backend(other.to_string()),
                })?;
            (anchor, deltas)
        };

        Ok(crate::storage::RingDeltaPath {
            from,
            to: ring_hash_target,
            deltas,
        })
    }
}

#[async_trait]
impl RingWriter for InMemoryRings {
    async fn append_delta(
        &self,
        tenant: TenantId,
        org_id: OrganizationId,
        delta: RingDelta,
    ) -> Result<RingHash, StorageError> {
        let mut map = self.inner();
        let key = (tenant, org_id);

        // Check if this is the first delta for this org.
        let is_new_org = !map.contains_key(&key);

        if is_new_org {
            // For the first delta (must be Add), use RingDeltaLog::new to properly initialize.
            let founder = match &delta {
                RingDelta::Add(pubkey) => *pubkey,
                RingDelta::Remove(_) => {
                    return Err(StorageError::Backend(
                        "first ring delta must be Add, not Remove".to_string(),
                    ));
                }
            };

            let log =
                RingDeltaLog::new(founder).map_err(|e| StorageError::Backend(e.to_string()))?;

            // Convert MasterPublicKey to RistrettoPoint for Ring construction
            let founder_point = nazgul::scalar::RistrettoPoint::from_bytes(&founder.0)
                .map_err(|_| StorageError::Backend("invalid founder public key".to_string()))?;
            let current = Ring::new(vec![founder_point]);
            let current_hash = crate::hashing::ring_hash(&current);

            map.insert(
                key,
                RingState {
                    log,
                    current,
                    current_hash,
                },
            );

            Ok(current_hash)
        } else {
            // Subsequent deltas: append to existing log.
            let state = map.get_mut(&key).expect("just checked existence");
            let (hash, _) = state
                .log
                .append(&mut state.current, delta.clone())
                .map_err(|e| StorageError::Backend(e.to_string()))?;
            state.current_hash = hash;
            Ok(hash)
        }
    }
}
