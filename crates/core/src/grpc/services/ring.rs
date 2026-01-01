//! RingService gRPC implementation.

use crate::ids::{GroupId, RingHash};
use crate::proto::ring_delta_to_bytes;
use crate::ring_log::apply_delta;
use crate::rpc::RpcError;
use crate::storage::facade::StorageFacade;
use mandate_proto::mandate::v1::{
    ring_service_server::RingService, GetRingHeadRequest, GetRingHeadResponse, StreamRingRequest,
    StreamRingResponse,
};
use nazgul::ring::Ring;
use nazgul::traits::LocalByteConvertible;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

use super::{clamp_ring_limit, extract_tenant_id, to_status};

/// Ring service backed by a `RingView`.
#[derive(Clone)]
pub struct RingServiceImpl {
    store: StorageFacade,
}

impl RingServiceImpl {
    pub fn new(store: StorageFacade) -> Self {
        Self { store }
    }
}

#[tonic::async_trait]
impl RingService for RingServiceImpl {
    async fn get_ring_head(
        &self,
        request: Request<GetRingHeadRequest>,
    ) -> Result<Response<GetRingHeadResponse>, Status> {
        let tenant = extract_tenant_id(&request, &self.store).await?;
        let group = request.into_inner().group_id;
        let group_id =
            GroupId(
                crate::proto::parse_ulid(&group).map_err(|e| RpcError::InvalidArgument {
                    field: "group_id",
                    reason: e.to_string(),
                })?,
            );

        // Current ring for the requested group.
        let ring = self
            .store
            .current_ring(tenant, group_id)
            .await
            .map_err(to_status)?;
        let ring_hash = crate::hashing::ring_hash_sha3_256(&ring);
        let members: Vec<Vec<u8>> = ring
            .members()
            .iter()
            .map(|p| p.to_bytes().to_vec())
            .collect();
        Ok(Response::new(GetRingHeadResponse {
            ring_hash: ring_hash.0.to_vec(),
            member_count: members.len() as u32,
            members,
        }))
    }

    type StreamRingStream = ReceiverStream<Result<StreamRingResponse, Status>>;

    async fn stream_ring(
        &self,
        request: Request<StreamRingRequest>,
    ) -> Result<Response<Self::StreamRingStream>, Status> {
        let tenant = extract_tenant_id(&request, &self.store).await?;
        let req = request.into_inner();
        let group_id = GroupId(crate::proto::parse_ulid(&req.group_id).map_err(|e| {
            RpcError::InvalidArgument {
                field: "group_id",
                reason: e.to_string(),
            }
        })?);
        let after_hash = if req.after_ring_hash.is_empty() {
            None
        } else {
            Some(RingHash(
                crate::proto::hash32_to_ring_hash(&mandate_proto::mandate::v1::Hash32 {
                    value: req.after_ring_hash.clone(),
                })
                .map_err(|e| RpcError::InvalidArgument {
                    field: "after_ring_hash",
                    reason: e.to_string(),
                })?
                .0,
            ))
        };

        // For now, stream a single batch from optional anchor to current ring head.
        let current_ring = self
            .store
            .current_ring(tenant, group_id)
            .await
            .map_err(to_status)?;
        let current_hash = crate::hashing::ring_hash_sha3_256(&current_ring);

        if after_hash.as_ref() == Some(&current_hash) {
            let (tx, rx) = mpsc::channel(1);
            let _ = tx
                .send(Ok(StreamRingResponse {
                    entries: Vec::new(),
                    next_ring_hash: current_hash.0.to_vec(),
                }))
                .await;
            return Ok(Response::new(ReceiverStream::new(rx)));
        }

        let path = self
            .store
            .ring_delta_path(tenant, group_id, after_hash, current_hash)
            .await
            .map_err(to_status)?;

        let anchor_override = if after_hash.is_none() {
            Some(Ring::new(Vec::new()))
        } else {
            None
        };

        let entries = encode_ring_delta_path(
            &self.store,
            tenant,
            group_id,
            &path,
            anchor_override,
            clamp_ring_limit(req.limit),
        )
        .await?;
        let next_hash = entries
            .last()
            .map(|e| e.ring_hash.clone())
            .unwrap_or_default();
        let (tx, rx) = mpsc::channel(1);
        let _ = tx
            .send(Ok(StreamRingResponse {
                entries,
                next_ring_hash: next_hash,
            }))
            .await;
        Ok(Response::new(ReceiverStream::new(rx)))
    }
}

#[allow(clippy::result_large_err)]
async fn encode_ring_delta_path(
    store: &StorageFacade,
    tenant: crate::ids::TenantId,
    group_id: GroupId,
    path: &crate::storage::RingDeltaPath,
    anchor_override: Option<Ring>,
    limit: usize,
) -> Result<Vec<mandate_proto::mandate::v1::RingDeltaEntry>, Status> {
    let mut ring = match anchor_override {
        Some(anchor) => anchor,
        None => {
            let anchor = store
                .ring_by_hash(tenant, group_id, &path.from)
                .await
                .map_err(to_status)?;
            (*anchor).clone()
        }
    };

    let deltas_bytes = path
        .deltas
        .iter()
        .take(limit)
        .map(|d| {
            apply_delta(&mut ring, d).map_err(|e| RpcError::Internal {
                operation: "ring_delta_application",
                details: e.to_string(),
            })?;
            Ok(ring_delta_to_bytes(d))
        })
        .collect::<Result<Vec<_>, Status>>()?;

    let ring_hash = crate::hashing::ring_hash_sha3_256(&ring);

    Ok(vec![mandate_proto::mandate::v1::RingDeltaEntry {
        ring_hash: ring_hash.0.to_vec(),
        deltas: deltas_bytes,
    }])
}
