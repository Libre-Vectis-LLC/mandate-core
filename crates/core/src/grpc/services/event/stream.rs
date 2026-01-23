//! stream_events gRPC handler implementation.

use super::service::EventServiceImpl;
use crate::ids::{GroupId, SequenceNo};
use mandate_proto::mandate::v1::{StreamEventsRequest, StreamEventsResponse};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

use super::super::{clamp_events_limit, extract_tenant_id, to_status};

/// Type alias for the streaming response.
pub(super) type StreamEventsStream = ReceiverStream<Result<StreamEventsResponse, Status>>;

impl EventServiceImpl {
    pub(super) async fn stream_events(
        &self,
        request: Request<StreamEventsRequest>,
    ) -> Result<Response<StreamEventsStream>, Status> {
        let tenant = extract_tenant_id(&request, &self.store).await?;
        let body = request.into_inner();
        let group_id = GroupId(crate::proto::parse_ulid(&body.group_id).map_err(|e| {
            crate::rpc::RpcError::InvalidArgument {
                field: "group_id",
                reason: e.to_string(),
            }
        })?);
        let cursor = if body.start_sequence_no < 0 {
            None
        } else {
            Some(SequenceNo::new(body.start_sequence_no))
        };
        let limit = clamp_events_limit(body.limit);
        let records = self
            .store
            .stream_events(tenant, group_id, cursor, limit)
            .await
            .map_err(to_status)?;

        // Calculate total egress bytes for billing
        let total_bytes: usize = records.iter().map(|(_, b, _)| b.len()).sum();
        let group_id_str = group_id.to_string();

        // Check egress balance before sending data
        self.egress_meter
            .check_egress(&group_id_str, total_bytes)
            .await
            .map_err(|e| Status::resource_exhausted(format!("egress check failed: {}", e)))?;

        let (tx, rx) = mpsc::channel(1);
        let sequence_nos: Vec<i64> = records.iter().map(|(_, _, seq)| seq.as_i64()).collect();
        let event_bytes: Vec<Vec<u8>> = records.into_iter().map(|(_, b, _)| b.to_vec()).collect();

        // Record egress after preparing response (charge for data transfer)
        // Note: We intentionally ignore errors here - the data is already prepared
        // and the check_egress call above already validated the balance.
        let _ = self
            .egress_meter
            .record_egress(&group_id_str, total_bytes)
            .await;

        let _ = tx
            .send(Ok(StreamEventsResponse {
                event_bytes,
                sequence_nos,
            }))
            .await;
        Ok(Response::new(ReceiverStream::new(rx)))
    }
}
