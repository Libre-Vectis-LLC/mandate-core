use crate::proto::API_TOKEN_METADATA_KEY;
use crate::rpc::RpcError;
use crate::storage::EventStore;
use mandate_proto::mandate::v1::{
    event_service_server::EventService, PushEventRequest, PushEventResponse, StreamEventsRequest,
    StreamEventsResponse,
};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

/// Basic EventService stub wired to EventStore.
pub struct EventServiceImpl<S: EventStore> {
    store: S,
}

impl<S: EventStore> EventServiceImpl<S> {
    pub fn new(store: S) -> Self {
        Self { store }
    }
}

#[tonic::async_trait]
impl<S: EventStore + Send + Sync + 'static> EventService for EventServiceImpl<S> {
    async fn push_event(
        &self,
        request: Request<PushEventRequest>,
    ) -> Result<Response<PushEventResponse>, Status> {
        // In a full implementation we'd parse event_bytes, verify signature, etc.
        let tenant = extract_tenant(&request)?;
        let body = request.into_inner();
        let event_bytes: crate::storage::EventBytes = body.event_bytes.into();
        let id = self
            .store
            .append(tenant, event_bytes.clone())
            .map_err(to_status)?;
        let event_id = format_event_id(&id)?;
        Ok(Response::new(PushEventResponse {
            event_id,
            sequence_no: 0, // placeholder; real store returns sequence
        }))
    }

    type StreamEventsStream = ReceiverStream<Result<StreamEventsResponse, Status>>;

    async fn stream_events(
        &self,
        _request: Request<StreamEventsRequest>,
    ) -> Result<Response<Self::StreamEventsStream>, Status> {
        // Placeholder streaming: empty stream for now.
        let (tx, rx) = mpsc::channel(1);
        drop(tx);
        Ok(Response::new(ReceiverStream::new(rx)))
    }
}

fn to_status(err: crate::storage::StorageError) -> Status {
    match err {
        crate::storage::StorageError::NotFound(_) => RpcError::NotFound(err.to_string()).into(),
        crate::storage::StorageError::Backend(msg) => RpcError::Internal(msg).into(),
    }
}

#[allow(clippy::result_large_err)]
fn format_event_id(id: &crate::ids::EventId) -> Result<String, Status> {
    // EventId is 32-byte content hash; not ULID. For demo, hex it.
    Ok(hex::encode(id.0))
}

#[allow(clippy::result_large_err)]
fn extract_tenant<T>(req: &Request<T>) -> Result<crate::ids::TenantId, Status> {
    let token = req
        .metadata()
        .get(API_TOKEN_METADATA_KEY)
        .ok_or_else(|| RpcError::Unauthenticated("missing api token".into()))?
        .to_str()
        .map_err(|_| RpcError::Unauthenticated("bad token".into()))?;
    // Placeholder: treat token as ULID string for tenant
    let ulid = ulid::Ulid::from_string(token)
        .map_err(|_| RpcError::Unauthenticated("invalid token ulid".into()))?;
    Ok(crate::ids::TenantId(ulid))
}
