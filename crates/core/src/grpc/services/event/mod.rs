//! EventService gRPC implementation.

mod poll;
mod push_event;
mod push_event_helpers;
mod service;
mod stream;
mod validation;

pub use service::EventServiceImpl;

use mandate_proto::mandate::v1::event_service_server::EventService;
use tonic::{Request, Response, Status};

#[tonic::async_trait]
impl EventService for EventServiceImpl {
    async fn push_event(
        &self,
        request: Request<mandate_proto::mandate::v1::PushEventRequest>,
    ) -> Result<Response<mandate_proto::mandate::v1::PushEventResponse>, Status> {
        self.push_event(request).await
    }

    type StreamEventsStream = stream::StreamEventsStream;

    async fn stream_events(
        &self,
        request: Request<mandate_proto::mandate::v1::StreamEventsRequest>,
    ) -> Result<Response<Self::StreamEventsStream>, Status> {
        self.stream_events(request).await
    }

    async fn get_poll_results(
        &self,
        request: Request<mandate_proto::mandate::v1::GetPollResultsRequest>,
    ) -> Result<Response<mandate_proto::mandate::v1::GetPollResultsResponse>, Status> {
        self.get_poll_results(request).await
    }

    async fn get_poll_bundle(
        &self,
        request: Request<mandate_proto::mandate::v1::GetPollBundleRequest>,
    ) -> Result<Response<mandate_proto::mandate::v1::GetPollBundleResponse>, Status> {
        self.get_poll_bundle(request).await
    }
}
