use anyhow::{Context, Result};
use futures_util::StreamExt;
use mandate_core::proto::API_TOKEN_METADATA_KEY;
use mandate_proto::mandate::v1::{
    event_service_client::EventServiceClient, ring_service_client::RingServiceClient,
    StreamEventsRequest, StreamEventsResponse, StreamRingRequest, StreamRingResponse,
};
use tonic::metadata::MetadataValue;
use tonic::transport::Channel;
use tonic::Request;

#[derive(Debug, Clone)]
pub struct EventRecord {
    pub sequence_no: i64,
    pub event_bytes: Vec<u8>,
}

pub struct AuditClient {
    edge_url: String,
    api_token: String,
    edge_channel: Option<Channel>,
}

impl AuditClient {
    pub fn new(edge_url: String, api_token: String) -> Self {
        Self {
            edge_url,
            api_token,
            edge_channel: None,
        }
    }

    async fn edge_channel(&mut self) -> Result<Channel> {
        if let Some(channel) = &self.edge_channel {
            return Ok(channel.clone());
        }
        let channel = Channel::from_shared(self.edge_url.clone())
            .context("invalid edge URL")?
            .connect()
            .await
            .context("failed to connect to edge")?;
        self.edge_channel = Some(channel.clone());
        Ok(channel)
    }

    fn with_token<T>(&self, mut req: Request<T>) -> Result<Request<T>> {
        let token = MetadataValue::try_from(self.api_token.as_str())
            .context("invalid api token metadata value")?;
        req.metadata_mut().insert(API_TOKEN_METADATA_KEY, token);
        Ok(req)
    }

    pub async fn stream_events(
        &mut self,
        group_id: &str,
        start_seq: i64,
        limit: u32,
    ) -> Result<Vec<EventRecord>> {
        let channel = self.edge_channel().await?;
        let mut client = EventServiceClient::new(channel);
        let req = self.with_token(Request::new(StreamEventsRequest {
            group_id: group_id.to_string(),
            start_sequence_no: start_seq,
            limit,
        }))?;
        let mut stream = client
            .stream_events(req)
            .await
            .context("stream_events failed")?
            .into_inner();

        let mut records = Vec::new();
        while let Some(response) = stream.next().await {
            let response: StreamEventsResponse = response.context("stream_events response")?;
            for (idx, bytes) in response.event_bytes.into_iter().enumerate() {
                let seq = response.sequence_nos.get(idx).copied().unwrap_or_default();
                records.push(EventRecord {
                    sequence_no: seq,
                    event_bytes: bytes,
                });
            }
        }
        Ok(records)
    }

    pub async fn stream_ring(
        &mut self,
        group_id: &str,
        after_ring_hash: Vec<u8>,
        limit: u32,
    ) -> Result<StreamRingResponse> {
        let channel = self.edge_channel().await?;
        let mut client = RingServiceClient::new(channel);
        let req = self.with_token(Request::new(StreamRingRequest {
            group_id: group_id.to_string(),
            after_ring_hash,
            limit,
        }))?;
        let mut stream = client
            .stream_ring(req)
            .await
            .context("stream_ring failed")?
            .into_inner();

        let mut last: Option<StreamRingResponse> = None;
        while let Some(response) = stream.next().await {
            last = Some(response.context("stream_ring response")?);
        }
        Ok(last.unwrap_or(StreamRingResponse {
            entries: Vec::new(),
            next_ring_hash: Vec::new(),
        }))
    }
}
