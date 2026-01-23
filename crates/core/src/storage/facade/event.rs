use super::StorageFacade;
use crate::ids::{GroupId, SequenceNo, TenantId};
use crate::storage::{EventBytes, EventRecord, StorageError};

impl StorageFacade {
    // ─────────────────────────────────────────────────────────────────────────
    // Event methods
    // ─────────────────────────────────────────────────────────────────────────

    /// Get the tail (most recent) event for a group.
    pub async fn event_tail(
        &self,
        tenant: TenantId,
        group_id: GroupId,
    ) -> Result<EventRecord, StorageError> {
        self.event_reader.tail(tenant, group_id).await
    }

    /// Stream events for a group, starting after the given sequence number.
    pub async fn stream_events(
        &self,
        tenant: TenantId,
        group_id: GroupId,
        after_sequence: Option<SequenceNo>,
        limit: usize,
    ) -> Result<Vec<EventRecord>, StorageError> {
        self.event_reader
            .stream_group(tenant, group_id, after_sequence, limit)
            .await
    }

    /// Append an event to the event log.
    pub async fn append_event(
        &self,
        tenant: TenantId,
        group_id: GroupId,
        event_bytes: EventBytes,
    ) -> Result<(crate::ids::EventId, SequenceNo), StorageError> {
        self.event_writer
            .append(tenant, group_id, event_bytes)
            .await
    }
}
