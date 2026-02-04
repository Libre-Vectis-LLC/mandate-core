use super::StorageFacade;
use crate::ids::{OrganizationId, SequenceNo, TenantId};
use crate::storage::{EventBytes, EventRecord, StorageError};

impl StorageFacade {
    // ─────────────────────────────────────────────────────────────────────────
    // Event methods
    // ─────────────────────────────────────────────────────────────────────────

    /// Get the tail (most recent) event for a group.
    pub async fn event_tail(
        &self,
        tenant: TenantId,
        org_id: OrganizationId,
    ) -> Result<EventRecord, StorageError> {
        self.event_reader.tail(tenant, org_id).await
    }

    /// Stream events for a group, starting after the given sequence number.
    pub async fn stream_events(
        &self,
        tenant: TenantId,
        org_id: OrganizationId,
        after_sequence: Option<SequenceNo>,
        limit: usize,
    ) -> Result<Vec<EventRecord>, StorageError> {
        self.event_reader
            .stream_group(tenant, org_id, after_sequence, limit)
            .await
    }

    /// Append an event to the event log.
    pub async fn append_event(
        &self,
        tenant: TenantId,
        org_id: OrganizationId,
        event_bytes: EventBytes,
    ) -> Result<(crate::ids::EventId, SequenceNo), StorageError> {
        self.event_writer.append(tenant, org_id, event_bytes).await
    }
}
