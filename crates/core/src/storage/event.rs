//! Event log interfaces (append-only).

use crate::ids::{EventId, OrganizationId, SequenceNo, TenantId};
use async_trait::async_trait;

use super::types::{EventBytes, EventRecord, StorageError};

/// Append-only event storage. Intended for a single-writer per tenant; multi-tenant shares one table.
pub trait EventStore: EventReader + EventWriter {}

/// Write-only surface for events; separated to allow distinct read/write backends.
#[async_trait]
pub trait EventWriter {
    /// Append a canonical, signed event to the append-only log.
    ///
    /// This method is the primary write interface for the audit log. Events are
    /// written in serialized form and never modified after insertion. The returned
    /// sequence number establishes a total order for replay and streaming.
    ///
    /// # Arguments
    /// * `tenant` - The tenant identifier owning this event
    /// * `org_id` - The org IDentifier scoping this event
    /// * `event_bytes` - Canonical, signed, serialized event bytes
    ///
    /// # Returns
    /// A tuple of `(EventId, SequenceNo)` uniquely identifying this event and its
    /// position in the total order.
    ///
    /// # Errors
    /// * `StorageError::Backend` - When the underlying storage layer fails
    /// * `StorageError::PreconditionFailed` - When tenant or org does not exist
    ///
    /// # Invariants
    /// * Events are immutable once appended
    /// * Sequence numbers are strictly increasing per `(tenant, org_id)` pair
    /// * Single-writer assumption: concurrent appends for the same org are undefined
    async fn append(
        &self,
        tenant: TenantId,
        org_id: OrganizationId,
        event_bytes: EventBytes,
    ) -> Result<(EventId, SequenceNo), StorageError>;
}

/// Read-only org helper to support backend-specific implementations (e.g., Postgres).
#[async_trait]
pub trait EventReader {
    /// Stream events for an org in deterministic append order.
    ///
    /// This method supports keyset pagination using sequence numbers. Results are
    /// always ordered by increasing `SequenceNo`, enabling efficient forward iteration
    /// without offset-based pagination.
    ///
    /// # Arguments
    /// * `tenant` - The tenant identifier
    /// * `org_id` - The org IDentifier
    /// * `after_sequence` - Optional anchor; if `None`, starts from the first event
    /// * `limit` - Maximum number of events to return
    ///
    /// # Returns
    /// A vector of `EventRecord` tuples in ascending sequence order, potentially empty.
    ///
    /// # Errors
    /// * `StorageError::NotFound` - When tenant or org does not exist
    /// * `StorageError::Backend` - When the underlying storage layer fails
    ///
    /// # Invariants
    /// * Results are always ordered by increasing `SequenceNo`
    /// * No duplicates across successive calls with keyset pagination
    async fn stream_org(
        &self,
        tenant: TenantId,
        org_id: OrganizationId,
        after_sequence: Option<SequenceNo>,
        limit: usize,
    ) -> Result<Vec<EventRecord>, StorageError>;

    /// Retrieve a single event by its identifier.
    ///
    /// # Arguments
    /// * `tenant` - The tenant identifier
    /// * `org_id` - The org IDentifier
    /// * `id` - The event identifier
    ///
    /// # Returns
    /// The full `EventRecord` including canonical bytes and sequence number.
    ///
    /// # Errors
    /// * `StorageError::NotFound(NotFound::Event)` - When the event does not exist
    /// * `StorageError::Backend` - When the underlying storage layer fails
    async fn get(
        &self,
        tenant: TenantId,
        org_id: OrganizationId,
        id: &EventId,
    ) -> Result<EventRecord, StorageError>;

    /// Retrieve the most recent event for an org.
    ///
    /// This is a shortcut for retrieving the event with the highest sequence number
    /// for the given `(tenant, org_id)` pair.
    ///
    /// # Arguments
    /// * `tenant` - The tenant identifier
    /// * `org_id` - The org IDentifier
    ///
    /// # Returns
    /// The most recent `EventRecord` in append order.
    ///
    /// # Errors
    /// * `StorageError::NotFound(NotFound::Tail)` - When the org has no events yet
    /// * `StorageError::Backend` - When the underlying storage layer fails
    async fn tail(
        &self,
        tenant: TenantId,
        org_id: OrganizationId,
    ) -> Result<EventRecord, StorageError>;
}
