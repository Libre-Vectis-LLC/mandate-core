//! EventService implementation struct and constructors.

use crate::billing::{default_egress_meter, SharedEgressMeter};
use crate::storage::facade::StorageFacade;
use std::sync::Arc;

/// Basic EventService stub wired to EventStore.
#[derive(Clone)]
pub struct EventServiceImpl {
    pub(super) store: StorageFacade,
    pub(super) verifier: Arc<dyn crate::crypto::verifier::SignatureVerifier>,
    pub(super) egress_meter: SharedEgressMeter,
}

impl EventServiceImpl {
    /// Create a new EventService with the default no-op egress meter.
    pub fn new(
        store: StorageFacade,
        verifier: Arc<dyn crate::crypto::verifier::SignatureVerifier>,
    ) -> Self {
        Self {
            store,
            verifier,
            egress_meter: default_egress_meter(),
        }
    }

    /// Create a new EventService with a custom egress meter.
    pub fn with_egress_meter(
        store: StorageFacade,
        verifier: Arc<dyn crate::crypto::verifier::SignatureVerifier>,
        egress_meter: SharedEgressMeter,
    ) -> Self {
        Self {
            store,
            verifier,
            egress_meter,
        }
    }
}
