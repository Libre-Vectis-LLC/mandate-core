use std::sync::Arc;

use crate::storage::{EventReader, EventWriter, RingView, RingWriter};

/// Thin convenience wrapper to inject storage capabilities as a single handle.
#[derive(Clone)]
pub struct StorageFacade {
    pub event_reader: Arc<dyn EventReader + Send + Sync>,
    pub event_writer: Arc<dyn EventWriter + Send + Sync>,
    pub ring_view: Arc<dyn RingView + Send + Sync>,
    pub ring_writer: Arc<dyn RingWriter + Send + Sync>,
}

impl StorageFacade {
    pub fn new(
        event_reader: Arc<dyn EventReader + Send + Sync>,
        event_writer: Arc<dyn EventWriter + Send + Sync>,
        ring_view: Arc<dyn RingView + Send + Sync>,
        ring_writer: Arc<dyn RingWriter + Send + Sync>,
    ) -> Self {
        Self {
            event_reader,
            event_writer,
            ring_view,
            ring_writer,
        }
    }
}
