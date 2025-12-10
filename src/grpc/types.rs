use crate::storage::EventRecord;
use std::sync::Arc;

#[derive(Clone, Default)]
pub struct InMemoryEvents {
    pub events: Vec<EventRecord>,
}

impl InMemoryEvents {
    pub fn push(&mut self, record: EventRecord) {
        self.events.push(record);
    }

    pub fn slice_after(&self, after: Option<usize>, limit: usize) -> Vec<EventRecord> {
        let start = after.map(|i| i + 1).unwrap_or(0);
        self.events
            .iter()
            .skip(start)
            .take(limit)
            .cloned()
            .collect()
    }
}

pub type Bytes = Arc<[u8]>;
pub type SequenceNo = i64;
