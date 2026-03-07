//! Validation helpers for event processing.

use crate::storage::BannedOperation;

/// Map event type to corresponding banned operation.
pub(super) fn banned_operation_for_event(
    event_type: &crate::event::EventType,
) -> Option<BannedOperation> {
    match event_type {
        crate::event::EventType::MessageCreate(_) => Some(BannedOperation::PostMessage),
        crate::event::EventType::PollCreate(_) => Some(BannedOperation::CreatePoll),
        crate::event::EventType::VoteCast(_) => Some(BannedOperation::CastVote),
        crate::event::EventType::VoteRevocation(_) => Some(BannedOperation::CastVote),
        _ => None,
    }
}
