//! Election lifecycle phase state machine.
//!
//! A poll progresses through four phases:
//!
//! ```text
//! Voting ──(deadline)──► Sealed ──(bundle published)──► VerificationOpen ──(window closes)──► Finalized
//! ```
//!
//! Transitions are driven by wall-clock time and the `PollBundlePublished` event.

use serde::{Deserialize, Serialize};

use super::Poll;

/// The phase of a poll's election lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ElectionPhase {
    /// Voting is open: `now < deadline` (or `deadline` is `None`).
    Voting,
    /// Voting has closed but the bundle has not been published yet:
    /// `deadline <= now < deadline + sealed_duration` (or bundle not yet published).
    Sealed,
    /// Bundle was published and the verification window is open.
    /// Vote revocations are accepted during this phase.
    VerificationOpen,
    /// Verification window has closed; the election result is final.
    Finalized,
}

impl Poll {
    /// Determine the current election phase based on wall-clock time and
    /// the optional `PollBundlePublished` timestamp.
    ///
    /// # Arguments
    ///
    /// * `now` - Current epoch time in seconds.
    /// * `bundle_published_at` - Epoch seconds when the `PollBundlePublished`
    ///   event was processed, or `None` if no bundle has been published yet.
    ///
    /// # Edge cases
    ///
    /// * `deadline = None` → always returns `Voting` (legacy poll with no lifecycle).
    /// * Bundle not published while in sealed period → stays `Sealed`.
    /// * `sealed_duration_secs = None` → treated as 0 (no sealed period).
    /// * `verification_window_secs = None` → treated as 0 (immediate finalization
    ///   after bundle publication).
    pub fn election_phase(&self, now: u64, bundle_published_at: Option<u64>) -> ElectionPhase {
        let deadline = match self.deadline {
            Some(d) => d,
            // Legacy polls without a deadline are always in the Voting phase.
            None => return ElectionPhase::Voting,
        };

        // Phase 1: Voting (now < deadline)
        if now < deadline {
            return ElectionPhase::Voting;
        }

        // Phase 2/3/4: deadline has passed.
        // `sealed_duration_secs` is stored for informational/display purposes
        // (e.g., telling members "results will be published within N seconds"),
        // but the actual Sealed → VerificationOpen transition is driven by
        // the `PollBundlePublished` event, not by a timer.
        match bundle_published_at {
            None => {
                // Bundle not published yet. If still within the sealed window
                // (or no sealed window defined), stay Sealed.
                ElectionPhase::Sealed
            }
            Some(published_at) => {
                let verification_window = self.verification_window_secs.unwrap_or(0);

                if verification_window == 0 {
                    // No verification window → immediate finalization after bundle.
                    return ElectionPhase::Finalized;
                }

                // Verification window starts when the bundle is published.
                let verification_end = published_at.saturating_add(verification_window);

                if now < verification_end {
                    ElectionPhase::VerificationOpen
                } else {
                    ElectionPhase::Finalized
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::{OrganizationId, RingHash};

    fn test_org_id() -> OrganizationId {
        crate::test_utils::test_org_id()
    }

    fn make_poll(
        deadline: Option<u64>,
        sealed_duration_secs: Option<u64>,
        verification_window_secs: Option<u64>,
    ) -> Poll {
        Poll {
            org_id: test_org_id(),
            ring_hash: RingHash([0u8; 32]),
            poll_id: "test-poll".into(),
            questions: vec![],
            created_at: 1000,
            instructions: None,
            deadline,
            sealed_duration_secs,
            verification_window_secs,
        }
    }

    #[test]
    fn no_deadline_always_voting() {
        let poll = make_poll(None, Some(60), Some(120));
        assert_eq!(poll.election_phase(0, None), ElectionPhase::Voting);
        assert_eq!(poll.election_phase(u64::MAX, None), ElectionPhase::Voting);
        assert_eq!(
            poll.election_phase(u64::MAX, Some(100)),
            ElectionPhase::Voting
        );
    }

    #[test]
    fn before_deadline_is_voting() {
        let poll = make_poll(Some(2000), Some(60), Some(120));
        assert_eq!(poll.election_phase(1999, None), ElectionPhase::Voting);
        assert_eq!(poll.election_phase(1000, None), ElectionPhase::Voting);
    }

    #[test]
    fn at_deadline_transitions_to_sealed() {
        let poll = make_poll(Some(2000), Some(60), Some(120));
        assert_eq!(poll.election_phase(2000, None), ElectionPhase::Sealed);
    }

    #[test]
    fn after_deadline_no_bundle_stays_sealed() {
        let poll = make_poll(Some(2000), Some(60), Some(120));
        assert_eq!(poll.election_phase(2050, None), ElectionPhase::Sealed);
        // Even well past the sealed duration, stays Sealed if no bundle published.
        assert_eq!(poll.election_phase(3000, None), ElectionPhase::Sealed);
    }

    #[test]
    fn bundle_published_opens_verification() {
        let poll = make_poll(Some(2000), Some(60), Some(120));
        // Bundle published at 2060, verification window 120s → ends at 2180.
        assert_eq!(
            poll.election_phase(2070, Some(2060)),
            ElectionPhase::VerificationOpen
        );
        assert_eq!(
            poll.election_phase(2179, Some(2060)),
            ElectionPhase::VerificationOpen
        );
    }

    #[test]
    fn verification_window_closes_to_finalized() {
        let poll = make_poll(Some(2000), Some(60), Some(120));
        // Bundle at 2060, verification window 120s → ends at 2180.
        assert_eq!(
            poll.election_phase(2180, Some(2060)),
            ElectionPhase::Finalized
        );
        assert_eq!(
            poll.election_phase(3000, Some(2060)),
            ElectionPhase::Finalized
        );
    }

    #[test]
    fn no_verification_window_immediate_finalization() {
        let poll = make_poll(Some(2000), Some(60), None);
        assert_eq!(
            poll.election_phase(2070, Some(2060)),
            ElectionPhase::Finalized
        );
    }

    #[test]
    fn zero_verification_window_immediate_finalization() {
        let poll = make_poll(Some(2000), Some(60), Some(0));
        assert_eq!(
            poll.election_phase(2070, Some(2060)),
            ElectionPhase::Finalized
        );
    }

    #[test]
    fn no_sealed_duration_bundle_opens_verification() {
        let poll = make_poll(Some(2000), None, Some(120));
        // No sealed duration, bundle published at deadline.
        assert_eq!(
            poll.election_phase(2050, Some(2000)),
            ElectionPhase::VerificationOpen
        );
    }

    #[test]
    fn full_lifecycle_progression() {
        let poll = make_poll(Some(1000), Some(60), Some(120));

        // Voting
        assert_eq!(poll.election_phase(999, None), ElectionPhase::Voting);
        // Sealed (deadline passed, no bundle)
        assert_eq!(poll.election_phase(1000, None), ElectionPhase::Sealed);
        // Still Sealed (within sealed window, no bundle)
        assert_eq!(poll.election_phase(1050, None), ElectionPhase::Sealed);
        // VerificationOpen (bundle published at 1060)
        assert_eq!(
            poll.election_phase(1070, Some(1060)),
            ElectionPhase::VerificationOpen
        );
        // Finalized (verification window closed: 1060 + 120 = 1180)
        assert_eq!(
            poll.election_phase(1180, Some(1060)),
            ElectionPhase::Finalized
        );
    }

    #[test]
    fn saturating_add_prevents_overflow() {
        let poll = make_poll(Some(1000), None, Some(u64::MAX));
        // published_at + verification_window would overflow; saturating_add clamps to u64::MAX.
        // Since now < u64::MAX, we stay in VerificationOpen.
        assert_eq!(
            poll.election_phase(1100, Some(1000)),
            ElectionPhase::VerificationOpen
        );
    }
}
