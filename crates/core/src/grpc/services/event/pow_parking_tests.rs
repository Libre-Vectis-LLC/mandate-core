//! Unit tests for PoW lazy verification parking mechanism.
//!
//! Tests the `OrgParkingState` and `SigVerificationGuard` types that coordinate
//! lazy PoW verification: when a signature verification is in-flight for an org,
//! subsequent PoW requests park until the verification completes, then re-evaluate
//! whether PoW is still required.

use super::service::{OrgParkingState, SigVerificationGuard};
use std::sync::atomic::Ordering;
use std::sync::Arc;

/// Verify initial parking state: no in-flight verifications, no parked requests.
#[test]
fn test_parking_state_initial() {
    let state = OrgParkingState::new();
    assert_eq!(state.sig_in_flight.load(Ordering::SeqCst), 0);
    assert_eq!(state.parked.load(Ordering::SeqCst), 0);
}

/// Test that `SigVerificationGuard` increments in-flight on creation
/// and decrements + notifies on drop.
#[test]
fn test_sig_verification_guard_lifecycle() {
    let state = Arc::new(OrgParkingState::new());

    // Create guard: in-flight should be 1
    let guard = SigVerificationGuard::new(Arc::clone(&state));
    assert_eq!(state.sig_in_flight.load(Ordering::SeqCst), 1);

    // Drop guard: in-flight should return to 0
    drop(guard);
    assert_eq!(state.sig_in_flight.load(Ordering::SeqCst), 0);
}

/// Test that multiple guards stack correctly and dropping one decrements properly.
#[test]
fn test_sig_verification_guard_stacking() {
    let state = Arc::new(OrgParkingState::new());

    let guard1 = SigVerificationGuard::new(Arc::clone(&state));
    let guard2 = SigVerificationGuard::new(Arc::clone(&state));
    assert_eq!(state.sig_in_flight.load(Ordering::SeqCst), 2);

    drop(guard1);
    assert_eq!(state.sig_in_flight.load(Ordering::SeqCst), 1);

    drop(guard2);
    assert_eq!(state.sig_in_flight.load(Ordering::SeqCst), 0);
}

/// Test bounded parking: simulate parking and unparking requests
/// to verify counter tracking.
#[test]
fn test_parking_counter_tracking() {
    let state = OrgParkingState::new();

    // Simulate sig in-flight
    state.sig_in_flight.store(1, Ordering::SeqCst);
    assert_eq!(state.sig_in_flight.load(Ordering::SeqCst), 1);

    // Simulate 3 requests parking
    state.parked.fetch_add(1, Ordering::SeqCst);
    state.parked.fetch_add(1, Ordering::SeqCst);
    state.parked.fetch_add(1, Ordering::SeqCst);
    assert_eq!(state.parked.load(Ordering::SeqCst), 3);

    // Simulate sig completion: clear in-flight and notify
    state.sig_in_flight.store(0, Ordering::SeqCst);
    state.notify.notify_waiters();

    // Simulate unparking
    state.parked.fetch_sub(1, Ordering::SeqCst);
    state.parked.fetch_sub(1, Ordering::SeqCst);
    state.parked.fetch_sub(1, Ordering::SeqCst);
    assert_eq!(state.parked.load(Ordering::SeqCst), 0);
}

/// Test that guard drop notifies parked waiters (async integration).
#[tokio::test]
async fn test_guard_drop_notifies_parked_waiters() {
    let state = Arc::new(OrgParkingState::new());

    // Create guard (simulates sig verification in flight)
    let guard = SigVerificationGuard::new(Arc::clone(&state));

    // Spawn a task that parks and waits for notification
    let state_clone = Arc::clone(&state);
    let waiter = tokio::spawn(async move {
        state_clone.parked.fetch_add(1, Ordering::SeqCst);
        // Wait for notification from guard drop (with timeout to prevent hang)
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            state_clone.notify.notified(),
        )
        .await
        .expect("should be notified within timeout");
        state_clone.parked.fetch_sub(1, Ordering::SeqCst);
    });

    // Small yield to ensure the waiter task has registered its notification future
    tokio::task::yield_now().await;

    // Drop guard: should notify the waiting task
    drop(guard);

    // Wait for the waiter to complete
    waiter.await.expect("waiter task should complete");
    assert_eq!(state.parked.load(Ordering::SeqCst), 0);
    assert_eq!(state.sig_in_flight.load(Ordering::SeqCst), 0);
}
