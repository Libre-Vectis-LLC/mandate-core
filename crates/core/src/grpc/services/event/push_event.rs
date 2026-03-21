//! push_event gRPC handler implementation.

use super::super::{
    extract_tenant_id, max_event_bytes, max_message_content_chars, max_poll_id_length, to_status,
};
use super::service::EventServiceImpl;
use super::validation::banned_operation_for_event;
use crate::event::Event;
use crate::hashing::ring_hash;
use crate::key_manager::MandateDerivable;
use crate::rpc::RpcError;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use mandate_proto::mandate::v1::{PushEventRequest, PushEventResponse};
use nazgul::keypair::KeyPair as NazgulKeyPair;
use nazgul::ring::Ring;
use std::sync::Arc;
use tonic::{Request, Response, Status};

impl EventServiceImpl {
    pub(super) async fn push_event(
        &self,
        request: Request<PushEventRequest>,
    ) -> Result<Response<PushEventResponse>, Status> {
        let tenant = extract_tenant_id(&request, &self.store).await?;
        let body = request.into_inner();
        let event_bytes: crate::storage::EventBytes = body.event_bytes.into();
        if event_bytes.len() > max_event_bytes() {
            return Err(RpcError::InvalidArgument {
                field: "event_bytes",
                reason: format!("too large: {} > {}", event_bytes.len(), max_event_bytes()),
            }
            .into());
        }
        let mut event: Event =
            serde_json::from_slice(&event_bytes).map_err(|e| RpcError::InvalidArgument {
                field: "event_bytes",
                reason: format!("invalid JSON payload: {e}"),
            })?;

        // Verify tenant owns the organization referenced by this event
        let (org_tenant, _) = self
            .store
            .get_organization(event.org_id)
            .await
            .map_err(to_status)?;
        if tenant != org_tenant {
            return Err(RpcError::NotFound {
                resource: "organization",
                id: "not found".into(),
            }
            .into());
        }

        // Validate poll_id length for poll/vote events to prevent resource exhaustion
        let max_id_len = max_poll_id_length();
        match &event.event_type {
            crate::event::EventType::PollCreate(poll) => {
                if poll.poll_id.len() > max_id_len {
                    return Err(RpcError::InvalidArgument {
                        field: "poll_id",
                        reason: format!("too long: {} > {}", poll.poll_id.len(), max_id_len),
                    }
                    .into());
                }
                for q in &poll.questions {
                    if q.question_id.len() > max_id_len {
                        return Err(RpcError::InvalidArgument {
                            field: "question_id",
                            reason: format!("too long: {} > {}", q.question_id.len(), max_id_len),
                        }
                        .into());
                    }
                }
            }
            crate::event::EventType::VoteCast(vote) => {
                if vote.poll_id.len() > max_id_len {
                    return Err(RpcError::InvalidArgument {
                        field: "poll_id",
                        reason: format!("too long: {} > {}", vote.poll_id.len(), max_id_len),
                    }
                    .into());
                }
            }
            crate::event::EventType::VoteRevocation(vr) => {
                if vr.poll_id.len() > max_id_len {
                    return Err(RpcError::InvalidArgument {
                        field: "poll_id",
                        reason: format!("too long: {} > {}", vr.poll_id.len(), max_id_len),
                    }
                    .into());
                }
            }
            crate::event::EventType::PollBundlePublished(pb) => {
                if pb.poll_id.len() > max_id_len {
                    return Err(RpcError::InvalidArgument {
                        field: "poll_id",
                        reason: format!("too long: {} > {}", pb.poll_id.len(), max_id_len),
                    }
                    .into());
                }
            }
            crate::event::EventType::MessageCreate(msg) => {
                // Count UTF-8 characters (not bytes) for proper international text support
                let content_chars = String::from_utf8_lossy(&msg.content.0).chars().count();
                let max_chars = max_message_content_chars();
                if content_chars > max_chars {
                    return Err(RpcError::InvalidArgument {
                        field: "message_content",
                        reason: format!("too long: {content_chars} characters > {max_chars} limit"),
                    }
                    .into());
                }
            }
            _ => {}
        }

        // Validate poll existence for VoteCast events (before expensive signature verification)
        // This provides fast-path rejection for votes targeting non-existent polls.
        //
        // SECURITY: We MUST reject NotFound because signature verification alone cannot
        // validate poll existence - it only verifies the ring hash is valid. An attacker
        // could craft a VoteCast with any valid ring hash but a fake poll_id.
        if let crate::event::EventType::VoteCast(vote) = &event.event_type {
            match self
                .store
                .get_poll_ring_hash(tenant, event.org_id, &vote.poll_id)
                .await
            {
                Ok(poll_ring_hash) => {
                    // Poll exists — verify the vote's declared poll_ring_hash matches
                    // the ring hash snapshot stored at poll creation time.
                    //
                    // SECURITY: Without this check, an attacker could cast a vote using
                    // a newer (or different) ring while claiming it targets a poll that
                    // was created under a different ring. This binds votes to the exact
                    // ring membership that existed when the poll was created.
                    if vote.poll_ring_hash != poll_ring_hash {
                        return Err(RpcError::FailedPrecondition {
                            operation: "vote_ring_binding",
                            reason: "vote.poll_ring_hash does not match poll snapshot".into(),
                        }
                        .into());
                    }
                }
                Err(crate::storage::StorageError::NotFound(_)) => {
                    // Poll not found in ring-hash index - reject the vote.
                    // This prevents votes against non-existent polls.
                    return Err(RpcError::FailedPrecondition {
                        operation: "poll_existence",
                        reason: format!("poll does not exist: {}", vote.poll_id),
                    }
                    .into());
                }
                Err(other) => return Err(to_status(other)),
            }
        }

        // Validate poll existence and election phase for VoteRevocation events.
        //
        // VoteRevocation is only accepted during the VerificationOpen phase.
        // The server retrieves the poll's ring hash (for later ring derivation)
        // and the bundle_published_at timestamp (for phase determination).
        //
        // SECURITY: Unlike VoteCast, VoteRevocation does not carry poll_ring_hash
        // in its body. The server looks it up from the PollRingHashIndex and uses
        // it to derive the per-poll signing ring for signature verification.
        //
        // We store the looked-up poll_ring_hash for use during ring derivation
        // in step 3b (compact signature ring loading).
        let mut vote_revocation_poll_ring_hash: Option<crate::ids::RingHash> = None;
        if let crate::event::EventType::VoteRevocation(vr) = &event.event_type {
            let poll_ring_hash = match self
                .store
                .get_poll_ring_hash(tenant, event.org_id, &vr.poll_id)
                .await
            {
                Ok(h) => h,
                Err(crate::storage::StorageError::NotFound(_)) => {
                    return Err(RpcError::FailedPrecondition {
                        operation: "poll_existence",
                        reason: format!("poll does not exist: {}", vr.poll_id),
                    }
                    .into());
                }
                Err(other) => return Err(to_status(other)),
            };

            // Check election phase: VoteRevocation is only accepted during VerificationOpen.
            //
            // To determine the phase, we need:
            // 1. The Poll event data (for deadline/verification_window_secs)
            // 2. The bundle_published_at timestamp
            //
            // For now, we check bundle_published_at: if None, the poll is not yet in
            // VerificationOpen (still Sealed or Voting). If Some, we accept the
            // revocation during the VerificationOpen window.
            //
            // Full phase validation using Poll::election_phase() requires reconstructing
            // the Poll struct from storage, which will be added when PollMetadataIndex
            // is implemented. For now, the bundle_published_at check provides the
            // essential guard: revocations are only accepted after bundle publication.
            let bundle_published_at = self
                .store
                .get_bundle_published_at(tenant, event.org_id, &vr.poll_id)
                .await
                .map_err(to_status)?;

            if bundle_published_at.is_none() {
                return Err(RpcError::FailedPrecondition {
                    operation: "vote_revocation_phase",
                    reason: "poll bundle has not been published yet; \
                             vote revocation is only accepted during VerificationOpen phase"
                        .into(),
                }
                .into());
            }

            vote_revocation_poll_ring_hash = Some(poll_ring_hash);
        }

        // Validate poll existence for PollBundlePublished events.
        //
        // The poll must exist before a bundle can be published for it.
        // Also reject duplicate bundle publications (idempotency).
        if let crate::event::EventType::PollBundlePublished(pb) = &event.event_type {
            match self
                .store
                .get_poll_ring_hash(tenant, event.org_id, &pb.poll_id)
                .await
            {
                Ok(_) => { /* poll exists, proceed */ }
                Err(crate::storage::StorageError::NotFound(_)) => {
                    return Err(RpcError::FailedPrecondition {
                        operation: "poll_existence",
                        reason: format!("poll does not exist: {}", pb.poll_id),
                    }
                    .into());
                }
                Err(other) => return Err(to_status(other)),
            }

            // Reject duplicate bundle publication.
            let already_published = self
                .store
                .get_bundle_published_at(tenant, event.org_id, &pb.poll_id)
                .await
                .map_err(to_status)?;
            if already_published.is_some() {
                return Err(RpcError::FailedPrecondition {
                    operation: "bundle_publication",
                    reason: format!("bundle already published for poll: {}", pb.poll_id),
                }
                .into());
            }
        }

        // 1. Auto-fill Chain Hash
        //
        // The server automatically assigns the correct previous_event_hash based on chain state.
        // This enables O(n) concurrent event submissions without client re-signing on conflicts.
        //
        // Security note: Chain integrity is enforced by Party A's Edge and Bot monitoring.
        // The signature does NOT include previous_event_hash (see Event::to_signing_bytes).
        match self.store.event_tail(tenant, event.org_id).await {
            Ok((tail_id, _, _)) => {
                // Chain exists - set previous_event_hash to current tail
                event.previous_event_hash = crate::ids::EventId(tail_id.0);
            }
            Err(crate::storage::StorageError::NotFound(_)) => {
                // Genesis event - set zero prev hash
                event.previous_event_hash = crate::ids::EventId([0u8; 32]);
            }
            Err(e) => return Err(to_status(e)),
        }

        let sig = event
            .signature
            .as_ref()
            .ok_or_else(|| RpcError::Unauthenticated {
                credential: "signature",
                reason: "missing".into(),
            })?;
        let key_image = sig.key_image();

        // 2. Cheap checks (anti-replay, bans)
        if let crate::event::EventType::VoteCast(vote) = &event.event_type {
            let used = self
                .store
                .is_vote_key_image_used(tenant, event.org_id, &vote.poll_id, &key_image)
                .await
                .map_err(to_status)?;
            if used {
                return Err(RpcError::FailedPrecondition {
                    operation: "vote_cast",
                    reason: "duplicate key image (vote already cast)".into(),
                }
                .into());
            }
        }

        // 2a. VoteRevocation idempotency: reject duplicate revocations for same (key_image, poll_id).
        //
        // SECURITY: Prevents replay of revocation events. A member can only revoke
        // their vote once per poll. The key_image binds the revocation to the same
        // identity that cast the original vote.
        if let crate::event::EventType::VoteRevocation(vr) = &event.event_type {
            // First check: was a vote actually cast with this key image?
            let vote_exists = self
                .store
                .is_vote_key_image_used(tenant, event.org_id, &vr.poll_id, &key_image)
                .await
                .map_err(to_status)?;
            if !vote_exists {
                return Err(RpcError::FailedPrecondition {
                    operation: "vote_revocation",
                    reason: "no vote found for this key image in this poll".into(),
                }
                .into());
            }

            // Second check: has this vote already been revoked?
            let already_revoked = self
                .store
                .is_vote_revoked(tenant, event.org_id, &vr.poll_id, &key_image)
                .await
                .map_err(to_status)?;
            if already_revoked {
                return Err(RpcError::FailedPrecondition {
                    operation: "vote_revocation",
                    reason: "vote has already been revoked".into(),
                }
                .into());
            }
        }

        if let Some(operation) = banned_operation_for_event(&event.event_type) {
            let banned = self
                .store
                .is_banned(tenant, event.org_id, &key_image, operation)
                .await
                .map_err(to_status)?;
            if banned {
                return Err(RpcError::FailedPrecondition {
                    operation: "banned_check",
                    reason: format!("key image banned for {operation:?}"),
                }
                .into());
            }
        }

        // 2b. Verify owner/delegate for admin events (ban + ring management + poll bundle)
        let delegate_external_ring = match &event.event_type {
            crate::event::EventType::BanCreate(_)
            | crate::event::EventType::BanRevoke(_)
            | crate::event::EventType::RingUpdate(_)
            | crate::event::EventType::PollBundlePublished(_) => {
                // Get owner's public key from storage
                let owner_pubkey = self
                    .store
                    .get_owner_pubkey(event.org_id)
                    .await
                    .map_err(to_status)?
                    .ok_or_else(|| RpcError::FailedPrecondition {
                        operation: "delegate_verification",
                        reason: "owner public key not set".into(),
                    })?;

                // Decompress owner's public key to a RistrettoPoint
                let compressed = CompressedRistretto::from_slice(&owner_pubkey.0).map_err(|e| {
                    RpcError::FailedPrecondition {
                        operation: "delegate_verification",
                        reason: format!("invalid owner public key: {e}"),
                    }
                })?;
                let owner_point: RistrettoPoint =
                    compressed
                        .decompress()
                        .ok_or_else(|| RpcError::FailedPrecondition {
                            operation: "delegate_verification",
                            reason: "invalid owner public key".into(),
                        })?;

                // Create owner keypair (public key only) for derivation
                let owner_kp = NazgulKeyPair::from_public_key_only(owner_point);

                // Derive delegate key using the canonical MandateDerivable trait
                // (ensures consistent info() encoding with client-side derivation)
                let delegate_kp = owner_kp.derive_delegate(&event.org_id);

                // Build single-element ring containing only the delegate public key
                let delegate_ring = Ring::new(vec![*delegate_kp.public()]);
                let delegate_hash = ring_hash(&delegate_ring);

                // Verify that the signature's ring hash matches the expected delegate ring hash
                // Use sig.ring_hash() as the authoritative source for what ring was used to sign
                let actual_ring_hash = sig.ring_hash();
                if actual_ring_hash != delegate_hash {
                    return Err(RpcError::PermissionDenied {
                        resource: "admin_event",
                        reason: "signature ring is not the owner/delegate ring".into(),
                    }
                    .into());
                }

                // Only provide delegate ring for Compact mode; Archival mode embeds its own ring
                match sig.mode() {
                    crate::crypto::signature::StorageMode::Compact => Some(Arc::new(delegate_ring)),
                    crate::crypto::signature::StorageMode::Archival => None,
                }
            }
            _ => None,
        };

        // 2c. Check ban limit for BanCreate events (OOM protection)
        if let crate::event::EventType::BanCreate(ban) = &event.event_type {
            let current_count = self
                .store
                .count_bans_for_ring(tenant, event.org_id, &ban.ring_hash)
                .await
                .map_err(to_status)?;
            if current_count >= crate::storage::MAX_BANS_PER_RING_HASH {
                return Err(RpcError::FailedPrecondition {
                    operation: "ban_create",
                    reason: format!(
                        "too many bans for ring hash (limit: {})",
                        crate::storage::MAX_BANS_PER_RING_HASH
                    ),
                }
                .into());
            }
        }

        // 3. POW gate: if this org is in POW mode, require valid proof before
        //    spending CPU on expensive signature verification.
        //
        //    Lazy PoW verification: when sig verification is in-flight for this org,
        //    park the request. When sig verification completes:
        //    - If sig failed → difficulty upgraded → parked request's PoW is stale → reject O(1)
        //    - If sig passed → maybe recovery → skip PoW entirely if no longer required
        let mut pow_proof_count: Option<usize> = None;
        let pow_key = (tenant, event.org_id);
        {
            let pow_required = self
                .pow_states
                .get(&pow_key)
                .map(|s| s.should_require_pow())
                .unwrap_or(false);

            if pow_required {
                match &body.pow_submission {
                    None => {
                        // POW required but not provided — return challenge parameters.
                        return Err(self.make_pow_challenge_status(tenant, event.org_id));
                    }
                    Some(proto_sub) => {
                        // Lazy verification: if sig verification is in-flight, park this request.
                        // Skip parking if DashMap is at capacity (verify PoW immediately instead).
                        let parking_state = if self.pow_parking_at_capacity()
                            && !self.pow_parking.contains_key(&pow_key)
                        {
                            None
                        } else {
                            Some(
                                self.pow_parking
                                    .entry(pow_key)
                                    .or_insert_with(|| {
                                        Arc::new(super::service::OrgParkingState::new())
                                    })
                                    .clone(),
                            )
                        };

                        let should_park = parking_state
                            .as_ref()
                            .map(|ps| {
                                ps.sig_in_flight.load(std::sync::atomic::Ordering::SeqCst) > 0
                            })
                            .unwrap_or(false);

                        if should_park {
                            let ps = parking_state.as_ref().unwrap();
                            // Check parking capacity.
                            let current_parked =
                                ps.parked.load(std::sync::atomic::Ordering::SeqCst);
                            if current_parked >= self.pow_parking_limit {
                                // Parking full — reject immediately with current challenge.
                                tracing::warn!(
                                    tenant_id = %tenant.0,
                                    organization_id = %event.org_id,
                                    parked_count = current_parked,
                                    limit = self.pow_parking_limit,
                                    "pow_parking_full"
                                );
                                return Err(self.make_pow_challenge_status(tenant, event.org_id));
                            }

                            // Park: wait for sig verification to complete (with TTL).
                            ps.parked.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            let park_result =
                                tokio::time::timeout(self.pow_parking_ttl, ps.notify.notified())
                                    .await;
                            ps.parked.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);

                            if park_result.is_err() {
                                // TTL expired — reject with current challenge.
                                return Err(self.make_pow_challenge_status(tenant, event.org_id));
                            }

                            // Re-check: sig verification completed, pow state may have changed.
                            let still_required = self
                                .pow_states
                                .get(&pow_key)
                                .map(|s| s.should_require_pow())
                                .unwrap_or(false);
                            if !still_required {
                                // Recovery happened — skip PoW verification entirely.
                            } else {
                                self.verify_pow_submission(tenant, event.org_id, proto_sub)
                                    .await?;
                                let (params, _) =
                                    self.current_pow_params_and_version(tenant, event.org_id);
                                pow_proof_count = Some(params.required_proofs);
                            }
                        } else {
                            // No in-flight sig verification or parking unavailable — verify PoW immediately.
                            self.verify_pow_submission(tenant, event.org_id, proto_sub)
                                .await?;
                            let (params, _) =
                                self.current_pow_params_and_version(tenant, event.org_id);
                            pow_proof_count = Some(params.required_proofs);
                        }
                    }
                }
            }
        }

        // 3b. Verify Signature
        // Load ring if needed (Compact signature)
        let external_ring = if let Some(ring) = delegate_external_ring {
            Some(ring)
        } else {
            match sig.mode() {
                crate::crypto::signature::StorageMode::Compact => {
                    if let crate::event::EventType::VoteCast(vote) = &event.event_type {
                        let vote_signing_ring = self
                            .get_or_derive_vote_signing_ring(
                                tenant,
                                event.org_id,
                                vote.poll_ring_hash,
                                &vote.poll_id,
                            )
                            .await?;
                        let expected_vote_ring_hash = ring_hash(vote_signing_ring.as_ref());
                        if vote.ring_hash != expected_vote_ring_hash {
                            return Err(RpcError::FailedPrecondition {
                                operation: "vote_signing_ring_binding",
                                reason:
                                    "vote.ring_hash does not match derived per-poll signing ring"
                                        .into(),
                            }
                            .into());
                        }
                        Some(vote_signing_ring)
                    } else if let crate::event::EventType::VoteRevocation(vr) = &event.event_type {
                        // VoteRevocation uses the same per-poll derived signing ring as VoteCast.
                        // The poll_ring_hash was looked up from PollRingHashIndex during
                        // the pre-check phase and stored in vote_revocation_poll_ring_hash.
                        let poll_ring_hash =
                            vote_revocation_poll_ring_hash.ok_or_else(|| RpcError::Internal {
                                operation: "vote_revocation_ring",
                                details: "poll_ring_hash not set (pre-check skipped?)".into(),
                            })?;
                        let revocation_signing_ring = self
                            .get_or_derive_vote_signing_ring(
                                tenant,
                                event.org_id,
                                poll_ring_hash,
                                &vr.poll_id,
                            )
                            .await?;
                        let expected_ring_hash = ring_hash(revocation_signing_ring.as_ref());
                        if vr.ring_hash != expected_ring_hash {
                            return Err(RpcError::FailedPrecondition {
                                operation: "revocation_signing_ring_binding",
                                reason: "vr.ring_hash does not match derived per-poll signing ring"
                                    .into(),
                            }
                            .into());
                        }
                        Some(revocation_signing_ring)
                    } else {
                        // Get ring hash from event body if available, otherwise use signature's ring hash.
                        // BanRevoke events don't store ring_hash in body, so we use the signature's.
                        let ring_hash = event
                            .event_type
                            .ring_hash()
                            .unwrap_or_else(|| sig.ring_hash());

                        Some(
                            self.store
                                .ring_by_hash(tenant, event.org_id, &ring_hash)
                                .await
                                .map_err(to_status)?,
                        )
                    }
                }
                crate::crypto::signature::StorageMode::Archival => None,
            }
        };

        // Enforce per-poll vote signing ring derivation for archival votes and revocations.
        if matches!(sig.mode(), crate::crypto::signature::StorageMode::Archival) {
            if let crate::event::EventType::VoteCast(vote) = &event.event_type {
                let vote_signing_ring = self
                    .get_or_derive_vote_signing_ring(
                        tenant,
                        event.org_id,
                        vote.poll_ring_hash,
                        &vote.poll_id,
                    )
                    .await?;
                let expected_vote_ring_hash = ring_hash(vote_signing_ring.as_ref());
                if vote.ring_hash != expected_vote_ring_hash {
                    return Err(RpcError::FailedPrecondition {
                        operation: "vote_signing_ring_binding",
                        reason: "vote.ring_hash does not match derived per-poll signing ring"
                            .into(),
                    }
                    .into());
                }
            }
            if let crate::event::EventType::VoteRevocation(vr) = &event.event_type {
                let poll_ring_hash =
                    vote_revocation_poll_ring_hash.ok_or_else(|| RpcError::Internal {
                        operation: "vote_revocation_ring",
                        details: "poll_ring_hash not set (pre-check skipped?)".into(),
                    })?;
                let revocation_signing_ring = self
                    .get_or_derive_vote_signing_ring(
                        tenant,
                        event.org_id,
                        poll_ring_hash,
                        &vr.poll_id,
                    )
                    .await?;
                let expected_ring_hash = ring_hash(revocation_signing_ring.as_ref());
                if vr.ring_hash != expected_ring_hash {
                    return Err(RpcError::FailedPrecondition {
                        operation: "revocation_signing_ring_binding",
                        reason: "vr.ring_hash does not match derived per-poll signing ring".into(),
                    }
                    .into());
                }
            }
        }

        let signed_msg = event.to_signing_bytes().map_err(|e| RpcError::Internal {
            operation: "event_serialization",
            details: format!("canonical serialization failed: {e}"),
        })?;

        let ring_size =
            Self::verification_ring_size(sig, external_ring.as_deref()).ok_or_else(|| {
                RpcError::Internal {
                    operation: "verification_meter",
                    details: "compact signature missing external ring".into(),
                }
            })?;
        let message_bytes = signed_msg.len();

        let item = crate::crypto::verifier::SignatureItem {
            signature: sig.clone(),
            message: signed_msg,
            weight: 1,
            external_ring,
            organization_id: event.org_id.to_string(),
        };

        // Acquire sig verification guard: tracks in-flight count and notifies parked
        // PoW requests when dropped (on completion, error, or panic).
        // Skip guard if parking DashMap is at capacity for new orgs.
        let _sig_guard =
            if self.pow_parking_at_capacity() && !self.pow_parking.contains_key(&pow_key) {
                None
            } else {
                let ps = self
                    .pow_parking
                    .entry(pow_key)
                    .or_insert_with(|| Arc::new(super::service::OrgParkingState::new()))
                    .clone();
                Some(super::service::SigVerificationGuard::new(ps))
            };

        let results =
            self.verifier
                .verify_batch(&[item])
                .await
                .map_err(|e| RpcError::Internal {
                    operation: "signature_verification",
                    details: e.to_string(),
                })?;
        if !results[0] {
            // Record failure in POW state machine — may trigger or escalate POW requirement.
            // Guard: skip tracking if DashMap is at capacity (graceful degradation for new orgs).
            let should_challenge =
                if self.pow_states_at_capacity() && !self.pow_states.contains_key(&pow_key) {
                    // DashMap at capacity — skip PoW tracking for this new org (graceful degradation).
                    tracing::error!(
                        current_count = self.pow_states.len(),
                        max_count = super::service::MAX_POW_STATE_ENTRIES,
                        "pow_states_capacity_warning"
                    );
                    false
                } else {
                    let mut state = self.pow_states.entry(pow_key).or_default();
                    let was_pow_required = state.pow_required;
                    let old_version = state.difficulty_version;
                    let org_config = self.resolve_pow_config(&pow_key);
                    state.on_verification_failure(&org_config);
                    let new_version = state.difficulty_version;

                    if state.pow_required && !was_pow_required {
                        // First time PoW is triggered for this org
                        let (params, _) = self.current_pow_params_and_version(tenant, event.org_id);
                        tracing::info!(
                            tenant_id = %tenant.0,
                            organization_id = %event.org_id,
                            difficulty_version = new_version,
                            required_proofs = params.required_proofs,
                            "pow_triggered"
                        );
                    } else if state.pow_required && was_pow_required && new_version != old_version {
                        // Difficulty escalated
                        let (params, _) = self.current_pow_params_and_version(tenant, event.org_id);
                        tracing::info!(
                            tenant_id = %tenant.0,
                            organization_id = %event.org_id,
                            old_version = old_version,
                            new_version = new_version,
                            new_required_proofs = params.required_proofs,
                            "pow_difficulty_escalated"
                        );
                    }

                    state.should_require_pow()
                };

            if should_challenge {
                // Drop guard before returning to notify parked requests.
                drop(_sig_guard);
                return Err(self.make_pow_challenge_status(tenant, event.org_id));
            }

            return Err(RpcError::Unauthenticated {
                credential: "signature",
                reason: "verification failed".into(),
            }
            .into());
        }

        // Signature verified successfully — record success, potentially recover from POW mode.
        {
            if let Some(mut state) = self.pow_states.get_mut(&pow_key) {
                let was_pow_required = state.pow_required;
                let org_config = self.resolve_pow_config(&pow_key);
                state.on_verification_success(&org_config);
                if was_pow_required && !state.pow_required {
                    tracing::info!(
                        tenant_id = %tenant.0,
                        organization_id = %event.org_id,
                        "pow_recovered"
                    );
                }
            }
        }

        // Drop guard to notify parked requests that sig verification is complete.
        drop(_sig_guard);

        // Charge verification AFTER successful signature verification.
        // This prevents economic DoS where attackers drain balance with invalid signatures.
        // PoW proof count is included when applicable so CPU-heavy PoW work is billed.
        self.verification_meter
            .charge_verification(
                &event.org_id.to_string(),
                ring_size,
                message_bytes,
                pow_proof_count,
            )
            .await
            .map_err(Self::verification_meter_error_to_status)?;

        // 3b. Archival ring_hash consistency check
        //
        // For Archival signatures, the ring is embedded in the signature itself.
        // Verify that the embedded ring's hash matches the ring_hash declared in
        // the event body. Without this check, an attacker could declare ring_hash X
        // (matching a legitimate ring) but embed a different ring Y in the signature.
        //
        // Admin events (BanCreate/BanRevoke/RingUpdate) are excluded because their
        // ring hash was already verified against the delegate ring in step 2b.
        if matches!(sig.mode(), crate::crypto::signature::StorageMode::Archival) {
            let is_admin_event = matches!(
                &event.event_type,
                crate::event::EventType::BanCreate(_)
                    | crate::event::EventType::BanRevoke(_)
                    | crate::event::EventType::RingUpdate(_)
                    | crate::event::EventType::PollBundlePublished(_)
            );
            if !is_admin_event {
                if let Some(declared_hash) = event.event_type.ring_hash() {
                    let sig_ring_hash = sig.ring_hash();
                    if sig_ring_hash != declared_hash {
                        return Err(RpcError::FailedPrecondition {
                            operation: "archival_ring_hash_consistency",
                            reason: "embedded ring hash does not match declared ring_hash".into(),
                        }
                        .into());
                    }
                }
            }
        }

        if let crate::event::EventType::RingUpdate(update) = &event.event_type {
            self.validate_and_apply_ring_update(tenant, event.org_id, update)
                .await?;
        }

        // 4. Store poll ring hash BEFORE committing the event
        //
        // DESIGN DECISION: Index write happens before event commit for consistent error handling.
        // - If index write fails → Event not committed, clean failure
        // - If event commit fails → Orphan index entry exists, but harmless:
        //   VoteCast validates ring hash against signature, so votes against orphan entries
        //   will fail signature verification (ring hash won't match any real poll)
        //
        // This ordering ensures we never return an error after the event is committed,
        // which would confuse clients about the actual state.
        if let crate::event::EventType::PollCreate(poll) = &event.event_type {
            self.store
                .store_poll_ring_hash(tenant, event.org_id, &poll.poll_id, poll.ring_hash)
                .await
                .map_err(to_status)?;
        }

        // 4b. Store PollBundlePublished timestamp BEFORE committing the event.
        //
        // This records when the bundle was published, enabling the
        // Sealed → VerificationOpen phase transition. Subsequent VoteRevocation
        // events will check this timestamp to verify the poll is in the correct phase.
        //
        // DESIGN DECISION: Same ordering rationale as step 4 — index write before
        // event commit. An orphan timestamp entry is harmless (it just means the
        // phase check will see VerificationOpen for a poll whose event wasn't committed).
        if let crate::event::EventType::PollBundlePublished(pb) = &event.event_type {
            // Use the event's ULID timestamp as the bundle publication time.
            let published_at = event.event_ulid.as_ulid().timestamp_ms() / 1000;
            self.store
                .store_bundle_published_at(tenant, event.org_id, &pb.poll_id, published_at)
                .await
                .map_err(to_status)?;
        }

        // 5. Commit the event
        //
        // Re-serialize the event to include the server-assigned previous_event_hash.
        // This ensures the stored event has the correct chain linkage.
        let final_event_bytes: crate::storage::EventBytes = serde_json::to_vec(&event)
            .map_err(|e| RpcError::Internal {
                operation: "event_serialization",
                details: format!("failed to serialize event: {e}"),
            })?
            .into();

        let id = self
            .store
            .append_event(tenant, event.org_id, final_event_bytes)
            .await
            .map_err(to_status)?;

        // 5b. Record vote revocation AFTER event commit.
        //
        // The revocation record references the committed event's ID, so it must
        // happen after append_event. If this write fails, the event is already
        // committed but the revocation index is missing — a subsequent revocation
        // attempt for the same key image would succeed (not idempotent). This is
        // acceptable for P1: the worst case is a duplicate revocation event in the
        // log, which auditors can detect. Full atomicity will be addressed in P5.1
        // with database transactions.
        if let crate::event::EventType::VoteRevocation(vr) = &event.event_type {
            self.store
                .store_vote_revocation(tenant, event.org_id, &vr.poll_id, &key_image, &id.0)
                .await
                .map_err(to_status)?;
        }

        let event_hash = crate::proto::event_id_to_hash32(&id.0);
        let event_ulid = crate::proto::ulid_to_proto(&event.event_ulid.as_ulid());
        Ok(Response::new(PushEventResponse {
            event_ulid: Some(event_ulid),
            event_hash: Some(event_hash),
            sequence_no: id.1.as_i64(),
            event_url: None, // Set by Edge proxy for poll events with Onion URL
        }))
    }
}
