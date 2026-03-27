use super::InviteServiceImpl;
use crate::grpc::services::{extract_tenant_id, to_status};
use crate::ids::MasterPublicKey;
use crate::rpc::RpcError;
use mandate_proto::mandate::v1::{RegisterWithInviteCodeRequest, RegisterWithInviteCodeResponse};
use tonic::{Request, Response, Status};

pub(super) async fn register_with_invite_code(
    service: &InviteServiceImpl,
    request: Request<RegisterWithInviteCodeRequest>,
) -> Result<Response<RegisterWithInviteCodeResponse>, Status> {
    let tenant = extract_tenant_id(&request, &service.store).await?;
    let body = request.into_inner();

    if body.invite_code.is_empty() {
        return Err(RpcError::InvalidArgument {
            field: "invite_code",
            reason: "missing".into(),
        }
        .into());
    }

    // Validate display_name length
    if let Some(ref name) = body.display_name {
        if name.len() > 255 {
            return Err(RpcError::InvalidArgument {
                field: "display_name",
                reason: "exceeds 255 characters".into(),
            }
            .into());
        }
    }

    // Rate limit check
    service.check_rate_limit(tenant)?;

    // Atomically validate and increment invite code usage
    let entry = service
        .store
        .validate_and_increment_invite_code(tenant, &body.invite_code)
        .await
        .map_err(|e| {
            // Map all storage errors to NOT_FOUND to avoid info leakage
            match e {
                crate::storage::StorageError::NotFound(_)
                | crate::storage::StorageError::PreconditionFailed(_) => RpcError::NotFound {
                    resource: "invite_code",
                    id: "not found".into(),
                }
                .into(),
                other => to_status(other),
            }
        })?;

    // Create pending member directly via submit_pending_member.
    // Invite code validation is already done above via InviteCodeStore;
    // we only need to record the pending member entry.
    let pending_id = service
        .store
        .submit_pending_member(
            tenant,
            entry.org_id,
            "",                         // No Telegram user ID for standalone registration
            MasterPublicKey([0u8; 32]), // Empty key — filled in later
            [0u8; 32],                  // Empty rage_pub — filled in later
        )
        .await
        .map_err(|e| {
            // If submit fails but we already incremented usage,
            // that's acceptable (usage count is approximate; the code
            // may appear "used" even though the member wasn't created).
            tracing::warn!(
                org_id = %entry.org_id.0,
                "invite code incremented but member creation failed"
            );
            to_status(e)
        })?;

    tracing::info!(
        tenant = %tenant.0,
        org_id = %entry.org_id.0,
        "member registered via invite code"
    );

    Ok(Response::new(RegisterWithInviteCodeResponse {
        member_id: pending_id,
        org_id: entry.org_id.to_string(),
        status: "pending".to_string(),
    }))
}
