use super::InviteServiceImpl;
use crate::grpc::services::{extract_tenant_id, to_status};
use crate::rpc::RpcError;
use crate::storage::invite_code::CreateInviteCodeParams;
use mandate_proto::mandate::v1::{CreateInviteCodeRequest, CreateInviteCodeResponse};
use tonic::{Request, Response, Status};

pub(super) async fn create_invite_code(
    service: &InviteServiceImpl,
    request: Request<CreateInviteCodeRequest>,
) -> Result<Response<CreateInviteCodeResponse>, Status> {
    let tenant = extract_tenant_id(&request, &service.store).await?;
    let body = request.into_inner();

    // Validate org_id
    if body.org_id.is_empty() {
        return Err(RpcError::InvalidArgument {
            field: "org_id",
            reason: "missing".into(),
        }
        .into());
    }

    // Validate max_uses >= 1
    if body.max_uses == 0 {
        return Err(RpcError::InvalidArgument {
            field: "max_uses",
            reason: "must be >= 1".into(),
        }
        .into());
    }

    // Validate expires_at is in the future (if set)
    if let Some(expires_at) = body.expires_at {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;
        if expires_at <= now_ms {
            return Err(RpcError::InvalidArgument {
                field: "expires_at",
                reason: "must be in the future".into(),
            }
            .into());
        }
    }

    // Validate metadata length
    if let Some(ref metadata) = body.metadata {
        if metadata.len() > 4096 {
            return Err(RpcError::InvalidArgument {
                field: "metadata",
                reason: "exceeds 4096 bytes".into(),
            }
            .into());
        }
    }

    let org_id = body
        .org_id
        .parse::<ulid::Ulid>()
        .map(crate::ids::OrganizationId)
        .map_err(|_| RpcError::InvalidArgument {
            field: "org_id",
            reason: "invalid ULID".into(),
        })?;

    let params = CreateInviteCodeParams {
        org_id,
        created_by: tenant.0.to_string(), // Use tenant ID as admin identifier
        expires_at_ms: body.expires_at,
        max_uses: body.max_uses,
        metadata: body.metadata,
    };

    let code = service
        .store
        .create_invite_code(tenant, params)
        .await
        .map_err(to_status)?;

    // Log code creation without revealing the actual code value
    tracing::info!(
        tenant = %tenant.0,
        org_id = %org_id.0,
        max_uses = body.max_uses,
        "invite code created"
    );

    Ok(Response::new(CreateInviteCodeResponse {
        code: code.clone(),
        invite_url: code, // Core doesn't know the URL base; caller assembles the URL
    }))
}
