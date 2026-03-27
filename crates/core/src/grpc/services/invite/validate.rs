use super::InviteServiceImpl;
use crate::grpc::services::extract_tenant_id;
use crate::rpc::RpcError;
use crate::storage::StorageError;
use mandate_proto::mandate::v1::{ValidateInviteCodeRequest, ValidateInviteCodeResponse};
use tonic::{Request, Response, Status};

pub(super) async fn validate_invite_code(
    service: &InviteServiceImpl,
    request: Request<ValidateInviteCodeRequest>,
) -> Result<Response<ValidateInviteCodeResponse>, Status> {
    let tenant = extract_tenant_id(&request, &service.store).await?;
    let body = request.into_inner();

    if body.code.is_empty() {
        return Err(RpcError::InvalidArgument {
            field: "code",
            reason: "missing".into(),
        }
        .into());
    }

    // Rate limit check
    service.check_rate_limit(tenant)?;

    // Attempt to get the invite code — return unified NOT_FOUND for all
    // validation errors to avoid leaking information about code state.
    let entry = match service.store.get_invite_code(tenant, &body.code).await {
        Ok(entry) => entry,
        Err(StorageError::NotFound(_)) => {
            return Ok(Response::new(ValidateInviteCodeResponse {
                valid: false,
                org_id: None,
                org_name: None,
                metadata: None,
                error_reason: Some("not_found".to_string()),
            }));
        }
        Err(e) => {
            return Err(crate::grpc::services::to_status(e));
        }
    };

    // Check validity conditions
    if !entry.is_active {
        return Ok(Response::new(ValidateInviteCodeResponse {
            valid: false,
            org_id: None,
            org_name: None,
            metadata: None,
            error_reason: Some("not_found".to_string()), // Unified error
        }));
    }

    if let Some(expires_at) = entry.expires_at_ms {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;
        if now_ms > expires_at {
            return Ok(Response::new(ValidateInviteCodeResponse {
                valid: false,
                org_id: None,
                org_name: None,
                metadata: None,
                error_reason: Some("not_found".to_string()), // Unified error
            }));
        }
    }

    if entry.current_uses >= entry.max_uses {
        return Ok(Response::new(ValidateInviteCodeResponse {
            valid: false,
            org_id: None,
            org_name: None,
            metadata: None,
            error_reason: Some("not_found".to_string()), // Unified error
        }));
    }

    // Code is valid — does NOT consume usage
    Ok(Response::new(ValidateInviteCodeResponse {
        valid: true,
        org_id: Some(entry.org_id.0.to_string()),
        org_name: Some(entry.org_id.0.to_string()), // Use org_id as name for core
        metadata: entry.metadata,
        error_reason: None,
    }))
}
