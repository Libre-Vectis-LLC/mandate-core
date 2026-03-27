use super::InviteServiceImpl;
use crate::grpc::services::{extract_tenant_id, to_status};
use crate::rpc::RpcError;
use mandate_proto::mandate::v1::{RevokeInviteCodeRequest, RevokeInviteCodeResponse};
use tonic::{Request, Response, Status};

pub(super) async fn revoke_invite_code(
    service: &InviteServiceImpl,
    request: Request<RevokeInviteCodeRequest>,
) -> Result<Response<RevokeInviteCodeResponse>, Status> {
    let tenant = extract_tenant_id(&request, &service.store).await?;
    let body = request.into_inner();

    if body.code.is_empty() {
        return Err(RpcError::InvalidArgument {
            field: "code",
            reason: "missing".into(),
        }
        .into());
    }

    // Log revocation without revealing the actual code value
    tracing::info!(
        tenant = %tenant.0,
        code_len = body.code.len(),
        "invite code revocation requested"
    );

    service
        .store
        .revoke_invite_code(tenant, &body.code)
        .await
        .map_err(to_status)?;

    Ok(Response::new(RevokeInviteCodeResponse { success: true }))
}
