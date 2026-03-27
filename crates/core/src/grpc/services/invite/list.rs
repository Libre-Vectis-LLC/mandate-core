use super::InviteServiceImpl;
use crate::grpc::services::{clamp_limit, extract_tenant_id, to_status};
use crate::rpc::RpcError;
use mandate_proto::mandate::v1::{
    InviteCode, ListInviteCodesRequest, ListInviteCodesResponse, PageToken,
};
use tonic::{Request, Response, Status};

pub(super) async fn list_invite_codes(
    service: &InviteServiceImpl,
    request: Request<ListInviteCodesRequest>,
) -> Result<Response<ListInviteCodesResponse>, Status> {
    let tenant = extract_tenant_id(&request, &service.store).await?;
    let body = request.into_inner();

    if body.org_id.is_empty() {
        return Err(RpcError::InvalidArgument {
            field: "org_id",
            reason: "missing".into(),
        }
        .into());
    }

    let org_id = body
        .org_id
        .parse::<ulid::Ulid>()
        .map(crate::ids::OrganizationId)
        .map_err(|_| RpcError::InvalidArgument {
            field: "org_id",
            reason: "invalid ULID".into(),
        })?;

    let limit = clamp_limit(body.limit, 50, 100);
    let page_token = body
        .page_token
        .as_ref()
        .filter(|pt| !pt.value.is_empty())
        .map(|pt| pt.value.clone());

    let (entries, next_token) = service
        .store
        .list_invite_codes(tenant, org_id, limit, page_token)
        .await
        .map_err(to_status)?;

    let codes: Vec<InviteCode> = entries
        .into_iter()
        .map(|e| InviteCode {
            code: e.code,
            org_id: e.org_id.0.to_string(),
            created_by: e.created_by,
            created_at: e.created_at_ms,
            expires_at: e.expires_at_ms,
            max_uses: e.max_uses,
            current_uses: e.current_uses,
            redeemed_by: None,
            metadata: e.metadata,
            is_active: e.is_active,
        })
        .collect();

    Ok(Response::new(ListInviteCodesResponse {
        codes,
        next_page_token: next_token.map(|t| PageToken { value: t }),
    }))
}
