//! ListMemberOrganizations RPC handler.

use crate::grpc::services::{clamp_events_limit, extract_tenant_id, to_status};
use mandate_proto::mandate::v1::{
    OrganizationMembership, ListMemberOrganizationsRequest, ListMemberOrganizationsResponse, PageToken,
};
use tonic::{Request, Response, Status};

use super::MemberServiceImpl;

pub(super) async fn list_member_organizations(
    service: &MemberServiceImpl,
    request: Request<ListMemberOrganizationsRequest>,
) -> Result<Response<ListMemberOrganizationsResponse>, Status> {
    // Extract tenant from authentication context
    let tenant = extract_tenant_id(&request, &service.store).await?;
    let body = request.into_inner();

    // Validate nazgul_pub length
    if body.nazgul_pub.len() != 32 {
        return Err(Status::invalid_argument(
            "nazgul_pub must be exactly 32 bytes",
        ));
    }

    // Extract filter_status parameter
    let filter_status = if body.filter_status.as_deref() == Some("") {
        None
    } else {
        body.filter_status.as_deref()
    };

    // Query groups for this member
    let (groups, next_page, total_count) = service
        .store
        .list_organizations_for_member(
            tenant,
            &body.nazgul_pub,
            clamp_events_limit(body.limit),
            body.page_token.as_ref().and_then(|t| {
                if t.value.is_empty() {
                    None
                } else {
                    Some(t.value.clone())
                }
            }),
            filter_status,
        )
        .await
        .map_err(to_status)?;

    // Convert to proto messages
    let proto_groups = groups
        .into_iter()
        .map(|g| OrganizationMembership {
            org_id: g.org_id.to_string(),
            joined_at: g.joined_at_ms,
            status: g.status,
        })
        .collect();

    Ok(Response::new(ListMemberOrganizationsResponse {
        orgs: proto_groups,
        next_page_token: next_page.map(|value| PageToken { value }),
        total_count,
    }))
}
