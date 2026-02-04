//! Pending member operations.

use crate::ids::GroupId;
use crate::rpc::RpcError;
use mandate_proto::mandate::v1::{
    GetApprovedMemberByTgUserIdRequest, GetApprovedMemberByTgUserIdResponse,
    ListPendingMembersRequest, ListPendingMembersResponse, PendingMember as ProtoPendingMember,
    RegisterMemberRequest, RegisterMemberResponse, SubmitPendingMemberRequest,
    SubmitPendingMemberResponse,
};
use tonic::{Request, Response, Status};

use super::super::{clamp_events_limit, extract_tenant_id, to_status};
use super::MemberServiceImpl;

pub(super) async fn submit_pending_member(
    service: &MemberServiceImpl,
    request: Request<SubmitPendingMemberRequest>,
) -> Result<Response<SubmitPendingMemberResponse>, Status> {
    let body = request.into_inner();
    let group_id = GroupId(crate::proto::parse_ulid(&body.group_id).map_err(|e| {
        RpcError::InvalidArgument {
            field: "group_id",
            reason: e.to_string(),
        }
    })?);

    let (tenant, _) = service.store.get_group(group_id).await.map_err(to_status)?;

    let nazgul_pub = body
        .nazgul_pub
        .as_ref()
        .ok_or_else(|| RpcError::InvalidArgument {
            field: "nazgul_pub",
            reason: "missing".into(),
        })?;
    let nazgul_pub =
        crate::proto::nazgul_pub_from_proto(nazgul_pub).map_err(|e| RpcError::InvalidArgument {
            field: "nazgul_pub",
            reason: e.to_string(),
        })?;

    let rage_pub = body
        .rage_pub
        .as_ref()
        .ok_or_else(|| RpcError::InvalidArgument {
            field: "rage_pub",
            reason: "missing".into(),
        })?;
    let rage_pub =
        crate::proto::rage_pub_from_proto(rage_pub).map_err(|e| RpcError::InvalidArgument {
            field: "rage_pub",
            reason: e.to_string(),
        })?;

    let pending_id = service
        .store
        .submit_pending_member(tenant, group_id, &body.tg_user_id, nazgul_pub, rage_pub)
        .await
        .map_err(to_status)?;

    Ok(Response::new(SubmitPendingMemberResponse { pending_id }))
}

pub(super) async fn list_pending_members(
    service: &MemberServiceImpl,
    request: Request<ListPendingMembersRequest>,
) -> Result<Response<ListPendingMembersResponse>, Status> {
    let tenant = extract_tenant_id(&request, &service.store).await?;
    let body = request.into_inner();
    let group_id = GroupId(crate::proto::parse_ulid(&body.group_id).map_err(|e| {
        RpcError::InvalidArgument {
            field: "group_id",
            reason: e.to_string(),
        }
    })?);

    let (group_tenant, _) = service.store.get_group(group_id).await.map_err(to_status)?;
    if group_tenant != tenant {
        return Err(RpcError::NotFound {
            resource: "group",
            id: format!("{}", group_id.0),
        }
        .into());
    }

    let (members, _next_page) = service
        .store
        .list_pending_members(tenant, group_id, clamp_events_limit(body.limit), None)
        .await
        .map_err(to_status)?;

    let proto_members = members
        .into_iter()
        .map(|m| ProtoPendingMember {
            pending_id: m.pending_id,
            tg_user_id: m.tg_user_id,
            nazgul_pub: Some(crate::proto::master_pub_to_proto(&m.nazgul_pub)),
            rage_pub: Some(mandate_proto::mandate::v1::RagePublicKey {
                value: m.rage_pub.to_vec(),
            }),
            submitted_at_ms: m.submitted_at_ms,
        })
        .collect();

    Ok(Response::new(ListPendingMembersResponse {
        members: proto_members,
        next_page_token: None,
    }))
}

pub(super) async fn get_approved_member_by_tg_user_id(
    service: &MemberServiceImpl,
    request: Request<GetApprovedMemberByTgUserIdRequest>,
) -> Result<Response<GetApprovedMemberByTgUserIdResponse>, Status> {
    let tenant = extract_tenant_id(&request, &service.store).await?;
    let body = request.into_inner();
    let group_id = GroupId(crate::proto::parse_ulid(&body.group_id).map_err(|e| {
        RpcError::InvalidArgument {
            field: "group_id",
            reason: e.to_string(),
        }
    })?);

    // Verify tenant owns the group
    let (group_tenant, _) = service.store.get_group(group_id).await.map_err(to_status)?;
    if group_tenant != tenant {
        return Err(RpcError::NotFound {
            resource: "group",
            id: format!("{}", group_id.0),
        }
        .into());
    }

    let member = service
        .store
        .get_approved_member_by_tg_user_id(tenant, group_id, &body.tg_user_id)
        .await
        .map_err(to_status)?;

    match member {
        Some(m) => Ok(Response::new(GetApprovedMemberByTgUserIdResponse {
            member: Some(ProtoPendingMember {
                pending_id: m.pending_id,
                tg_user_id: m.tg_user_id,
                nazgul_pub: Some(crate::proto::master_pub_to_proto(&m.nazgul_pub)),
                rage_pub: Some(mandate_proto::mandate::v1::RagePublicKey {
                    value: m.rage_pub.to_vec(),
                }),
                submitted_at_ms: m.submitted_at_ms,
            }),
        })),
        None => Err(RpcError::NotFound {
            resource: "approved_member",
            id: body.tg_user_id,
        }
        .into()),
    }
}

pub(super) async fn register_member(
    service: &MemberServiceImpl,
    request: Request<RegisterMemberRequest>,
) -> Result<Response<RegisterMemberResponse>, Status> {
    let tenant = extract_tenant_id(&request, &service.store).await?;
    let body = request.into_inner();

    // Validate invite_code (required)
    if body.invite_code.is_empty() {
        return Err(RpcError::InvalidArgument {
            field: "invite_code",
            reason: "missing".into(),
        }
        .into());
    }

    // Validate nazgul_pub (required)
    let nazgul_pub = body
        .nazgul_pub
        .as_ref()
        .ok_or_else(|| RpcError::InvalidArgument {
            field: "nazgul_pub",
            reason: "missing".into(),
        })?;
    let nazgul_pub =
        crate::proto::nazgul_pub_from_proto(nazgul_pub).map_err(|e| RpcError::InvalidArgument {
            field: "nazgul_pub",
            reason: e.to_string(),
        })?;

    // Validate rage_pub (required)
    let rage_pub = body
        .rage_pub
        .as_ref()
        .ok_or_else(|| RpcError::InvalidArgument {
            field: "rage_pub",
            reason: "missing".into(),
        })?;
    let rage_pub =
        crate::proto::rage_pub_from_proto(rage_pub).map_err(|e| RpcError::InvalidArgument {
            field: "rage_pub",
            reason: e.to_string(),
        })?;

    // Extract optional identity fields
    let display_name = if let Some(identity) = body.identity {
        identity.display_name
    } else {
        None
    };

    // Register via invite code
    let (pending_id, group_id) = service
        .store
        .register_standalone_member(
            tenant,
            &body.invite_code,
            nazgul_pub,
            rage_pub,
            display_name,
        )
        .await
        .map_err(to_status)?;

    Ok(Response::new(RegisterMemberResponse {
        pending_id,
        group_id: group_id.to_string(),
        status: "pending".to_string(),
    }))
}
