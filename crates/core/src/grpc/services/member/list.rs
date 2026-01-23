//! List members operation.

use crate::ids::GroupId;
use crate::rpc::RpcError;
use mandate_proto::mandate::v1::{ListMembersRequest, ListMembersResponse};
use tonic::{Request, Response, Status};

use super::super::{clamp_events_limit, extract_tenant_id, to_status};
use super::MemberServiceImpl;

pub(super) async fn list_members(
    service: &MemberServiceImpl,
    request: Request<ListMembersRequest>,
) -> Result<Response<ListMembersResponse>, Status> {
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

    // Extract filter parameters
    let filter_source = body.filter_source.and_then(|s_int| {
        use mandate_proto::mandate::v1::IdentitySource as ProtoIdentitySource;
        ProtoIdentitySource::try_from(s_int)
            .ok()
            .and_then(|s| match s {
                ProtoIdentitySource::Unknown => None,
                ProtoIdentitySource::Telegram => Some("telegram"),
                ProtoIdentitySource::Standalone => Some("standalone"),
                ProtoIdentitySource::Other => None,
            })
    });

    let filter_status = body.filter_status.as_deref();

    // Query members
    let (members, next_page, total_count) = service
        .store
        .list_all_members(
            tenant,
            group_id,
            clamp_events_limit(body.limit),
            body.page_token.as_ref().and_then(|t| {
                if t.value.is_empty() {
                    None
                } else {
                    Some(t.value.clone())
                }
            }),
            filter_source,
            filter_status,
        )
        .await
        .map_err(to_status)?;

    // Convert to proto messages
    use mandate_proto::mandate::v1::{
        IdentitySource as ProtoIdentitySource, MemberInfo as ProtoMemberInfo,
    };

    let proto_members = members
        .into_iter()
        .map(|m| ProtoMemberInfo {
            nazgul_pub: m.nazgul_pub.0.to_vec(),
            identity: Some(mandate_proto::mandate::v1::MemberIdentity {
                external_id: m.identity.external_id,
                display_name: m.identity.display_name,
                organization_id: m.identity.organization_id,
                credential_ref: m.identity.credential_ref.map(|c| {
                    mandate_proto::mandate::v1::CredentialRef {
                        credential_id: c.credential_id,
                        credential_type: c.credential_type,
                        verified_at: c.verified_at,
                    }
                }),
                source: match m.identity.source {
                    crate::event::IdentitySource::Telegram => ProtoIdentitySource::Telegram.into(),
                    crate::event::IdentitySource::Standalone => {
                        ProtoIdentitySource::Standalone.into()
                    }
                    crate::event::IdentitySource::Other(_) => ProtoIdentitySource::Other.into(),
                },
            }),
            status: m.status,
            joined_at: m.joined_at_ms as u64,
        })
        .collect();

    Ok(Response::new(ListMembersResponse {
        members: proto_members,
        next_page_token: next_page.map(|value| mandate_proto::mandate::v1::PageToken { value }),
        total_count,
    }))
}
