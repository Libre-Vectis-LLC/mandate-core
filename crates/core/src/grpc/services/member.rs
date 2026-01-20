//! MemberService gRPC implementation.

use crate::ids::GroupId;
use crate::rpc::RpcError;
use crate::storage::facade::StorageFacade;
use mandate_proto::mandate::v1::{
    member_service_server::MemberService, ExportMembersRequest, ExportMembersResponse,
    GetApprovedMemberByTgUserIdRequest, GetApprovedMemberByTgUserIdResponse, ListMembersRequest,
    ListMembersResponse, ListPendingMembersRequest, ListPendingMembersResponse,
    PendingMember as ProtoPendingMember, RegisterMemberRequest, RegisterMemberResponse,
    SubmitPendingMemberRequest, SubmitPendingMemberResponse,
};
use tonic::{Request, Response, Status};

use super::{clamp_events_limit, extract_tenant_id, to_status};

#[derive(Clone)]
pub struct MemberServiceImpl {
    store: StorageFacade,
}

impl MemberServiceImpl {
    pub fn new(store: StorageFacade) -> Self {
        Self { store }
    }
}

#[tonic::async_trait]
impl MemberService for MemberServiceImpl {
    async fn submit_pending_member(
        &self,
        request: Request<SubmitPendingMemberRequest>,
    ) -> Result<Response<SubmitPendingMemberResponse>, Status> {
        let body = request.into_inner();
        let group_id = GroupId(crate::proto::parse_ulid(&body.group_id).map_err(|e| {
            RpcError::InvalidArgument {
                field: "group_id",
                reason: e.to_string(),
            }
        })?);

        let (tenant, _) = self.store.get_group(group_id).await.map_err(to_status)?;

        let nazgul_pub = body
            .nazgul_pub
            .as_ref()
            .ok_or_else(|| RpcError::InvalidArgument {
                field: "nazgul_pub",
                reason: "missing".into(),
            })?;
        let nazgul_pub = crate::proto::nazgul_pub_from_proto(nazgul_pub).map_err(|e| {
            RpcError::InvalidArgument {
                field: "nazgul_pub",
                reason: e.to_string(),
            }
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

        let pending_id = self
            .store
            .submit_pending_member(tenant, group_id, &body.tg_user_id, nazgul_pub, rage_pub)
            .await
            .map_err(to_status)?;

        Ok(Response::new(SubmitPendingMemberResponse { pending_id }))
    }

    async fn list_pending_members(
        &self,
        request: Request<ListPendingMembersRequest>,
    ) -> Result<Response<ListPendingMembersResponse>, Status> {
        let tenant = extract_tenant_id(&request, &self.store).await?;
        let body = request.into_inner();
        let group_id = GroupId(crate::proto::parse_ulid(&body.group_id).map_err(|e| {
            RpcError::InvalidArgument {
                field: "group_id",
                reason: e.to_string(),
            }
        })?);

        let (group_tenant, _) = self.store.get_group(group_id).await.map_err(to_status)?;
        if group_tenant != tenant {
            return Err(RpcError::NotFound {
                resource: "group",
                id: format!("{}", group_id.0),
            }
            .into());
        }

        let (members, _next_page) = self
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

    async fn get_approved_member_by_tg_user_id(
        &self,
        request: Request<GetApprovedMemberByTgUserIdRequest>,
    ) -> Result<Response<GetApprovedMemberByTgUserIdResponse>, Status> {
        let tenant = extract_tenant_id(&request, &self.store).await?;
        let body = request.into_inner();
        let group_id = GroupId(crate::proto::parse_ulid(&body.group_id).map_err(|e| {
            RpcError::InvalidArgument {
                field: "group_id",
                reason: e.to_string(),
            }
        })?);

        // Verify tenant owns the group
        let (group_tenant, _) = self.store.get_group(group_id).await.map_err(to_status)?;
        if group_tenant != tenant {
            return Err(RpcError::NotFound {
                resource: "group",
                id: format!("{}", group_id.0),
            }
            .into());
        }

        let member = self
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

    async fn register_member(
        &self,
        request: Request<RegisterMemberRequest>,
    ) -> Result<Response<RegisterMemberResponse>, Status> {
        let tenant = extract_tenant_id(&request, &self.store).await?;
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
        let nazgul_pub = crate::proto::nazgul_pub_from_proto(nazgul_pub).map_err(|e| {
            RpcError::InvalidArgument {
                field: "nazgul_pub",
                reason: e.to_string(),
            }
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
        let (display_name, organization_id) = if let Some(identity) = body.identity {
            (identity.display_name, identity.organization_id)
        } else {
            (None, None)
        };

        // Register via invite code
        let (pending_id, group_id) = self
            .store
            .register_standalone_member(
                tenant,
                &body.invite_code,
                nazgul_pub,
                rage_pub,
                display_name,
                organization_id,
            )
            .await
            .map_err(to_status)?;

        Ok(Response::new(RegisterMemberResponse {
            pending_id,
            group_id: group_id.to_string(),
            status: "pending".to_string(),
        }))
    }

    async fn list_members(
        &self,
        request: Request<ListMembersRequest>,
    ) -> Result<Response<ListMembersResponse>, Status> {
        let tenant = extract_tenant_id(&request, &self.store).await?;
        let body = request.into_inner();
        let group_id = GroupId(crate::proto::parse_ulid(&body.group_id).map_err(|e| {
            RpcError::InvalidArgument {
                field: "group_id",
                reason: e.to_string(),
            }
        })?);

        // Verify tenant owns the group
        let (group_tenant, _) = self.store.get_group(group_id).await.map_err(to_status)?;
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
        let (members, next_page, total_count) = self
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
                        crate::event::IdentitySource::Telegram => {
                            ProtoIdentitySource::Telegram.into()
                        }
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

    async fn export_members(
        &self,
        request: Request<ExportMembersRequest>,
    ) -> Result<Response<ExportMembersResponse>, Status> {
        let tenant = extract_tenant_id(&request, &self.store).await?;
        let body = request.into_inner();
        let group_id = GroupId(crate::proto::parse_ulid(&body.group_id).map_err(|e| {
            RpcError::InvalidArgument {
                field: "group_id",
                reason: e.to_string(),
            }
        })?);

        // Verify tenant owns the group
        let (group_tenant, _) = self.store.get_group(group_id).await.map_err(to_status)?;
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

        // Query all members (no pagination for export)
        let (members, _, member_count) = self
            .store
            .list_all_members(
                tenant,
                group_id,
                10000, // Large limit for export
                None,
                filter_source,
                filter_status,
            )
            .await
            .map_err(to_status)?;

        // Format output based on requested format
        let data = match body.format.to_lowercase().as_str() {
            "csv" => {
                // Generate CSV output
                let mut csv = String::from("nazgul_pub,external_id,display_name,organization_id,status,joined_at,identity_source\n");
                for m in &members {
                    csv.push_str(&format!(
                        "{},{},{},{},{},{},{}\n",
                        bs58::encode(&m.nazgul_pub.0).into_string(),
                        m.identity.external_id.as_deref().unwrap_or(""),
                        m.identity.display_name.as_deref().unwrap_or(""),
                        m.identity.organization_id.as_deref().unwrap_or(""),
                        m.status,
                        m.joined_at_ms,
                        match &m.identity.source {
                            crate::event::IdentitySource::Telegram => "telegram",
                            crate::event::IdentitySource::Standalone => "standalone",
                            crate::event::IdentitySource::Other(s) => s.as_str(),
                        }
                    ));
                }
                csv
            }
            "json" => {
                // Generate JSON output
                let json_members: Vec<serde_json::Value> = members
                    .iter()
                    .map(|m| {
                        serde_json::json!({
                            "nazgul_pub": bs58::encode(&m.nazgul_pub.0).into_string(),
                            "external_id": m.identity.external_id.as_deref().unwrap_or(""),
                            "display_name": m.identity.display_name.as_deref().unwrap_or(""),
                            "organization_id": m.identity.organization_id.as_deref().unwrap_or(""),
                            "status": m.status,
                            "joined_at": m.joined_at_ms,
                            "identity_source": match &m.identity.source {
                                crate::event::IdentitySource::Telegram => "telegram",
                                crate::event::IdentitySource::Standalone => "standalone",
                                crate::event::IdentitySource::Other(s) => s.as_str(),
                            },
                        })
                    })
                    .collect();
                serde_json::to_string_pretty(&json_members).unwrap_or_default()
            }
            _ => {
                return Err(RpcError::InvalidArgument {
                    field: "format",
                    reason: format!("unsupported format: {}", body.format),
                }
                .into());
            }
        };

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        Ok(Response::new(ExportMembersResponse {
            data,
            member_count,
            exported_at: now_ms,
        }))
    }
}
