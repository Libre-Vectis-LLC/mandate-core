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

        // Determine which fields to include
        let include_fields = if body.include_fields.is_empty() {
            // Default: all fields
            vec![
                "external_id",
                "display_name",
                "organization_id",
                "credential_status",
                "joined_at",
                "status",
                "identity_source",
            ]
        } else {
            // Validate field names
            let valid_fields = [
                "external_id",
                "display_name",
                "organization_id",
                "credential_status",
                "joined_at",
                "status",
                "identity_source",
            ];
            for field in &body.include_fields {
                if !valid_fields.contains(&field.as_str()) {
                    return Err(RpcError::InvalidArgument {
                        field: "include_fields",
                        reason: format!("invalid field name: {}", field),
                    }
                    .into());
                }
            }
            body.include_fields.iter().map(|s| s.as_str()).collect()
        };

        // Format output based on requested format
        let data = match body.format.to_lowercase().as_str() {
            "csv" => {
                // Generate CSV output with field selection and proper escaping
                let mut csv = String::new();

                // Header row
                csv.push_str(
                    &include_fields
                        .iter()
                        .map(|f| csv_escape(f))
                        .collect::<Vec<_>>()
                        .join(","),
                );
                csv.push('\n');

                // Data rows
                for m in &members {
                    let row_values: Vec<String> = include_fields
                        .iter()
                        .map(|field| {
                            let value = match *field {
                                "external_id" => {
                                    m.identity.external_id.as_deref().unwrap_or("").to_string()
                                }
                                "display_name" => {
                                    m.identity.display_name.as_deref().unwrap_or("").to_string()
                                }
                                "organization_id" => m
                                    .identity
                                    .organization_id
                                    .as_deref()
                                    .unwrap_or("")
                                    .to_string(),
                                "credential_status" => m
                                    .identity
                                    .credential_ref
                                    .as_ref()
                                    .map(|c| {
                                        if c.verified_at > 0 {
                                            "verified"
                                        } else {
                                            "unverified"
                                        }
                                    })
                                    .unwrap_or("none")
                                    .to_string(),
                                "joined_at" => m.joined_at_ms.to_string(),
                                "status" => m.status.clone(),
                                "identity_source" => match &m.identity.source {
                                    crate::event::IdentitySource::Telegram => "telegram",
                                    crate::event::IdentitySource::Standalone => "standalone",
                                    crate::event::IdentitySource::Other(s) => s.as_str(),
                                }
                                .to_string(),
                                _ => String::new(),
                            };
                            // Apply CSV escaping and formula injection prevention
                            csv_escape(&sanitize_for_csv(&value))
                        })
                        .collect();

                    csv.push_str(&row_values.join(","));
                    csv.push('\n');
                }
                csv
            }
            "json" => {
                // Generate JSON output with field selection
                let json_members: Vec<serde_json::Value> = members
                    .iter()
                    .map(|m| {
                        let mut obj = serde_json::Map::new();

                        for field in &include_fields {
                            let value: serde_json::Value = match *field {
                                "external_id" => serde_json::Value::String(
                                    m.identity.external_id.clone().unwrap_or_default(),
                                ),
                                "display_name" => serde_json::Value::String(
                                    m.identity.display_name.clone().unwrap_or_default(),
                                ),
                                "organization_id" => serde_json::Value::String(
                                    m.identity.organization_id.clone().unwrap_or_default(),
                                ),
                                "credential_status" => serde_json::Value::String(
                                    m.identity
                                        .credential_ref
                                        .as_ref()
                                        .map(|c| {
                                            if c.verified_at > 0 {
                                                "verified"
                                            } else {
                                                "unverified"
                                            }
                                        })
                                        .unwrap_or("none")
                                        .to_string(),
                                ),
                                "joined_at" => serde_json::Value::Number(serde_json::Number::from(
                                    m.joined_at_ms,
                                )),
                                "status" => serde_json::Value::String(m.status.clone()),
                                "identity_source" => serde_json::Value::String(
                                    match &m.identity.source {
                                        crate::event::IdentitySource::Telegram => "telegram",
                                        crate::event::IdentitySource::Standalone => "standalone",
                                        crate::event::IdentitySource::Other(s) => s.as_str(),
                                    }
                                    .to_string(),
                                ),
                                _ => serde_json::Value::Null,
                            };
                            obj.insert(field.to_string(), value);
                        }

                        serde_json::Value::Object(obj)
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

/// Sanitizes a string to prevent Excel Formula Injection (CSV Injection).
///
/// Prepends a single quote if the string starts with =, +, -, or @
/// to prevent Excel from interpreting it as a formula.
///
/// # Arguments
///
/// * `input` - The string to sanitize
///
/// # Returns
///
/// Sanitized string safe for CSV export
fn sanitize_for_csv(input: &str) -> String {
    if input.starts_with('=')
        || input.starts_with('+')
        || input.starts_with('-')
        || input.starts_with('@')
    {
        format!("'{}", input)
    } else {
        input.to_string()
    }
}

/// Escapes a CSV field value according to RFC 4180.
///
/// Fields containing commas, double-quotes, or newlines are enclosed in double-quotes.
/// Double-quotes within the field are escaped by doubling them.
///
/// # Arguments
///
/// * `field` - The field value to escape
///
/// # Returns
///
/// Properly escaped CSV field value
fn csv_escape(field: &str) -> String {
    // Check if field needs quoting (contains comma, quote, or newline)
    if field.contains(',') || field.contains('"') || field.contains('\n') || field.contains('\r') {
        // Escape double-quotes by doubling them
        let escaped = field.replace('"', "\"\"");
        format!("\"{}\"", escaped)
    } else {
        field.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_for_csv_prevents_formula_injection() {
        assert_eq!(sanitize_for_csv("=SUM(A1:A10)"), "'=SUM(A1:A10)");
        assert_eq!(sanitize_for_csv("+1+1"), "'+1+1");
        assert_eq!(sanitize_for_csv("-5"), "'-5");
        assert_eq!(sanitize_for_csv("@IMPORT"), "'@IMPORT");
        assert_eq!(sanitize_for_csv("normal text"), "normal text");
    }

    #[test]
    fn test_csv_escape_handles_special_characters() {
        // No escaping needed for plain text
        assert_eq!(csv_escape("plain"), "plain");

        // Fields with commas need quoting
        assert_eq!(csv_escape("hello,world"), "\"hello,world\"");

        // Fields with quotes need escaping and quoting
        assert_eq!(csv_escape("say \"hello\""), "\"say \"\"hello\"\"\"");

        // Fields with newlines need quoting
        assert_eq!(csv_escape("line1\nline2"), "\"line1\nline2\"");

        // Fields with carriage returns need quoting
        assert_eq!(csv_escape("line1\rline2"), "\"line1\rline2\"");

        // Complex case: comma + quote + newline
        assert_eq!(
            csv_escape("value, \"quoted\", \nand newline"),
            "\"value, \"\"quoted\"\", \nand newline\""
        );
    }

    #[test]
    fn test_csv_escape_empty_string() {
        assert_eq!(csv_escape(""), "");
    }

    #[test]
    fn test_sanitize_for_csv_combined_with_escape() {
        // Test that both functions work together correctly
        let malicious = "=SUM(A1,A2)";
        let sanitized = sanitize_for_csv(malicious);
        let escaped = csv_escape(&sanitized);

        // Should be: '=SUM(A1,A2) → "'=SUM(A1,A2)"
        assert_eq!(escaped, "\"'=SUM(A1,A2)\"");
    }
}
