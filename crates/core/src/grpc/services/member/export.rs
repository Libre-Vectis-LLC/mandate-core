//! Export members operation and CSV utilities.

use crate::ids::GroupId;
use crate::rpc::RpcError;
use mandate_proto::mandate::v1::{ExportMembersRequest, ExportMembersResponse};
use tonic::{Request, Response, Status};

use super::super::{extract_tenant_id, to_status};
use super::MemberServiceImpl;

pub(super) async fn export_members(
    service: &MemberServiceImpl,
    request: Request<ExportMembersRequest>,
) -> Result<Response<ExportMembersResponse>, Status> {
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

    // Query all members (no pagination for export)
    let (members, _, member_count) = service
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
                            "joined_at" => {
                                serde_json::Value::Number(serde_json::Number::from(m.joined_at_ms))
                            }
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
pub(crate) fn sanitize_for_csv(input: &str) -> String {
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
pub(crate) fn csv_escape(field: &str) -> String {
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
