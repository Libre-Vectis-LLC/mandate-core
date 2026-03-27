use crate::grpc::services::tests::create_test_org;
use crate::grpc::wiring::CoreServices;
use crate::ids::TenantId;
use mandate_proto::mandate::v1::invite_service_server::InviteService;
use mandate_proto::mandate::v1::{
    CreateInviteCodeRequest, ListInviteCodesRequest, RegisterWithInviteCodeRequest,
    RevokeInviteCodeRequest, ValidateInviteCodeRequest,
};
use tonic::{Code, Request};

fn test_tenant() -> TenantId {
    TenantId(ulid::Ulid::new())
}

fn make_request_with_tenant<T>(tenant: TenantId, body: T) -> Request<T> {
    let mut req = Request::new(body);
    req.extensions_mut().insert(tenant);
    req
}

#[tokio::test]
async fn test_create_invite_code_basic() {
    let services = CoreServices::new_in_memory().expect("core services");
    let tenant = test_tenant();
    let org_id = create_test_org(&services, tenant).await;

    let req = make_request_with_tenant(
        tenant,
        CreateInviteCodeRequest {
            org_id: org_id.to_string(),
            expires_at: None,
            max_uses: 5,
            metadata: Some(r#"{"role":"contributor"}"#.to_string()),
        },
    );

    let resp = services
        .invite
        .create_invite_code(req)
        .await
        .expect("create invite code");
    let body = resp.into_inner();

    assert_eq!(body.code.len(), 20, "code should be 20 characters");
    assert!(
        !body.invite_url.is_empty(),
        "invite_url should not be empty"
    );
}

#[tokio::test]
async fn test_create_invite_code_validation() {
    let services = CoreServices::new_in_memory().expect("core services");
    let tenant = test_tenant();

    // Missing org_id
    let req = make_request_with_tenant(
        tenant,
        CreateInviteCodeRequest {
            org_id: String::new(),
            expires_at: None,
            max_uses: 5,
            metadata: None,
        },
    );
    let err = services
        .invite
        .create_invite_code(req)
        .await
        .expect_err("missing org_id");
    assert_eq!(err.code(), Code::InvalidArgument);

    // max_uses = 0
    let org_id = create_test_org(&services, tenant).await;
    let req = make_request_with_tenant(
        tenant,
        CreateInviteCodeRequest {
            org_id: org_id.to_string(),
            expires_at: None,
            max_uses: 0,
            metadata: None,
        },
    );
    let err = services
        .invite
        .create_invite_code(req)
        .await
        .expect_err("max_uses=0");
    assert_eq!(err.code(), Code::InvalidArgument);

    // expires_at in the past
    let req = make_request_with_tenant(
        tenant,
        CreateInviteCodeRequest {
            org_id: org_id.to_string(),
            expires_at: Some(1), // epoch + 1ms
            max_uses: 1,
            metadata: None,
        },
    );
    let err = services
        .invite
        .create_invite_code(req)
        .await
        .expect_err("expires_at in past");
    assert_eq!(err.code(), Code::InvalidArgument);
}

#[tokio::test]
async fn test_list_invite_codes() {
    let services = CoreServices::new_in_memory().expect("core services");
    let tenant = test_tenant();
    let org_id = create_test_org(&services, tenant).await;

    // Create 3 codes
    for _ in 0..3 {
        let req = make_request_with_tenant(
            tenant,
            CreateInviteCodeRequest {
                org_id: org_id.to_string(),
                expires_at: None,
                max_uses: 10,
                metadata: None,
            },
        );
        services
            .invite
            .create_invite_code(req)
            .await
            .expect("create");
    }

    let req = make_request_with_tenant(
        tenant,
        ListInviteCodesRequest {
            org_id: org_id.to_string(),
            limit: 10,
            page_token: None,
        },
    );
    let resp = services
        .invite
        .list_invite_codes(req)
        .await
        .expect("list invite codes");
    assert_eq!(resp.into_inner().codes.len(), 3);
}

#[tokio::test]
async fn test_validate_invite_code_valid() {
    let services = CoreServices::new_in_memory().expect("core services");
    let tenant = test_tenant();
    let org_id = create_test_org(&services, tenant).await;

    let create_req = make_request_with_tenant(
        tenant,
        CreateInviteCodeRequest {
            org_id: org_id.to_string(),
            expires_at: None,
            max_uses: 5,
            metadata: Some("test-meta".to_string()),
        },
    );
    let code = services
        .invite
        .create_invite_code(create_req)
        .await
        .expect("create")
        .into_inner()
        .code;

    let validate_req =
        make_request_with_tenant(tenant, ValidateInviteCodeRequest { code: code.clone() });
    let resp = services
        .invite
        .validate_invite_code(validate_req)
        .await
        .expect("validate")
        .into_inner();

    assert!(resp.valid, "code should be valid");
    assert_eq!(resp.org_id.unwrap(), org_id.to_string());
    assert_eq!(resp.metadata.unwrap(), "test-meta");
}

#[tokio::test]
async fn test_validate_invite_code_not_found() {
    let services = CoreServices::new_in_memory().expect("core services");
    let tenant = test_tenant();

    let req = make_request_with_tenant(
        tenant,
        ValidateInviteCodeRequest {
            code: "nonexistent-code-1234".to_string(),
        },
    );
    let resp = services
        .invite
        .validate_invite_code(req)
        .await
        .expect("validate should return response, not error")
        .into_inner();

    assert!(!resp.valid, "nonexistent code should be invalid");
    assert_eq!(resp.error_reason.unwrap(), "not_found");
}

#[tokio::test]
async fn test_revoke_invite_code() {
    let services = CoreServices::new_in_memory().expect("core services");
    let tenant = test_tenant();
    let org_id = create_test_org(&services, tenant).await;

    let code = services
        .invite
        .create_invite_code(make_request_with_tenant(
            tenant,
            CreateInviteCodeRequest {
                org_id: org_id.to_string(),
                expires_at: None,
                max_uses: 5,
                metadata: None,
            },
        ))
        .await
        .expect("create")
        .into_inner()
        .code;

    // Revoke
    let revoke_req =
        make_request_with_tenant(tenant, RevokeInviteCodeRequest { code: code.clone() });
    let resp = services
        .invite
        .revoke_invite_code(revoke_req)
        .await
        .expect("revoke");
    assert!(resp.into_inner().success);

    // Validate should now show invalid
    let validate_req =
        make_request_with_tenant(tenant, ValidateInviteCodeRequest { code: code.clone() });
    let resp = services
        .invite
        .validate_invite_code(validate_req)
        .await
        .expect("validate after revoke")
        .into_inner();
    assert!(!resp.valid);
}

#[tokio::test]
async fn test_register_with_invite_code() {
    let services = CoreServices::new_in_memory().expect("core services");
    let tenant = test_tenant();
    let org_id = create_test_org(&services, tenant).await;

    let code = services
        .invite
        .create_invite_code(make_request_with_tenant(
            tenant,
            CreateInviteCodeRequest {
                org_id: org_id.to_string(),
                expires_at: None,
                max_uses: 2,
                metadata: None,
            },
        ))
        .await
        .expect("create")
        .into_inner()
        .code;

    // Register first member
    let register_req = make_request_with_tenant(
        tenant,
        RegisterWithInviteCodeRequest {
            invite_code: code.clone(),
            display_name: Some("Alice".to_string()),
        },
    );
    let resp = services
        .invite
        .register_with_invite_code(register_req)
        .await
        .expect("register first")
        .into_inner();

    assert!(!resp.member_id.is_empty(), "member_id should be set");
    assert_eq!(resp.org_id, org_id.to_string());
    assert_eq!(resp.status, "pending");

    // Register second member
    let register_req2 = make_request_with_tenant(
        tenant,
        RegisterWithInviteCodeRequest {
            invite_code: code.clone(),
            display_name: Some("Bob".to_string()),
        },
    );
    services
        .invite
        .register_with_invite_code(register_req2)
        .await
        .expect("register second");

    // Third registration should fail (max_uses=2)
    let register_req3 = make_request_with_tenant(
        tenant,
        RegisterWithInviteCodeRequest {
            invite_code: code.clone(),
            display_name: Some("Charlie".to_string()),
        },
    );
    let err = services
        .invite
        .register_with_invite_code(register_req3)
        .await
        .expect_err("exhausted");
    assert_eq!(err.code(), Code::NotFound); // Unified NOT_FOUND
}

#[tokio::test]
async fn test_rate_limit_enforcement() {
    use crate::grpc::services::invite::InviteRateLimitConfig;

    let services = CoreServices::new_in_memory().expect("core services");
    let tenant = test_tenant();
    let org_id = create_test_org(&services, tenant).await;

    // Create service with low rate limit for testing
    let invite_svc = crate::grpc::services::InviteServiceImpl::with_rate_limit(
        services.invite.store.clone(),
        InviteRateLimitConfig {
            capacity: 3,
            window_ms: 60_000,
        },
    );

    let code = services
        .invite
        .create_invite_code(make_request_with_tenant(
            tenant,
            CreateInviteCodeRequest {
                org_id: org_id.to_string(),
                expires_at: None,
                max_uses: 100,
                metadata: None,
            },
        ))
        .await
        .expect("create")
        .into_inner()
        .code;

    // 3 validations should succeed
    for _ in 0..3 {
        let req =
            make_request_with_tenant(tenant, ValidateInviteCodeRequest { code: code.clone() });
        invite_svc
            .validate_invite_code(req)
            .await
            .expect("within limit");
    }

    // 4th should fail
    let req = make_request_with_tenant(tenant, ValidateInviteCodeRequest { code: code.clone() });
    let err = invite_svc
        .validate_invite_code(req)
        .await
        .expect_err("over rate limit");
    assert_eq!(err.code(), Code::ResourceExhausted);
}
