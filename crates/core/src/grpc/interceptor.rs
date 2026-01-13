use crate::ids::{BotSecret, TenantId, TenantToken};
use crate::proto::{API_TOKEN_METADATA_KEY, BOT_SECRET_METADATA_KEY, TENANT_ID_METADATA_KEY};
use crate::rpc::RpcError;
use sha3::{Digest, Sha3_256};
use subtle::ConstantTimeEq;
use tonic::{Request, Status};
use ulid::Ulid;

/// Enforce presence of `x-api-token` and attach a `TenantToken` to request extensions.
///
/// The token is treated as an opaque secret (rotatable). Core must not interpret it as a tenant ID.
///
/// Note: `result_large_err` is acceptable here as `tonic::Status` is the required error type
/// for gRPC interceptors. Boxing would break compatibility with tonic's interceptor API.
#[allow(clippy::result_large_err)]
pub fn require_api_token(mut req: Request<()>) -> Result<Request<()>, Status> {
    let token = {
        let token = req
            .metadata()
            .get(API_TOKEN_METADATA_KEY)
            .ok_or_else(|| RpcError::Unauthenticated {
                credential: "api_token",
                reason: "missing".into(),
            })?
            .to_str()
            .map_err(|_| RpcError::Unauthenticated {
                credential: "api_token",
                reason: "bad encoding".into(),
            })?;

        if token.is_empty() {
            return Err(RpcError::Unauthenticated {
                credential: "api_token",
                reason: "empty".into(),
            }
            .into());
        }

        TenantToken::from(token)
    };

    req.extensions_mut().insert(token);
    Ok(req)
}

/// Extract bot secret from request metadata.
///
/// Note: `result_large_err` is acceptable here as `tonic::Status` is the required error type
/// for gRPC interceptors. Boxing would break compatibility with tonic's interceptor API.
#[allow(clippy::result_large_err)]
fn extract_bot_secret(req: &Request<()>) -> Result<BotSecret, Status> {
    let secret = req
        .metadata()
        .get(BOT_SECRET_METADATA_KEY)
        .ok_or_else(|| RpcError::Unauthenticated {
            credential: "bot_secret",
            reason: "missing".into(),
        })?
        .to_str()
        .map_err(|_| RpcError::Unauthenticated {
            credential: "bot_secret",
            reason: "bad encoding".into(),
        })?;

    if secret.is_empty() {
        return Err(RpcError::Unauthenticated {
            credential: "bot_secret",
            reason: "empty".into(),
        }
        .into());
    }

    Ok(BotSecret::from(secret))
}

/// Extract tenant ID from request metadata.
///
/// Note: `result_large_err` is acceptable here as `tonic::Status` is the required error type
/// for gRPC interceptors. Boxing would break compatibility with tonic's interceptor API.
#[allow(clippy::result_large_err)]
fn extract_tenant_id(req: &Request<()>) -> Result<TenantId, Status> {
    let tenant_str = req
        .metadata()
        .get(TENANT_ID_METADATA_KEY)
        .ok_or_else(|| RpcError::Unauthenticated {
            credential: "tenant_id",
            reason: "missing".into(),
        })?
        .to_str()
        .map_err(|_| RpcError::Unauthenticated {
            credential: "tenant_id",
            reason: "bad encoding".into(),
        })?;

    if tenant_str.is_empty() {
        return Err(RpcError::Unauthenticated {
            credential: "tenant_id",
            reason: "empty".into(),
        }
        .into());
    }

    let ulid = Ulid::from_string(tenant_str).map_err(|_| RpcError::InvalidArgument {
        field: "tenant_id",
        reason: "invalid ULID format".into(),
    })?;

    Ok(TenantId(ulid))
}

/// Enforce presence of `x-bot-secret` and attach a `BotSecret` to request extensions.
/// If `x-tenant-id` is present, also attaches `TenantId` to extensions.
///
/// **Warning:** This function only checks presence, not correctness of the bot secret.
/// Use `make_bot_secret_interceptor` for production deployments.
///
/// Note: `result_large_err` is acceptable here as `tonic::Status` is the required error type
/// for gRPC interceptors. Boxing would break compatibility with tonic's interceptor API.
#[allow(clippy::result_large_err)]
pub fn require_bot_secret(mut req: Request<()>) -> Result<Request<()>, Status> {
    let secret = extract_bot_secret(&req)?;
    req.extensions_mut().insert(secret);

    // Tenant context is optional at interceptor level - individual methods
    // that require it should validate presence in their implementation.
    if let Ok(tenant_id) = extract_tenant_id(&req) {
        req.extensions_mut().insert(tenant_id);
    }
    Ok(req)
}

/// Hash a secret using SHA3-256 to normalize length before constant-time comparison.
/// This prevents timing attacks based on length differences.
fn hash_for_comparison(secret: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(secret);
    hasher.finalize().into()
}

/// Create an interceptor that validates the bot secret using constant-time comparison
/// and extracts tenant context from request metadata if present.
///
/// This is the secure version that should be used in production.
/// Bot secret is required; tenant ID is optional at the interceptor level.
/// Individual service methods that require tenant context must validate its presence.
pub fn make_bot_secret_interceptor(
    expected: BotSecret,
) -> impl Fn(Request<()>) -> Result<Request<()>, Status> + Clone + Send + Sync + 'static {
    move |mut req: Request<()>| {
        let provided = extract_bot_secret(&req)?;

        // Hash both secrets to normalize length and prevent timing attacks
        let expected_hash = hash_for_comparison(expected.as_bytes());
        let provided_hash = hash_for_comparison(provided.as_bytes());

        // Constant-time comparison on fixed-length hashes
        if !bool::from(expected_hash.ct_eq(&provided_hash)) {
            return Err(RpcError::Unauthenticated {
                credential: "bot_secret",
                reason: "invalid".into(),
            }
            .into());
        }

        req.extensions_mut().insert(provided);

        // Tenant context is optional at interceptor level - individual methods
        // that require it (e.g., GroupService) should validate presence.
        if let Ok(tenant_id) = extract_tenant_id(&req) {
            req.extensions_mut().insert(tenant_id);
        }
        Ok(req)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::TEST_TENANT_ID_STR;
    use tonic::Code;

    #[test]
    fn rejects_missing_token() {
        let req = Request::new(());
        let err = require_api_token(req).expect_err("missing token must fail");
        assert_eq!(err.code(), Code::Unauthenticated);
    }

    #[test]
    fn rejects_empty_token() {
        let mut req = Request::new(());
        req.metadata_mut()
            .insert(API_TOKEN_METADATA_KEY, "".parse().expect("metadata value"));
        let err = require_api_token(req).expect_err("bad token must fail");
        assert_eq!(err.code(), Code::Unauthenticated);
    }

    #[test]
    fn stores_tenant_token_in_extensions() {
        let mut req = Request::new(());
        req.metadata_mut().insert(
            API_TOKEN_METADATA_KEY,
            "token-123".parse().expect("metadata value"),
        );

        let req = require_api_token(req).expect("valid token");
        let stored = req
            .extensions()
            .get::<TenantToken>()
            .cloned()
            .expect("tenant token extension");
        assert_eq!(stored.as_str(), "token-123");
    }

    #[test]
    fn rejects_missing_bot_secret() {
        let req = Request::new(());
        let err = require_bot_secret(req).expect_err("missing secret must fail");
        assert_eq!(err.code(), Code::Unauthenticated);
    }

    #[test]
    fn stores_bot_secret_without_tenant() {
        // Tenant is optional for admin operations
        let mut req = Request::new(());
        req.metadata_mut().insert(
            BOT_SECRET_METADATA_KEY,
            "secret-abc".parse().expect("metadata value"),
        );

        let req = require_bot_secret(req).expect("valid secret");
        let stored_secret = req
            .extensions()
            .get::<BotSecret>()
            .cloned()
            .expect("bot secret extension");
        assert_eq!(stored_secret.as_str(), "secret-abc");
        assert!(req.extensions().get::<TenantId>().is_none());
    }

    #[test]
    fn stores_bot_secret_and_tenant_in_extensions() {
        let mut req = Request::new(());
        req.metadata_mut().insert(
            BOT_SECRET_METADATA_KEY,
            "secret-abc".parse().expect("metadata value"),
        );
        req.metadata_mut().insert(
            TENANT_ID_METADATA_KEY,
            TEST_TENANT_ID_STR.parse().expect("metadata value"),
        );

        let req = require_bot_secret(req).expect("valid secret and tenant");
        let stored_secret = req
            .extensions()
            .get::<BotSecret>()
            .cloned()
            .expect("bot secret extension");
        assert_eq!(stored_secret.as_str(), "secret-abc");

        let stored_tenant = req
            .extensions()
            .get::<TenantId>()
            .cloned()
            .expect("tenant id extension");
        assert_eq!(stored_tenant.0.to_string(), TEST_TENANT_ID_STR);
    }

    #[test]
    fn validated_interceptor_accepts_correct_secret_and_tenant() {
        let expected = BotSecret::from("correct-secret");
        let interceptor = make_bot_secret_interceptor(expected);

        let mut req = Request::new(());
        req.metadata_mut().insert(
            BOT_SECRET_METADATA_KEY,
            "correct-secret".parse().expect("metadata value"),
        );
        req.metadata_mut().insert(
            TENANT_ID_METADATA_KEY,
            TEST_TENANT_ID_STR.parse().expect("metadata value"),
        );

        let req = interceptor(req).expect("correct secret and tenant must pass");

        let stored_secret = req
            .extensions()
            .get::<BotSecret>()
            .cloned()
            .expect("bot secret extension");
        assert_eq!(stored_secret.as_str(), "correct-secret");

        let stored_tenant = req
            .extensions()
            .get::<TenantId>()
            .cloned()
            .expect("tenant id extension");
        assert_eq!(stored_tenant.0.to_string(), TEST_TENANT_ID_STR);
    }

    #[test]
    fn validated_interceptor_rejects_wrong_secret() {
        let expected = BotSecret::from("correct-secret");
        let interceptor = make_bot_secret_interceptor(expected);

        let mut req = Request::new(());
        req.metadata_mut().insert(
            BOT_SECRET_METADATA_KEY,
            "wrong-secret".parse().expect("metadata value"),
        );
        req.metadata_mut().insert(
            TENANT_ID_METADATA_KEY,
            TEST_TENANT_ID_STR.parse().expect("metadata value"),
        );

        let err = interceptor(req).expect_err("wrong secret must fail");
        assert_eq!(err.code(), Code::Unauthenticated);
    }

    #[test]
    fn validated_interceptor_rejects_missing_secret() {
        let expected = BotSecret::from("correct-secret");
        let interceptor = make_bot_secret_interceptor(expected);

        let req = Request::new(());
        let err = interceptor(req).expect_err("missing secret must fail");
        assert_eq!(err.code(), Code::Unauthenticated);
    }

    #[test]
    fn validated_interceptor_accepts_missing_tenant() {
        // Tenant is optional at interceptor level for admin operations
        let expected = BotSecret::from("correct-secret");
        let interceptor = make_bot_secret_interceptor(expected);

        let mut req = Request::new(());
        req.metadata_mut().insert(
            BOT_SECRET_METADATA_KEY,
            "correct-secret".parse().expect("metadata value"),
        );
        // No tenant ID header

        let req = interceptor(req).expect("missing tenant should be allowed");
        assert!(req.extensions().get::<TenantId>().is_none());
    }

    #[test]
    fn validated_interceptor_ignores_invalid_tenant_format() {
        // Invalid tenant format is treated as "no tenant" rather than error
        let expected = BotSecret::from("correct-secret");
        let interceptor = make_bot_secret_interceptor(expected);

        let mut req = Request::new(());
        req.metadata_mut().insert(
            BOT_SECRET_METADATA_KEY,
            "correct-secret".parse().expect("metadata value"),
        );
        req.metadata_mut().insert(
            TENANT_ID_METADATA_KEY,
            "not-a-valid-ulid".parse().expect("metadata value"),
        );

        // Invalid tenant format is ignored, request proceeds without tenant in extensions
        let req = interceptor(req).expect("invalid tenant format should be ignored");
        assert!(req.extensions().get::<TenantId>().is_none());
    }
}
