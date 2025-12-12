use crate::ids::TenantId;
use crate::proto::API_TOKEN_METADATA_KEY;
use crate::rpc::RpcError;
use tonic::{Request, Status};

/// Enforce presence of `x-api-token` and attach a parsed `TenantId` to request extensions.
///
/// Current placeholder behavior treats the token value as a ULID string for the tenant.
#[allow(clippy::result_large_err)]
pub fn require_api_token(mut req: Request<()>) -> Result<Request<()>, Status> {
    let token = req
        .metadata()
        .get(API_TOKEN_METADATA_KEY)
        .ok_or_else(|| RpcError::Unauthenticated("missing api token".into()))?
        .to_str()
        .map_err(|_| RpcError::Unauthenticated("bad token".into()))?;

    let ulid = ulid::Ulid::from_string(token)
        .map_err(|_| RpcError::Unauthenticated("invalid token ulid".into()))?;

    req.extensions_mut().insert(TenantId(ulid));
    Ok(req)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tonic::Code;

    #[test]
    fn rejects_missing_token() {
        let req = Request::new(());
        let err = require_api_token(req).expect_err("missing token must fail");
        assert_eq!(err.code(), Code::Unauthenticated);
    }

    #[test]
    fn rejects_non_ulid_token() {
        let mut req = Request::new(());
        req.metadata_mut().insert(
            API_TOKEN_METADATA_KEY,
            "not-a-ulid".parse().expect("metadata value"),
        );
        let err = require_api_token(req).expect_err("bad token must fail");
        assert_eq!(err.code(), Code::Unauthenticated);
    }

    #[test]
    fn stores_tenant_id_in_extensions() {
        let tenant_ulid = ulid::Ulid::new();
        let mut req = Request::new(());
        req.metadata_mut().insert(
            API_TOKEN_METADATA_KEY,
            tenant_ulid.to_string().parse().expect("metadata value"),
        );

        let req = require_api_token(req).expect("valid token");
        let stored = req
            .extensions()
            .get::<TenantId>()
            .copied()
            .expect("tenant id extension");
        assert_eq!(stored.0, tenant_ulid);
    }
}
