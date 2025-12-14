use crate::ids::{BotSecret, TenantToken};
use crate::proto::{API_TOKEN_METADATA_KEY, BOT_SECRET_METADATA_KEY};
use crate::rpc::RpcError;
use tonic::{Request, Status};

/// Enforce presence of `x-api-token` and attach a `TenantToken` to request extensions.
///
/// The token is treated as an opaque secret (rotatable). Core must not interpret it as a tenant ID.
#[allow(clippy::result_large_err)]
pub fn require_api_token(mut req: Request<()>) -> Result<Request<()>, Status> {
    let token = {
        let token = req
            .metadata()
            .get(API_TOKEN_METADATA_KEY)
            .ok_or_else(|| RpcError::Unauthenticated("missing api token".into()))?
            .to_str()
            .map_err(|_| RpcError::Unauthenticated("bad token".into()))?;

        if token.is_empty() {
            return Err(RpcError::Unauthenticated("empty api token".into()).into());
        }

        TenantToken::from(token)
    };

    req.extensions_mut().insert(token);
    Ok(req)
}

/// Enforce presence of `x-bot-secret` and attach a `BotSecret` to request extensions.
#[allow(clippy::result_large_err)]
pub fn require_bot_secret(mut req: Request<()>) -> Result<Request<()>, Status> {
    let secret = {
        let secret = req
            .metadata()
            .get(BOT_SECRET_METADATA_KEY)
            .ok_or_else(|| RpcError::Unauthenticated("missing bot secret".into()))?
            .to_str()
            .map_err(|_| RpcError::Unauthenticated("bad secret encoding".into()))?;

        if secret.is_empty() {
            return Err(RpcError::Unauthenticated("empty bot secret".into()).into());
        }

        BotSecret::from(secret)
    };

    req.extensions_mut().insert(secret);
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
    fn stores_bot_secret_in_extensions() {
        let mut req = Request::new(());
        req.metadata_mut().insert(
            BOT_SECRET_METADATA_KEY,
            "secret-abc".parse().expect("metadata value"),
        );

        let req = require_bot_secret(req).expect("valid secret");
        let stored = req
            .extensions()
            .get::<BotSecret>()
            .cloned()
            .expect("bot secret extension");
        assert_eq!(stored.as_str(), "secret-abc");
    }
}
