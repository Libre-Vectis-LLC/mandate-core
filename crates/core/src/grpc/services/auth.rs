//! AuthService gRPC implementation.

use crate::storage::facade::StorageFacade;
use mandate_proto::mandate::v1::{
    auth_service_server::AuthService, RedeemGiftCardRequest, RedeemGiftCardResponse,
    ResolveTelegramUserRequest, ResolveTelegramUserResponse,
};
use rand::Rng;
use tonic::{Request, Response, Status};

use super::to_status;

#[derive(Clone)]
pub struct AuthServiceImpl {
    store: StorageFacade,
}

impl AuthServiceImpl {
    pub fn new(store: StorageFacade) -> Self {
        Self { store }
    }
}

#[tonic::async_trait]
impl AuthService for AuthServiceImpl {
    async fn redeem_gift_card(
        &self,
        request: Request<RedeemGiftCardRequest>,
    ) -> Result<Response<RedeemGiftCardResponse>, Status> {
        let body = request.into_inner();

        // Check if this tg_user_id already has an associated tenant.
        // If so, use the existing tenant for top-up instead of creating a new one.
        let existing = self
            .store
            .resolve_telegram_user(&body.tg_user_id)
            .await
            .map_err(to_status)?;

        let tenant_id = match existing {
            Some((tid, _)) => tid,                           // Existing tenant found
            None => crate::ids::TenantId(ulid::Ulid::new()), // Create new tenant
        };

        let card = self
            .store
            .redeem_gift_card(&body.code, tenant_id)
            .await
            .map_err(to_status)?;

        let new_balance = self
            .store
            .credit_tenant(tenant_id, &body.tg_user_id, card.amount)
            .await
            .map_err(to_status)?;

        // Issue a cryptographically secure token.
        // Use 32 random bytes (256 bits) to prevent token prediction/brute-force.
        let token_bytes: [u8; 32] = rand::thread_rng().gen();
        let token_str = format!("token-{}", hex::encode(token_bytes));
        let token = crate::ids::TenantToken::from(token_str.clone());
        self.store
            .insert_tenant_token(&token, tenant_id)
            .await
            .map_err(to_status)?;

        let balance_i64 =
            new_balance
                .try_as_i64()
                .ok_or_else(|| crate::rpc::RpcError::Internal {
                    operation: "redeem_gift_card",
                    details: "balance exceeds i64::MAX".into(),
                })?;
        Ok(Response::new(RedeemGiftCardResponse {
            tenant_id: tenant_id.0.to_string(),
            new_balance_nanos: balance_i64,
            api_token: token_str,
        }))
    }

    async fn resolve_telegram_user(
        &self,
        request: Request<ResolveTelegramUserRequest>,
    ) -> Result<Response<ResolveTelegramUserResponse>, Status> {
        let body = request.into_inner();

        let result = self
            .store
            .resolve_telegram_user(&body.tg_user_id)
            .await
            .map_err(to_status)?;

        match result {
            Some((tenant_id, group_id)) => Ok(Response::new(ResolveTelegramUserResponse {
                tenant_id: tenant_id.0.to_string(),
                group_id: group_id.0.to_string(),
            })),
            None => Err(Status::not_found(format!(
                "No tenant or group found for Telegram user: {}",
                body.tg_user_id
            ))),
        }
    }
}
