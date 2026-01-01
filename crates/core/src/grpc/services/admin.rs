//! AdminService gRPC implementation.

use crate::ids::Nanos;
use crate::storage::facade::StorageFacade;
use mandate_proto::mandate::v1::{
    admin_service_server::AdminService, ConfigUpdateRequest, ConfigUpdateResponse,
    IssueGiftCardRequest, IssueGiftCardResponse,
};
use tonic::{Request, Response, Status};

use super::to_status;

#[derive(Clone)]
pub struct AdminServiceImpl {
    store: StorageFacade,
}

impl AdminServiceImpl {
    pub fn new(store: StorageFacade) -> Self {
        Self { store }
    }
}

#[tonic::async_trait]
impl AdminService for AdminServiceImpl {
    async fn issue_gift_card(
        &self,
        request: Request<IssueGiftCardRequest>,
    ) -> Result<Response<IssueGiftCardResponse>, Status> {
        let body = request.into_inner();
        let card = self
            .store
            .issue_gift_card(Nanos::new(body.amount_nanos))
            .await
            .map_err(to_status)?;
        Ok(Response::new(IssueGiftCardResponse { code: card.code }))
    }

    async fn update_config(
        &self,
        _request: Request<ConfigUpdateRequest>,
    ) -> Result<Response<ConfigUpdateResponse>, Status> {
        // TODO: Implement config update logic in Phase 16
        Err(Status::unimplemented(
            "UpdateConfig not yet implemented - see Phase 16",
        ))
    }
}
