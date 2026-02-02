//! MemberService gRPC implementation.

use crate::storage::facade::StorageFacade;
use mandate_proto::mandate::v1::member_service_server::MemberService;

mod export;
mod list;
mod list_member_groups;
mod pending;

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
        request: tonic::Request<mandate_proto::mandate::v1::SubmitPendingMemberRequest>,
    ) -> Result<
        tonic::Response<mandate_proto::mandate::v1::SubmitPendingMemberResponse>,
        tonic::Status,
    > {
        pending::submit_pending_member(self, request).await
    }

    async fn list_pending_members(
        &self,
        request: tonic::Request<mandate_proto::mandate::v1::ListPendingMembersRequest>,
    ) -> Result<
        tonic::Response<mandate_proto::mandate::v1::ListPendingMembersResponse>,
        tonic::Status,
    > {
        pending::list_pending_members(self, request).await
    }

    async fn get_approved_member_by_tg_user_id(
        &self,
        request: tonic::Request<mandate_proto::mandate::v1::GetApprovedMemberByTgUserIdRequest>,
    ) -> Result<
        tonic::Response<mandate_proto::mandate::v1::GetApprovedMemberByTgUserIdResponse>,
        tonic::Status,
    > {
        pending::get_approved_member_by_tg_user_id(self, request).await
    }

    async fn register_member(
        &self,
        request: tonic::Request<mandate_proto::mandate::v1::RegisterMemberRequest>,
    ) -> Result<tonic::Response<mandate_proto::mandate::v1::RegisterMemberResponse>, tonic::Status>
    {
        pending::register_member(self, request).await
    }

    async fn list_members(
        &self,
        request: tonic::Request<mandate_proto::mandate::v1::ListMembersRequest>,
    ) -> Result<tonic::Response<mandate_proto::mandate::v1::ListMembersResponse>, tonic::Status>
    {
        list::list_members(self, request).await
    }

    async fn export_members(
        &self,
        request: tonic::Request<mandate_proto::mandate::v1::ExportMembersRequest>,
    ) -> Result<tonic::Response<mandate_proto::mandate::v1::ExportMembersResponse>, tonic::Status>
    {
        export::export_members(self, request).await
    }

    async fn list_member_groups(
        &self,
        request: tonic::Request<mandate_proto::mandate::v1::ListMemberGroupsRequest>,
    ) -> Result<tonic::Response<mandate_proto::mandate::v1::ListMemberGroupsResponse>, tonic::Status>
    {
        list_member_groups::list_member_groups(self, request).await
    }
}
