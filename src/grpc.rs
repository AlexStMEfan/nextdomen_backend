// src/grpc.rs

use tonic::{transport::Server, Request, Response, Status};
use crate::directory_service::DirectoryService;
use std::sync::Arc;

pub mod user_api {
    tonic::include_proto!("user_api");
}

use user_api::{
    user_api_server::{UserApi, UserApiServer},
    GetUserRequest, GetUserResponse,
};

#[derive(Clone)]
pub struct UserApiService {
    service: Arc<DirectoryService>,
}

#[tonic::async_trait]
impl UserApi for UserApiService {
    async fn get_user(
        &self,
        request: Request<GetUserRequest>,
    ) -> Result<Response<GetUserResponse>, Status> {
        let username = &request.into_inner().username;
        let user = self.service.find_user_by_username(username)
            .await
            .map_err(|_| Status::internal("DB error"))?
            .ok_or(Status::not_found("User not found"))?;

        Ok(Response::new(GetUserResponse {
            id: user.id.to_string(),
            username: user.username,
            email: user.email.unwrap_or_default(),
            display_name: user.display_name.unwrap_or_default(),
        }))
    }
}

pub async fn run_grpc_server(service: Arc<DirectoryService>, addr: &str) -> Result<(), Box<dyn std::error::Error>> {
    let addr = addr.parse()?;
    let api = UserApiService { service };
    let server = UserApiServer::new(api);

    Server::builder()
        .add_service(server)
        .serve(addr)
        .await?;

    Ok(())
}