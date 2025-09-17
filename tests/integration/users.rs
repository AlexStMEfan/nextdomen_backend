// tests/integration/users.rs

use nextdomen_backend::{directory_service::DirectoryService, web};
use axum_test::TestServer;

#[tokio::test]
async fn test_list_users() {
    let service = DirectoryService::open("test.db", &[0u8; 32]).unwrap();
    let server = TestServer::new(web::create_router(service)).unwrap();

    let response = server.get("/api/users").await;

    response.assert_status_ok();
    response.assert_content_type("application/json");
}