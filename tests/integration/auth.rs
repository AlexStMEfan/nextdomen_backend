// tests/integration/auth.rs

use nextdomen_backend::{directory_service::DirectoryService, web};
use axum_test::TestServer;
use serde_json::json;

#[tokio::test]
async fn test_login_success() {
    let service = DirectoryService::open("test.db", &[0u8; 32]).unwrap();
    let server = TestServer::new(web::create_router(service)).unwrap();

    let login_body = json!({
        "username": "admin",
        "password": "P@ssw0rd123"
    });

    let response = server.post("/api/login").json(&login_body).await;

    response.assert_status_ok();
    response.assert_json_has_key("token");
}

#[tokio::test]
async fn test_login_invalid_password() {
    let service = DirectoryService::open("test.db", &[0u8; 32]).unwrap();
    let server = TestServer::new(web::create_router(service)).unwrap();

    let login_body = json!({
        "username": "admin",
        "password": "wrong"
    });

    let response = server.post("/api/login").json(&login_body).await;

    response.assert_status_unauthorized();
}