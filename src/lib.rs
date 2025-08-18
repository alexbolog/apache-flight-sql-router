use arrow_flight::flight_service_server::FlightServiceServer;
use std::net::SocketAddr;
use tonic::transport::Server;

pub mod auth;
mod db_backends;
pub mod db_router;
pub mod interceptor;
// core flight server impl, not used, replaced by sql_service
// pub mod service;
mod sql_service;
pub mod types;
pub mod utils;

// Re-export commonly used items for convenience
use crate::db_router::DbRouter;
use crate::sql_service::SqlRouterService;
pub use auth::{Account, AuthContext, Claims, HandshakeCreds, RevocationList};

use crate::interceptor::auth_interceptor;
pub use types::{BatchStream, SqlBackend};

pub async fn run(
    addr: SocketAddr,
    issuer: String,
    audience: String,
    router: DbRouter,
) -> Result<(), Box<dyn std::error::Error>> {
    let flight = SqlRouterService::new(issuer.clone(), audience.clone(), router);

    // Shared revocation list for the interceptor (and optionally the service)
    let revocations = RevocationList::default();

    Server::builder()
        .add_service(FlightServiceServer::with_interceptor(
            flight,
            auth_interceptor(revocations, issuer, audience),
        ))
        .serve(addr)
        .await?;

    Ok(())
}
