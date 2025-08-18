use arrow_flight::flight_service_server::FlightServiceServer;

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

pub use types::{BatchStream, SqlBackend};

pub fn run() {
    let service = SqlRouterService::new(
        "apache-flight-sql-router".to_string(),
        "flight-clients".to_string(),
        DbRouter::new(vec![]),
    );
    FlightServiceServer::new(service);
}
