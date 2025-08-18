use arrow_flight::flight_service_server::FlightServiceServer;

pub mod auth;
pub mod db_router;
pub mod interceptor;
pub mod service;
pub mod types;
mod db_backends;
mod sql_service;
pub mod utils;

// Re-export commonly used items for convenience
pub use auth::{Account, AuthContext, Claims, HandshakeCreds, RevocationList};
pub use service::DmFlightService;
pub use types::{BatchStream, SqlBackend};

pub fn run() {
    let service = DmFlightService::new(
        "apache-flight-sql-router".to_string(),
        "flight-clients".to_string(),
    );
    FlightServiceServer::new(service);
}
