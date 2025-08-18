use arrow_flight::flight_service_server::FlightServiceServer;

pub mod auth;
pub mod interceptor;
pub mod service;
pub mod types;

// Re-export commonly used items for convenience
pub use auth::{Account, AuthContext, Claims, HandshakeCreds, RevocationList};
pub use service::MyFlightService;
pub use types::{BatchStream, SqlBackend};

pub fn run() {
    println!("Hello, world!");
    let service = MyFlightService::new(
        "apache-flight-sql-router".to_string(),
        "flight-clients".to_string(),
    );
    FlightServiceServer::new(service);

    // let data = Recipe::new("daily_sales")
    //     .with_param("date", "2025-08-14")
    //     .execute()
    //     .get_arrow();
}
