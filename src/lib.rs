use crate::flight_server::MyFlightService;
use arrow_flight::flight_service_server::FlightServiceServer;

mod flight_server;

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


