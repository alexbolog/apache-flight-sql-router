use apache_flight_sql_router::db_router::DbRouter;
use std::net::SocketAddr;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let router = build_router().await?;

    let addr: SocketAddr = "0.0.0.0:50051".parse()?;
    let issuer = "flight-demo-auth".to_string();
    let audience = "flight-clients".to_string();

    println!("Flight SQL server listening on {addr}");
    apache_flight_sql_router::run(addr, issuer, audience, router).await
}

async fn build_router() -> Result<DbRouter, Box<dyn std::error::Error>> {
    Ok(DbRouter::new(vec![]))
}
