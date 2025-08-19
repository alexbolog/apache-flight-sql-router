use arrow_flight::flight_service_server::FlightServiceServer;
use std::net::SocketAddr;
use std::sync::Arc;
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
    let revocations = Arc::clone(&flight.revocations);

    Server::builder()
        .add_service(FlightServiceServer::with_interceptor(
            flight,
            auth_interceptor(revocations, issuer, audience),
        ))
        .serve(addr)
        .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::TenantDbConfig;
    use arrow_flight::sql::client::FlightSqlServiceClient;
    use futures::TryStreamExt;
    use std::sync::Arc;
    use testcontainers::runners::SyncRunner;
    use testcontainers::Container;
    use testcontainers_modules::postgres;
    use testcontainers_modules::postgres::Postgres;
    use tokio_postgres::NoTls;
    use crate::db_backends::PostgresBackend;

    pub struct TestInfra {
        pub router: DbRouter,
    }

    pub async fn build_router_with_container(
        tenant_test_data: Vec<(&str, &str, u16)>,
    ) -> anyhow::Result<TestInfra> {
        let mut tenants = Vec::new();

        for (user_name, tenant_id, port) in tenant_test_data {
            let config = create_tenant_config(user_name, tenant_id, port).await?;
            tenants.push(config);
        }

        let router = DbRouter::new(tenants);

        Ok(TestInfra { router })
    }

    async fn create_tenant_config(
        user_name: &str,
        tenant_id: &str,
        host_port: u16,
    ) -> anyhow::Result<TenantDbConfig> {
        let conn_str = format!("postgres://postgres:postgres@127.0.0.1:{host_port}/postgres");

        // Init schema
        let (client, conn) = tokio_postgres::connect(&conn_str, NoTls).await?;
        tokio::spawn(async move {
            let _ = conn.await;
        });

        client
            .batch_execute(&format!(
                r#"
            CREATE TABLE IF NOT EXISTS users (
              id BIGSERIAL PRIMARY KEY,
              name TEXT NOT NULL,
              tenant_id TEXT NOT NULL
            );
            INSERT INTO users(name, tenant_id) VALUES ('{}', '{}') ON CONFLICT DO NOTHING;
        "#,
                user_name, tenant_id
            ))
            .await?;

        let pg = PostgresBackend::new_from_conn_string(&conn_str);
        let config = TenantDbConfig {
            tenant_id: tenant_id.to_string(),
            backend: Arc::new(pg),
            default_schema: None,
        };

        Ok(config)
    }

    fn get_pg_container_blocking() -> anyhow::Result<(Container<Postgres>, u16)> {
        let container = postgres::Postgres::default().start()?;
        let host_port = container.get_host_port_ipv4(5432)?;
        Ok((container, host_port))
    }

    /// End-to-end test including DB level tenancy isolation
    /// Test setup involves creating 2 DB instances, one per tenant, each instance with different data
    /// and 2 accounts, one per tenant.
    /// Test sets up the server,
    #[test]
    fn e2e_handshake_query_revoke() {
        use arrow_flight::decode::FlightRecordBatchStream;
        use arrow_flight::flight_service_client::FlightServiceClient;
        use tokio::net::TcpListener;
        use tokio_stream::wrappers::TcpListenerStream;
        use tonic::{transport::Server, Request};

        // generate test data synchronously - cannot launch containers from a tokio runtime
        let (_acme_node, acme_host_port) =
            get_pg_container_blocking().expect("failed to get container");

        let (_beta_node, beta_host_port) =
            get_pg_container_blocking().expect("failed to get container");

        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async move {
            let tenant_test_data = vec![
                ("alice", "tenant_acme", acme_host_port),
                ("bob", "tenant_beta", beta_host_port),
            ];

            // 1) Set up Postgres data + router
            let infra = build_router_with_container(tenant_test_data).await.unwrap();

            // 2) Start server on random port
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let issuer = "test-issuer".to_string();
            let audience = "test-audience".to_string();
            let svc = SqlRouterService::new(issuer.clone(), audience.clone(), infra.router.clone());
            let revocations = Arc::clone(&svc.revocations);

            let server = tokio::spawn(async move {
                Server::builder()
                    .add_service(FlightServiceServer::with_interceptor(
                        svc,
                        auth_interceptor(revocations, issuer, audience),
                    ))
                    .serve_with_incoming(TcpListenerStream::new(listener))
                    .await
                    .unwrap();
            });

            // 3) Client connect
            let endpoint_url = format!("http://{}", addr);
            let channel = tonic::transport::Channel::from_shared(endpoint_url.clone())
                .unwrap()
                .connect()
                .await
                .unwrap();

            let mut base = FlightServiceClient::new(channel.clone());
            let creds = HandshakeCreds {
                username: "alice".into(),
                password: "secret1".into(),
            };
            let payload = bytes::Bytes::from(serde_json::to_vec(&creds).unwrap());
            let req_stream = tokio_stream::iter(vec![arrow_flight::HandshakeRequest {
                protocol_version: 0,
                payload,
            }]);
            let mut hs = base
                .handshake(Request::new(req_stream))
                .await
                .unwrap()
                .into_inner();
            let token =
                String::from_utf8(hs.message().await.unwrap().unwrap().payload.to_vec()).unwrap();

            // Add auth header to all subsequent calls
            let mut sql = FlightSqlServiceClient::new(channel.clone());
            sql.set_header("authorization", format!("Bearer {token}"));

            // 4) Ask for FlightInfo for a statement
            let info = sql
                .execute("SELECT name FROM users".to_string(), None)
                .await
                .unwrap();
            let ticket = info.endpoint[0].ticket.as_ref().unwrap().clone();

            let flight_data_stream = sql.do_get(Request::new(ticket)).await.unwrap().into_inner();
            let mut rb_stream = FlightRecordBatchStream::new(flight_data_stream);

            // 5) Validate data integrity
            let mut total_rows = 0usize;
            while let Some(batch) = rb_stream.try_next().await.unwrap() {
                total_rows += batch.num_rows();
                let arr = batch
                    .column(0)
                    .as_any()
                    .downcast_ref::<arrow_array::StringArray>()
                    .unwrap();
                assert_eq!(arr.value(0), "alice"); // make sure we're fetching from the right tenant db
            }
            assert_eq!(total_rows, 1); // single row, this should be updated when extending to multiple tenants inside a single db table (if ever)

            // 6) Test revoke flow
            use arrow_flight::Action;
            let inner = sql.inner_mut();
            let mut act_req = Request::new(Action {
                r#type: "revoke_self".into(),
                body: bytes::Bytes::new(),
            });
            act_req
                .metadata_mut()
                .insert("authorization", format!("Bearer {token}").parse().unwrap());
            let mut act_stream = inner.do_action(act_req).await.unwrap().into_inner();
            let _ = act_stream.message().await.unwrap().unwrap();

            // 7) Subsequent call should fail with Unauthenticated
            let bad = sql
                .execute("SELECT 1".to_string(), None)
                .await
                .err()
                .unwrap();
            assert!(bad.to_string().contains("Unauthenticated"));

            server.abort();
        });
    }
}
