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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::TenantDbConfig;
    use arrow_flight::flight_descriptor::DescriptorType;
    use std::sync::Arc;
    use testcontainers::Container;
    use testcontainers::runners::SyncRunner;
    use testcontainers_modules::postgres;
    use testcontainers_modules::postgres::Postgres;
    use tokio_postgres::NoTls;

    pub struct TestInfra {
        pub router: DbRouter,
        pub _nodes: Vec<testcontainers::Container<Postgres>>, // keep it alive
    }

    pub async fn build_router_with_container() -> anyhow::Result<TestInfra> {
        let mut tenants = Vec::new();
        let mut nodes = Vec::new();

        let tenant_test_data = vec![("alice", "tenant_acme"), ("bob", "tenant_beta")];

        for (user_name, tenant_id) in tenant_test_data {
            let (container, config) = create_tenant_config(user_name, tenant_id).await?;
            tenants.push(config);
            nodes.push(container);
        }

        let router = DbRouter::new(tenants);

        Ok(TestInfra {
            router,
            _nodes: nodes,
        })
    }

    async fn create_tenant_config(
        user_name: &str,
        tenant_id: &str,
    ) -> anyhow::Result<(Container<Postgres>, TenantDbConfig)> {
        let container = postgres::Postgres::default().start()?;

        // Host port assigned by docker
        let host_port = container.get_host_port_ipv4(5432)?;
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
              tenant_id TEXT NOT NULL,
            );
            INSERT INTO users(name, tenant_id) VALUES ('{}', '{}') ON CONFLICT DO NOTHING;
        "#,
                user_name, tenant_id
            ))
            .await?;

        let pg = crate::db_backends::PostgresBackend::new_from_conn_string(&conn_str);
        let config = TenantDbConfig {
            tenant_id: tenant_id.to_string(),
            backend: Arc::new(pg),
            default_schema: None,
        };

        Ok((container, config))
    }

    #[tokio::test]
    async fn e2e_handshake_query_revoke() {
        use arrow_flight::decode::FlightRecordBatchStream;
        use arrow_flight::sql::{
            CommandStatementQuery, ProstMessageExt, SqlInfo, metadata::SqlInfoDataBuilder,
        };
        use arrow_flight::{
            FlightDescriptor, FlightEndpoint, HandshakeRequest, Ticket,
            flight_service_client::FlightServiceClient,
        };
        use bytes::Bytes;
        use tokio::net::TcpListener;
        use tokio_stream::wrappers::TcpListenerStream;
        use tonic::{Request, metadata::MetadataValue, transport::Server};

        // 1) Spin up Postgres + router
        let infra = build_router_with_container().await.unwrap();

        // 2) Start server on random port
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let issuer = "test-issuer".to_string();
        let audience = "test-audience".to_string();
        let svc = SqlRouterService::new(issuer.clone(), audience.clone(), infra.router.clone());
        let revocations = RevocationList::default();

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
        let endpoint = format!("http://{}", addr);
        let mut client = FlightServiceClient::connect(endpoint.clone())
            .await
            .unwrap();

        // 4) Handshake (get JWT)
        let creds = HandshakeCreds {
            username: "alice".into(),
            password: "secret1".into(),
        };
        let payload = serde_json::to_vec(&creds).unwrap();
        let req_stream = tokio_stream::iter(vec![HandshakeRequest {
            protocol_version: 0,
            payload: Bytes::from(payload),
        }]);
        let mut hs = client
            .handshake(Request::new(req_stream))
            .await
            .unwrap()
            .into_inner();
        let token =
            String::from_utf8(hs.message().await.unwrap().unwrap().payload.to_vec()).unwrap();

        // 5) Build a Flight SQL descriptor: SELECT name FROM users WHERE name = 'alice'
        let any = CommandStatementQuery {
            query: "SELECT name FROM users WHERE name = 'alice'".into(),
            transaction_id: None,
        }
        .as_any();

        let fd = FlightDescriptor {
            r#type: DescriptorType::Cmd as i32,
            cmd: Bytes::from(prost::Message::encode_to_vec(&any)),
            path: vec![],
        };

        // Attach Bearer to subsequent requests
        let bearer: MetadataValue<_> = format!("Bearer {token}").parse().unwrap();

        // 6) GetFlightInfo (schema + ticket)
        let mut req = Request::new(fd);
        req.metadata_mut().insert("authorization", bearer.clone());
        let info = client.get_flight_info(req).await.unwrap().into_inner();

        assert!(!info.schema.is_empty(), "schema should be present");
        let FlightEndpoint {
            ticket: Some(t), ..
        } = info.endpoint.first().cloned().expect("endpoint")
        else {
            panic!("no ticket")
        };

        // 7) DoGet → decode to batches, assert one row = "alice"
        let mut get_req = Request::new(Ticket { ticket: t.ticket });
        get_req
            .metadata_mut()
            .insert("authorization", bearer.clone());
        let flight_stream = client.do_get(get_req).await.unwrap().into_inner();
        let mut rb_stream =
            FlightRecordBatchStream::new_from_flight_data(flight_stream.map_err(|e| e.into()));

        // Collect rows
        use futures::TryStreamExt;
        let mut total_rows = 0usize;
        while let Some(batch) = rb_stream.try_next().await.unwrap() {
            total_rows += batch.num_rows();
            // Column 0 is "name"
            let arr = batch
                .column(0)
                .as_any()
                .downcast_ref::<arrow_array::StringArray>()
                .unwrap();
            assert_eq!(arr.value(0), "alice");
        }
        assert!(total_rows >= 1);

        // 8) Revoke token via DoAction (custom)
        use arrow_flight::Action;
        let mut act_req = Request::new(Action {
            r#type: "revoke_self".into(),
            body: Bytes::new(),
        });
        act_req
            .metadata_mut()
            .insert("authorization", bearer.clone());
        let mut act_stream = client.do_action(act_req).await.unwrap().into_inner();
        let _ = act_stream.message().await.unwrap().unwrap(); // "revoked"

        // 9) Subsequent call fails with Unauthenticated
        let mut get_req2 = Request::new(Ticket {
            ticket: Bytes::from_static(b"doesnt-matter"),
        });
        get_req2
            .metadata_mut()
            .insert("authorization", bearer.clone());
        let err = client.do_get(get_req2).await.err().expect("should fail");
        assert!(err.code() == tonic::Code::Unauthenticated);

        server.abort();
    }
}
