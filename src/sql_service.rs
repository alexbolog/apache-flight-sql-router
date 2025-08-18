use crate::auth::{create_jwt_token, verify_password};
use crate::db_router::DbRouter;
use crate::utils::{flight_data_from_arrow_batch, flight_data_from_arrow_schema};
use crate::{AuthContext, HandshakeCreds, RevocationList};
use arrow::ipc::writer::{IpcDataGenerator, IpcWriteOptions};
use arrow_flight::flight_service_server::FlightService;
use arrow_flight::sql::metadata::{SqlInfoData, SqlInfoDataBuilder};
use arrow_flight::sql::server::FlightSqlService;
use arrow_flight::sql::server::{DoPutError, PeekableFlightDataStream};
use arrow_flight::sql::*;
use arrow_flight::{
    Action, ActionType, FlightData, FlightDescriptor, FlightEndpoint, FlightInfo, HandshakeRequest,
    HandshakeResponse, Ticket,
};
use futures::{Stream, StreamExt, TryStreamExt, stream};
use std::pin::Pin;
use tonic::codegen::Bytes;
use tonic::{Request, Response, Status, Streaming};

#[derive(Clone)]
pub struct SqlRouterService {
    pub issuer: String,
    pub audience: String,
    pub revocations: RevocationList,
    router: DbRouter,
}

impl SqlRouterService {
    pub fn new(issuer: String, audience: String, router: DbRouter) -> Self {
        Self {
            issuer,
            audience,
            revocations: RevocationList::default(),
            router,
        }
    }
}

type HandshakeStream =
    Pin<Box<dyn Stream<Item = Result<HandshakeResponse, Status>> + Send + 'static>>;

type DoGetStream =
    Pin<Box<dyn futures::Stream<Item = Result<arrow_flight::FlightData, tonic::Status>> + Send>>;

type DoActionStream =
    Pin<Box<dyn futures::Stream<Item = Result<arrow_flight::Result, Status>> + Send + 'static>>;

#[tonic::async_trait]
impl FlightSqlService for SqlRouterService {
    type FlightService = Self;

    async fn do_handshake(
        &self,
        mut request: Request<Streaming<HandshakeRequest>>,
    ) -> Result<Response<HandshakeStream>, Status> {
        let stream = request.get_mut();
        let first = stream
            .next()
            .await
            .ok_or_else(|| Status::invalid_argument("empty handshake"))??;

        // Expect JSON creds in payload
        let creds: HandshakeCreds = serde_json::from_slice(&first.payload)
            .map_err(|_| Status::unauthenticated("invalid credentials payload"))?;

        // Verify against hardcoded accounts (argon2)
        let acct = verify_password(&creds.username, &creds.password)
            .map_err(|e| Status::unauthenticated(e))?;

        // Issue JWT (HS256 for demo)
        let token = create_jwt_token(&acct, &self.issuer, &self.audience)
            .map_err(|e| Status::internal(format!("token encode: {e}")))?;

        let resp = HandshakeResponse {
            protocol_version: first.protocol_version,
            payload: token.into_bytes().into(),
        };
        let s = futures::stream::once(async move { Ok(resp) });
        Ok(Response::new(Box::pin(s)))
    }

    async fn get_flight_info_statement(
        &self,
        query: CommandStatementQuery,
        req: Request<FlightDescriptor>,
    ) -> Result<Response<FlightInfo>, Status> {
        let ctx = req
            .extensions()
            .get::<AuthContext>()
            .ok_or(Status::unauthenticated("no auth context"))?
            .clone();
        let sql = query.query.clone();

        let cfg = self
            .router
            .for_tenant(&ctx.tenant_id)
            .map_err(|e| Status::permission_denied(e.to_string()))?;

        let schema = cfg.backend.schema(&sql, &ctx).await.map_err(internal)?;

        let schema_fd = flight_data_from_arrow_schema(&schema).map_err(internal)?;

        // Pack a ticket (tenant + sql) so DoGet can execute it
        let ticket_bytes = serde_json::to_vec(&(ctx.tenant_id.clone(), sql)).unwrap();
        let endpoint = FlightEndpoint {
            ticket: Some(Ticket {
                ticket: ticket_bytes.into(),
            }),
            location: vec![],
            app_metadata: vec![].into(),
            expiration_time: None,
        };

        let info = FlightInfo {
            schema: schema_fd.data_header,
            flight_descriptor: None,
            endpoint: vec![endpoint],
            total_records: -1,
            total_bytes: -1,
            app_metadata: vec![].into(),
            ordered: false,
        };
        Ok(Response::new(info))
    }

    async fn do_get_statement(
        &self,
        _ticket: TicketStatementQuery,
        req: Request<Ticket>,
    ) -> Result<Response<DoGetStream>, Status> {
        let ctx = req
            .extensions()
            .get::<AuthContext>()
            .ok_or(Status::unauthenticated("no auth context"))?
            .clone();

        let (tenant_id, sql): (String, String) =
            serde_json::from_slice(&req.get_ref().ticket).map_err(internal)?;

        if tenant_id != ctx.tenant_id {
            return Err(Status::permission_denied("tenant mismatch"));
        }

        let cfg = self
            .router
            .for_tenant(&tenant_id)
            .map_err(|e| Status::permission_denied(e.to_string()))?;

        let batches = cfg.backend.query(&sql, &ctx).await.map_err(internal)?;

        let out = batches
            .map(move |res| {
                res.map_err(internal).and_then(|rb| {
                    let (fd, dicts) = flight_data_from_arrow_batch(&rb).map_err(internal)?;
                    let seq = dicts.into_iter().map(Ok).chain(std::iter::once(Ok(fd)));
                    Ok::<_, Status>(futures::stream::iter(seq))
                })
            })
            .try_flatten();

        Ok(Response::new(Box::pin(out)))
    }

    async fn do_get_sql_info(
        &self,
        _query: CommandGetSqlInfo,
        _request: Request<Ticket>,
    ) -> Result<Response<DoGetStream>, Status> {
        // Build the SqlInfoData (server metadata)
        let mut b = SqlInfoDataBuilder::new();
        b.append(SqlInfo::FlightSqlServerName, "demo-sql-router");
        b.append(SqlInfo::FlightSqlServerVersion, "0.1.0");
        let sql_info_data: SqlInfoData = b.build().map_err(|e| Status::internal(e.to_string()))?;

        // TODO: impl actual record fetching
        // get the RecordBatch to send (empty Vec -> return all)
        let batch = sql_info_data
            .record_batch(Vec::<u32>::new())
            .map_err(|e| Status::internal(e.to_string()))?;

        // schema for encoding
        let schema_ref = sql_info_data.schema();
        // encode to FlightData sequence
        let flights = crate::utils::batches_to_flight_data(schema_ref.as_ref(), vec![batch])
            .map_err(|e| Status::internal(e.to_string()))?;

        // stream them as tonic Response<Stream>
        let s = futures::stream::iter(flights.into_iter().map(Ok));
        Ok(Response::new(Box::pin(s) as DoGetStream))
    }

    async fn do_get_fallback(
        &self,
        _request: Request<Ticket>,
        message: Any,
    ) -> Result<Response<DoGetStream>, Status> {
        Err(Status::unimplemented("do_get_fallback not implemented"))
    }

    async fn get_flight_info_substrait_plan(
        &self,
        _query: CommandStatementSubstraitPlan,
        _request: Request<FlightDescriptor>,
    ) -> Result<Response<FlightInfo>, Status> {
        Err(Status::unimplemented("do_get_fallback not implemented"))
    }

    async fn get_flight_info_prepared_statement(
        &self,
        _query: CommandPreparedStatementQuery,
        _request: Request<FlightDescriptor>,
    ) -> Result<Response<FlightInfo>, Status> {
        Err(Status::unimplemented("do_get_fallback not implemented"))
    }

    async fn get_flight_info_catalogs(
        &self,
        _query: CommandGetCatalogs,
        _request: Request<FlightDescriptor>,
    ) -> Result<Response<FlightInfo>, Status> {
        Err(Status::unimplemented("do_get_fallback not implemented"))
    }

    async fn get_flight_info_schemas(
        &self,
        _query: CommandGetDbSchemas,
        _request: Request<FlightDescriptor>,
    ) -> Result<Response<FlightInfo>, Status> {
        Err(Status::unimplemented("do_get_fallback not implemented"))
    }

    async fn get_flight_info_tables(
        &self,
        _query: CommandGetTables,
        _request: Request<FlightDescriptor>,
    ) -> Result<Response<FlightInfo>, Status> {
        Err(Status::unimplemented("do_get_fallback not implemented"))
    }

    async fn get_flight_info_table_types(
        &self,
        _query: CommandGetTableTypes,
        _request: Request<FlightDescriptor>,
    ) -> Result<Response<FlightInfo>, Status> {
        Err(Status::unimplemented("do_get_fallback not implemented"))
    }

    async fn get_flight_info_sql_info(
        &self,
        _query: CommandGetSqlInfo,
        _request: Request<FlightDescriptor>,
    ) -> Result<Response<FlightInfo>, Status> {
        Ok(Response::new(FlightInfo::default()))
    }

    async fn get_flight_info_primary_keys(
        &self,
        _query: CommandGetPrimaryKeys,
        _request: Request<FlightDescriptor>,
    ) -> Result<Response<FlightInfo>, Status> {
        Err(Status::unimplemented("do_get_fallback not implemented"))
    }

    async fn get_flight_info_exported_keys(
        &self,
        _query: CommandGetExportedKeys,
        _request: Request<FlightDescriptor>,
    ) -> Result<Response<FlightInfo>, Status> {
        Err(Status::unimplemented("do_get_fallback not implemented"))
    }

    async fn get_flight_info_imported_keys(
        &self,
        _query: CommandGetImportedKeys,
        _request: Request<FlightDescriptor>,
    ) -> Result<Response<FlightInfo>, Status> {
        Err(Status::unimplemented("do_get_fallback not implemented"))
    }

    async fn get_flight_info_cross_reference(
        &self,
        _query: CommandGetCrossReference,
        _request: Request<FlightDescriptor>,
    ) -> Result<Response<FlightInfo>, Status> {
        Err(Status::unimplemented("do_get_fallback not implemented"))
    }

    async fn get_flight_info_xdbc_type_info(
        &self,
        _query: CommandGetXdbcTypeInfo,
        _request: Request<FlightDescriptor>,
    ) -> Result<Response<FlightInfo>, Status> {
        Err(Status::unimplemented("do_get_fallback not implemented"))
    }

    async fn get_flight_info_fallback(
        &self,
        cmd: Command,
        _request: Request<FlightDescriptor>,
    ) -> Result<Response<FlightInfo>, Status> {
        Err(Status::unimplemented("do_get_fallback not implemented"))
    }

    async fn do_get_prepared_statement(
        &self,
        _query: CommandPreparedStatementQuery,
        _request: Request<Ticket>,
    ) -> Result<Response<DoGetStream>, Status> {
        Err(Status::unimplemented("do_get_fallback not implemented"))
    }

    async fn do_get_catalogs(
        &self,
        _query: CommandGetCatalogs,
        _request: Request<Ticket>,
    ) -> Result<Response<DoGetStream>, Status> {
        Err(Status::unimplemented("do_get_fallback not implemented"))
    }

    async fn do_get_schemas(
        &self,
        _query: CommandGetDbSchemas,
        _request: Request<Ticket>,
    ) -> Result<Response<DoGetStream>, Status> {
        Err(Status::unimplemented("do_get_fallback not implemented"))
    }

    async fn do_get_tables(
        &self,
        _query: CommandGetTables,
        _request: Request<Ticket>,
    ) -> Result<Response<DoGetStream>, Status> {
        Err(Status::unimplemented("do_get_fallback not implemented"))
    }

    async fn do_get_table_types(
        &self,
        _query: CommandGetTableTypes,
        _request: Request<Ticket>,
    ) -> Result<Response<DoGetStream>, Status> {
        Err(Status::unimplemented("do_get_fallback not implemented"))
    }

    async fn do_get_primary_keys(
        &self,
        _query: CommandGetPrimaryKeys,
        _request: Request<Ticket>,
    ) -> Result<Response<DoGetStream>, Status> {
        Err(Status::unimplemented("do_get_fallback not implemented"))
    }

    async fn do_get_exported_keys(
        &self,
        _query: CommandGetExportedKeys,
        _request: Request<Ticket>,
    ) -> Result<Response<DoGetStream>, Status> {
        Err(Status::unimplemented("do_get_fallback not implemented"))
    }

    async fn do_get_imported_keys(
        &self,
        _query: CommandGetImportedKeys,
        _request: Request<Ticket>,
    ) -> Result<Response<DoGetStream>, Status> {
        Err(Status::unimplemented("do_get_fallback not implemented"))
    }

    async fn do_get_cross_reference(
        &self,
        _query: CommandGetCrossReference,
        _request: Request<Ticket>,
    ) -> Result<Response<DoGetStream>, Status> {
        Err(Status::unimplemented("do_get_fallback not implemented"))
    }

    async fn do_get_xdbc_type_info(
        &self,
        _query: CommandGetXdbcTypeInfo,
        _request: Request<Ticket>,
    ) -> Result<Response<DoGetStream>, Status> {
        Err(Status::unimplemented("do_get_fallback not implemented"))
    }

    async fn do_put_fallback(
        &self,
        _request: Request<PeekableFlightDataStream>,
        message: Any,
    ) -> Result<Response<<Self as FlightService>::DoPutStream>, Status> {
        Err(Status::unimplemented("do_get_fallback not implemented"))
    }

    async fn do_put_error_callback(
        &self,
        _request: Request<PeekableFlightDataStream>,
        error: DoPutError,
    ) -> Result<Response<<Self as FlightService>::DoPutStream>, Status> {
        Err(Status::unimplemented("do_get_fallback not implemented"))
    }

    async fn do_put_statement_update(
        &self,
        _ticket: CommandStatementUpdate,
        _request: Request<PeekableFlightDataStream>,
    ) -> Result<i64, Status> {
        Err(Status::unimplemented("do_get_fallback not implemented"))
    }

    async fn do_put_statement_ingest(
        &self,
        _ticket: CommandStatementIngest,
        _request: Request<PeekableFlightDataStream>,
    ) -> Result<i64, Status> {
        Err(Status::unimplemented("do_get_fallback not implemented"))
    }

    async fn do_put_prepared_statement_query(
        &self,
        _query: CommandPreparedStatementQuery,
        _request: Request<PeekableFlightDataStream>,
    ) -> Result<DoPutPreparedStatementResult, Status> {
        Err(Status::unimplemented("do_get_fallback not implemented"))
    }

    async fn do_put_prepared_statement_update(
        &self,
        _query: CommandPreparedStatementUpdate,
        _request: Request<PeekableFlightDataStream>,
    ) -> Result<i64, Status> {
        Err(Status::unimplemented("do_get_fallback not implemented"))
    }

    async fn do_put_substrait_plan(
        &self,
        _query: CommandStatementSubstraitPlan,
        _request: Request<PeekableFlightDataStream>,
    ) -> Result<i64, Status> {
        Err(Status::unimplemented("do_get_fallback not implemented"))
    }

    async fn do_action_fallback(
        &self,
        request: Request<Action>,
    ) -> Result<Response<<Self as FlightService>::DoActionStream>, Status> {
        let ctx = request
            .extensions()
            .get::<AuthContext>()
            .ok_or(Status::unauthenticated("no auth context"))?
            .clone();

        let action = request.into_inner();
        match action.r#type.as_str() {
            "revoke_self" => {
                self.revocations.revoke(ctx.jti.clone());
                let out = arrow_flight::Result {
                    body: Bytes::from_static(b"revoked"),
                };
                Ok(Response::new(Box::pin(stream::once(async { Ok(out) }))))
            }
            other => Err(Status::unimplemented(format!("unknown action: {other}"))),
        }
    }

    #[allow(clippy::unused_async)]
    async fn list_custom_actions(&self) -> Option<Vec<Result<ActionType, Status>>> {
        Some(vec![Ok(ActionType {
            r#type: "revoke_self".into(),
            description: "Revoke the current JWT (by jti)".into(),
        })])
    }

    async fn do_action_create_prepared_statement(
        &self,
        _query: ActionCreatePreparedStatementRequest,
        _request: Request<Action>,
    ) -> Result<ActionCreatePreparedStatementResult, Status> {
        Err(Status::unimplemented("do_get_fallback not implemented"))
    }

    async fn do_action_close_prepared_statement(
        &self,
        _query: ActionClosePreparedStatementRequest,
        _request: Request<Action>,
    ) -> Result<(), Status> {
        Err(Status::unimplemented("do_get_fallback not implemented"))
    }

    async fn do_action_create_prepared_substrait_plan(
        &self,
        _query: ActionCreatePreparedSubstraitPlanRequest,
        _request: Request<Action>,
    ) -> Result<ActionCreatePreparedStatementResult, Status> {
        Err(Status::unimplemented("do_get_fallback not implemented"))
    }

    async fn do_action_begin_transaction(
        &self,
        _query: ActionBeginTransactionRequest,
        _request: Request<Action>,
    ) -> Result<ActionBeginTransactionResult, Status> {
        Err(Status::unimplemented("do_get_fallback not implemented"))
    }

    async fn do_action_end_transaction(
        &self,
        _query: ActionEndTransactionRequest,
        _request: Request<Action>,
    ) -> Result<(), Status> {
        Err(Status::unimplemented("do_get_fallback not implemented"))
    }

    async fn do_action_begin_savepoint(
        &self,
        _query: ActionBeginSavepointRequest,
        _request: Request<Action>,
    ) -> Result<ActionBeginSavepointResult, Status> {
        Err(Status::unimplemented("do_get_fallback not implemented"))
    }

    async fn do_action_end_savepoint(
        &self,
        _query: ActionEndSavepointRequest,
        _request: Request<Action>,
    ) -> Result<(), Status> {
        Err(Status::unimplemented("do_get_fallback not implemented"))
    }

    async fn do_action_cancel_query(
        &self,
        _query: ActionCancelQueryRequest,
        _request: Request<Action>,
    ) -> Result<ActionCancelQueryResult, Status> {
        Err(Status::unimplemented("do_get_fallback not implemented"))
    }

    async fn do_exchange_fallback(
        &self,
        _request: Request<Streaming<FlightData>>,
    ) -> Result<Response<<Self as FlightService>::DoExchangeStream>, Status> {
        Err(Status::unimplemented("do_get_fallback not implemented"))
    }

    async fn register_sql_info(&self, id: i32, result: &SqlInfo) {
        // Err(Status::unimplemented("do_get_fallback not implemented"))
    }
}

fn internal<E: std::fmt::Display>(e: E) -> Status {
    Status::internal(e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{Claims, HandshakeCreds, get_jwt_secret};
    use arrow_flight::HandshakeRequest;
    use arrow_flight::flight_service_client::FlightServiceClient;
    use arrow_flight::flight_service_server::FlightServiceServer;
    use futures::StreamExt;
    use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
    use serde_json;
    use std::net::SocketAddr;
    use tokio::net::TcpListener;
    use tokio::task::JoinHandle;
    use tonic::codegen::Bytes;
    use tonic::transport::Server;

    pub fn create_test_service() -> SqlRouterService {
        SqlRouterService::new(
            "test-issuer".to_string(),
            "test-audience".to_string(),
            DbRouter::default(),
        )
    }

    pub async fn start_test_server() -> (u16, JoinHandle<()>) {
        // Bind to random free port
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        let port = addr.port();

        let svc = create_test_service();

        // Spawn server task
        let handle = tokio::spawn(async move {
            Server::builder()
                .add_service(FlightServiceServer::new(svc))
                .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
                .await
                .expect("server crashed");
        });

        (port, handle)
    }

    #[tokio::test]
    pub async fn test_successful_handshake() {
        let (port, handle) = start_test_server().await;
        let mut client = FlightServiceClient::connect(format!("http://127.0.0.1:{}", port))
            .await
            .expect("failed to connect to server");

        // Create a request stream with one HandshakeRequest
        let creds = HandshakeCreds {
            username: "alice".into(),
            password: "secret1".into(),
        };
        let payload = serde_json::to_vec(&creds).unwrap();

        let req_stream = tokio_stream::iter(vec![HandshakeRequest {
            protocol_version: 0,
            payload: Bytes::from(payload),
        }]);

        let response = client
            .handshake(tonic::Request::new(req_stream))
            .await
            .unwrap();
        let mut stream = response.into_inner();
        let resp = stream.next().await.unwrap().unwrap();
        let token = String::from_utf8(resp.payload.to_vec()).unwrap();

        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_audience(&["test-audience"]);
        validation.set_issuer(&["test-issuer"]);

        let decoded = decode::<Claims>(
            &token,
            &DecodingKey::from_secret(get_jwt_secret()),
            &validation,
        )
        .expect("failed to decode JWT");

        assert_eq!(decoded.claims.sub, "alice");
        assert_eq!(decoded.claims.tid, "tenant_acme");
        assert_eq!(decoded.claims.roles, vec!["reader", "analyst"]);

        handle.abort();
    }

    #[tokio::test]
    pub async fn test_handshake_invalid_creds() {
        let (port, handle) = start_test_server().await;
        let mut client = FlightServiceClient::connect(format!("http://127.0.0.1:{}", port))
            .await
            .expect("failed to connect to server");

        let creds = HandshakeCreds {
            username: "alice".into(),
            password: "wrong-password".into(),
        };
        let payload = serde_json::to_vec(&creds).unwrap();

        let req_stream = tokio_stream::iter(vec![HandshakeRequest {
            protocol_version: 0,
            payload: Bytes::from(payload),
        }]);

        let result = client.handshake(tonic::Request::new(req_stream)).await;

        // The server should reject this
        assert!(result.is_err());

        // Optionally check the gRPC status code
        if let Err(status) = result {
            assert_eq!(status.code(), tonic::Code::Unauthenticated);
            assert!(status.message().contains("bad password"));
        }

        handle.abort();
    }

    #[test]
    pub fn test_sql_flight_service_constructor() {
        let service = SqlRouterService::new(
            "test-issuer".to_string(),
            "test-audience".to_string(),
            DbRouter::default(),
        );

        assert_eq!(service.issuer, "test-issuer");
        assert_eq!(service.audience, "test-audience");
        // The revocation list should be empty initially
        assert!(service.revocations.is_empty());
    }
}
