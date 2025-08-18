use arrow_flight::flight_service_server::FlightService;
use arrow_flight::*;
use futures::{Stream, StreamExt};
use serde_json;
use std::pin::Pin;
use std::result::Result;
use tonic::{Request, Response, Status, Streaming};
use tracing::info;

use crate::auth::{AuthContext, HandshakeCreds, RevocationList, create_jwt_token, verify_password};

pub struct DmFlightService {
    pub issuer: String,
    pub audience: String,
    pub revocations: RevocationList,
}

impl DmFlightService {
    pub fn new(issuer: String, audience: String) -> Self {
        Self {
            issuer,
            audience,
            revocations: RevocationList::default(),
        }
    }
}

#[tonic::async_trait]
impl FlightService for DmFlightService {
    type HandshakeStream =
        Pin<Box<dyn Stream<Item = Result<HandshakeResponse, Status>> + Send + 'static>>;

    async fn handshake(
        &self,
        mut request: Request<Streaming<HandshakeRequest>>,
    ) -> Result<Response<Self::HandshakeStream>, Status> {
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

    type ListFlightsStream =
        Pin<Box<dyn Stream<Item = Result<FlightInfo, Status>> + Send + 'static>>;
    async fn list_flights(
        &self,
        _request: Request<Criteria>,
    ) -> Result<Response<Self::ListFlightsStream>, Status> {
        let s = futures::stream::empty();
        Ok(Response::new(Box::pin(s)))
    }

    async fn get_flight_info(
        &self,
        request: Request<FlightDescriptor>,
    ) -> Result<Response<FlightInfo>, Status> {
        let ctx = request
            .extensions()
            .get::<AuthContext>()
            .ok_or_else(|| Status::internal("missing auth context"))?;
        info!(user = %ctx.user, tenant = %ctx.tenant_id, roles = ?ctx.roles, "get_flight_info");
        // For demo we return a stub FlightInfo. Real code: parse descriptor SQL, plan, etc.
        let endpoint = FlightEndpoint {
            ticket: Some(Ticket {
                ticket: b"demo".to_vec().into(),
            }),
            location: vec![],
            app_metadata: vec![].into(),
            expiration_time: None,
        };
        let info = FlightInfo {
            schema: vec![].into(),
            flight_descriptor: None,
            endpoint: vec![endpoint],
            total_records: -1,
            total_bytes: -1,
            app_metadata: vec![].into(),
            ordered: false,
        }; // schema omitted for brevity
        Ok(Response::new(info))
    }

    async fn poll_flight_info(
        &self,
        _request: Request<FlightDescriptor>,
    ) -> Result<Response<PollInfo>, Status> {
        Err(Status::unimplemented("poll_flight_info"))
    }

    async fn get_schema(
        &self,
        _request: Request<FlightDescriptor>,
    ) -> Result<Response<SchemaResult>, Status> {
        Err(Status::unimplemented("get_schema"))
    }

    type DoGetStream = Pin<Box<dyn Stream<Item = Result<FlightData, Status>> + Send + 'static>>;
    async fn do_get(
        &self,
        request: Request<Ticket>,
    ) -> Result<Response<Self::DoGetStream>, Status> {
        let ctx = request
            .extensions()
            .get::<AuthContext>()
            .ok_or_else(|| Status::internal("missing auth context"))?;
        info!(user = %ctx.user, tenant = %ctx.tenant_id, "do_get");
        // Stream no data for demo
        let s = futures::stream::empty();
        Ok(Response::new(Box::pin(s)))
    }

    type DoPutStream = Pin<Box<dyn Stream<Item = Result<PutResult, Status>> + Send + 'static>>;
    async fn do_put(
        &self,
        _request: Request<Streaming<FlightData>>,
    ) -> Result<Response<Self::DoPutStream>, Status> {
        let s = futures::stream::empty();
        Ok(Response::new(Box::pin(s)))
    }

    type DoExchangeStream =
        Pin<Box<dyn Stream<Item = Result<FlightData, Status>> + Send + 'static>>;
    async fn do_exchange(
        &self,
        _request: Request<Streaming<FlightData>>,
    ) -> Result<Response<Self::DoExchangeStream>, Status> {
        let s = futures::stream::empty();
        Ok(Response::new(Box::pin(s)))
    }

    type DoActionStream =
        Pin<Box<dyn Stream<Item = Result<arrow_flight::Result, Status>> + Send + 'static>>;
    async fn do_action(
        &self,
        request: Request<Action>,
    ) -> Result<Response<Self::DoActionStream>, Status> {
        // Demo action: revoke current token by jti (requires auth, see interceptor)
        let ctx = request
            .extensions()
            .get::<AuthContext>()
            .ok_or_else(|| Status::unauthenticated("no auth"))?;
        self.revocations.revoke(ctx.jti.clone());
        let body = arrow_flight::Result {
            body: b"revoked".to_vec().into(),
        };
        let s = futures::stream::once(async move { Ok(body) });
        Ok(Response::new(Box::pin(s)))
    }

    type ListActionsStream =
        Pin<Box<dyn Stream<Item = Result<ActionType, Status>> + Send + 'static>>;
    async fn list_actions(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<Self::ListActionsStream>, Status> {
        let s = futures::stream::once(async move {
            Ok(ActionType {
                r#type: "revoke_self".into(),
                description: "Revoke the current token".into(),
            })
        });
        Ok(Response::new(Box::pin(s)))
    }
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

    pub fn create_test_service() -> DmFlightService {
        DmFlightService::new("test-issuer".to_string(), "test-audience".to_string())
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
    pub fn test_myflight_service_constructor() {
        let service = DmFlightService::new("test-issuer".to_string(), "test-audience".to_string());

        assert_eq!(service.issuer, "test-issuer");
        assert_eq!(service.audience, "test-audience");
        // The revocation list should be empty initially
        assert!(service.revocations.is_empty());
    }
}
