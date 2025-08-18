use argon2::PasswordHasher;
use arrow_flight::flight_service_server::FlightService;
use arrow_flight::*;
use futures::{Stream, StreamExt};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use once_cell::sync::Lazy;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::pin::Pin;
use std::result::Result;
use std::sync::{Arc, RwLock};
use tonic::{Request, Response, Status, Streaming};
use tracing::info;
use uuid::Uuid;

#[derive(Clone, Debug)]
struct Account {
    username: String,
    // Argon2 hash of password
    pwd_hash: String,
    tenant_id: String,
    roles: Vec<String>,
}

static ACCOUNTS: Lazy<Vec<Account>> = Lazy::new(|| {
    // Passwords: "secret1", "secret2" (hashed with argon2)
    // Use a fixed salt for demo purposes to avoid rand version conflicts
    let salt = argon2::password_hash::SaltString::from_b64("dGVzdHNhbHQ").unwrap(); // "testsalt" in base64 (without padding)

    let hash1 = argon2::Argon2::default()
        .hash_password("secret1".as_bytes(), &salt)
        .unwrap()
        .to_string();
    let hash2 = argon2::Argon2::default()
        .hash_password("secret2".as_bytes(), &salt)
        .unwrap()
        .to_string();

    vec![
        Account {
            username: "alice".into(),
            pwd_hash: hash1,
            tenant_id: "tenant_acme".into(),
            roles: vec!["reader".into(), "analyst".into()],
        },
        Account {
            username: "bob".into(),
            pwd_hash: hash2,
            tenant_id: "tenant_beta".into(),
            roles: vec!["reader".into()],
        },
    ]
});

// Hardcoded symmetric key (HS256) for demo. In production prefer EdDSA/RS256.
static JWT_SECRET: Lazy<[u8; 32]> = Lazy::new(|| {
    // For demo we generate at boot; for real deployments, inject via env/secret store and rotate.
    let mut key = [0u8; 32];
    rand::rng().fill_bytes(&mut key);
    key
});

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String, // username or user id
    tid: String, // tenant id
    roles: Vec<String>,
    exp: usize,
    iat: usize,
    jti: String,
    iss: String,
    aud: String,
}

#[derive(Clone, Debug)]
struct AuthContext {
    user: String,
    tenant_id: String,
    roles: Vec<String>,
    jti: String,
}

// In-memory denylist for token revocation (opaque-like control for demo)
#[derive(Default, Clone)]
struct RevocationList(Arc<RwLock<HashSet<String>>>);
impl RevocationList {
    fn revoke(&self, jti: String) {
        self.0.write().unwrap().insert(jti);
    }
    fn is_revoked(&self, jti: &str) -> bool {
        self.0.read().unwrap().contains(jti)
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct HandshakeCreds {
    username: String,
    password: String,
}

pub struct MyFlightService {
    issuer: String,
    audience: String,
    revocations: RevocationList,
}

impl MyFlightService {
    pub fn new(issuer: String, audience: String) -> Self {
        Self {
            issuer,
            audience,
            revocations: RevocationList::default(),
        }
    }
}

use async_trait::async_trait;
use arrow_array::RecordBatch;
use arrow_schema::SchemaRef;

pub type BatchStream =
Pin<Box<dyn Stream<Item = anyhow::Result<RecordBatch>> + Send + 'static>>;

#[async_trait]
pub trait SqlBackend: Send + Sync {
    fn name(&self) -> &'static str;

    /// Discover the Arrow schema for a SQL statement.
    async fn schema(&self, sql: &str, ctx: &AuthContext) -> anyhow::Result<SchemaRef>;

    /// Execute and stream Arrow record batches.
    async fn query(&self, sql: &str, ctx: &AuthContext) -> anyhow::Result<BatchStream>;
}


#[tonic::async_trait]
impl FlightService for MyFlightService {
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
        let acct = ACCOUNTS
            .iter()
            .find(|a| a.username == creds.username)
            .ok_or_else(|| Status::unauthenticated("unknown user"))?;

        use argon2::password_hash::{PasswordHash, PasswordVerifier};
        let parsed = PasswordHash::new(&acct.pwd_hash).map_err(|_| Status::internal("bad hash"))?;
        argon2::Argon2::default()
            .verify_password(creds.password.as_bytes(), &parsed)
            .map_err(|_| Status::unauthenticated("bad password"))?;

        // Issue JWT (HS256 for demo)
        let now = chrono::Utc::now().timestamp() as usize;
        let jti = Uuid::new_v4().to_string();

        let claims = Claims {
            sub: acct.username.clone(),
            tid: acct.tenant_id.clone(),
            roles: acct.roles.clone(),
            iat: now,
            exp: now + 10 * 60, // 10 minutes
            jti: jti.clone(),
            iss: self.issuer.clone(),
            aud: self.audience.clone(),
        };
        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(&*JWT_SECRET),
        )
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

fn auth_interceptor(
    revocations: RevocationList,
    issuer: String,
    audience: String,
) -> impl Fn(Request<()>) -> std::result::Result<Request<()>, Status> + Clone {
    move |mut req: Request<()>| {
        // For now, allow all requests through since we can't easily check the method
        // In a real implementation, you'd want to check the gRPC method name
        // This is a simplified version for demo purposes

        let token = req
            .metadata()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .ok_or_else(|| Status::unauthenticated("missing bearer token"))?;

        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_audience(&[audience.as_str()]);
        validation.set_issuer(&[issuer.as_str()]);

        let data = decode::<Claims>(token, &DecodingKey::from_secret(&*JWT_SECRET), &validation)
            .map_err(|e| Status::unauthenticated(format!("invalid token: {e}")))?;

        if revocations.is_revoked(&data.claims.jti) {
            return Err(Status::unauthenticated("token revoked"));
        }

        let ctx = AuthContext {
            user: data.claims.sub,
            tenant_id: data.claims.tid,
            roles: data.claims.roles,
            jti: data.claims.jti,
        };
        req.extensions_mut().insert(ctx);
        Ok(req)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arrow_flight::flight_service_client::FlightServiceClient;
    use arrow_flight::flight_service_server::FlightServiceServer;
    use serde_json;
    use std::net::SocketAddr;
    use tokio::net::TcpListener;
    use tokio::task::JoinHandle;
    use tonic::codegen::Bytes;
    use tonic::transport::Server;

    fn create_test_service() -> MyFlightService {
        MyFlightService::new("test-issuer".to_string(), "test-audience".to_string())
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
    async fn test_successful_handshake() {
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

        let response = client.handshake(Request::new(req_stream)).await.unwrap();
        let mut stream = response.into_inner();
        let resp = stream.next().await.unwrap().unwrap();
        let token = String::from_utf8(resp.payload.to_vec()).unwrap();

        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_audience(&["test-audience"]);
        validation.set_issuer(&["test-issuer"]);

        let decoded =
            decode::<Claims>(&token, &DecodingKey::from_secret(&*JWT_SECRET), &validation)
                .expect("failed to decode JWT");

        assert_eq!(decoded.claims.sub, "alice");
        assert_eq!(decoded.claims.tid, "tenant_acme");
        assert_eq!(decoded.claims.roles, vec!["reader", "analyst"]);

        handle.abort();
    }

    #[tokio::test]
    async fn test_handshake_invalid_creds() {
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

        let result = client.handshake(Request::new(req_stream)).await;

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
    fn test_password_verification() {
        // Test that password verification works correctly
        let alice = ACCOUNTS.iter().find(|a| a.username == "alice").unwrap();

        // Test correct password
        use argon2::password_hash::{PasswordHash, PasswordVerifier};
        let parsed = PasswordHash::new(&alice.pwd_hash).unwrap();
        let result = argon2::Argon2::default().verify_password("secret1".as_bytes(), &parsed);
        assert!(result.is_ok());

        // Test incorrect password
        let result = argon2::Argon2::default().verify_password("wrongpassword".as_bytes(), &parsed);
        assert!(result.is_err());
    }

    #[test]
    fn test_revocation_list() {
        let revocations = RevocationList::default();

        // Initially no tokens are revoked
        assert!(!revocations.is_revoked("token1"));

        // Revoke a token
        revocations.revoke("token1".to_string());
        assert!(revocations.is_revoked("token1"));

        // Other tokens are still not revoked
        assert!(!revocations.is_revoked("token2"));

        // Revoke another token
        revocations.revoke("token2".to_string());
        assert!(revocations.is_revoked("token2"));
    }

    #[test]
    fn test_myflight_service_constructor() {
        let service = MyFlightService::new("test-issuer".to_string(), "test-audience".to_string());

        assert_eq!(service.issuer, "test-issuer");
        assert_eq!(service.audience, "test-audience");
        // The revocation list should be empty initially
        assert!(service.revocations.0.read().unwrap().is_empty());
    }
}
