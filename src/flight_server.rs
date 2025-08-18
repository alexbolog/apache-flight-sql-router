use std::collections::HashSet;
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use argon2::PasswordHasher;
use arrow_flight::flight_service_server::FlightService;
use arrow_flight::*;
use futures::{Stream, StreamExt};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use once_cell::sync::Lazy;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use tonic::{Request, Response, Status, Streaming};
use tracing::info;
use std::result::Result;

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
    let salt = argon2::password_hash::SaltString::from_b64("dGVzdHNhbHQ=").unwrap(); // "testsalt" in base64
    
    let hash1 = argon2::Argon2::default()
        .hash_password(
            "secret1".as_bytes(),
            &salt,
        )
        .unwrap()
        .to_string();
    let hash2 = argon2::Argon2::default()
        .hash_password(
            "secret2".as_bytes(),
            &salt,
        )
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

#[derive(Debug, Deserialize)]
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
        let jti = uuid_like();
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

    type DoActionStream = Pin<Box<dyn Stream<Item = Result<arrow_flight::Result, Status>> + Send + 'static>>;
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
}


fn auth_interceptor(revocations: RevocationList, issuer: String, audience: String) -> impl Fn(Request<()>) -> std::result::Result<Request<()>, Status> + Clone {
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

        let data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(&*JWT_SECRET),
            &validation,
        )
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

fn uuid_like() -> String {
    // Not a real UUID to keep deps minimal; fine for demo jti.
    use rand::Rng;
    let mut rng = rand::rng();
    let parts: [u32; 4] = [rng.random(), rng.random(), rng.random(), rng.random()];
    format!("{:08x}{:08x}{:08x}{:08x}", parts[0], parts[1], parts[2], parts[3])
}
