use crate::auth::{AuthContext, RevocationList, validate_jwt_token};
use tonic::{GrpcMethod, Request, Status};

pub fn auth_interceptor(
    revocations: RevocationList,
    issuer: String,
    audience: String,
) -> impl Fn(Request<()>) -> std::result::Result<Request<()>, Status> + Clone {
    move |mut req: Request<()>| {
        let is_handshake = req
            .extensions()
            .get::<GrpcMethod>()
            .map(|m| {
                m.method() == "Handshake" && m.service() == "arrow.flight.protocol.FlightService"
            })
            .unwrap_or(false);

        // Handshake: no token required
        if is_handshake {
            return Ok(req);
        }

        let token = req
            .metadata()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .ok_or_else(|| Status::unauthenticated("missing bearer token"))?;

        let claims = validate_jwt_token(token, &issuer, &audience)
            .map_err(|e| Status::unauthenticated(format!("invalid token: {e}")))?;

        if revocations.is_revoked(&claims.jti) {
            return Err(Status::unauthenticated("token revoked"));
        }

        let ctx = AuthContext {
            user: claims.sub,
            tenant_id: claims.tid,
            roles: claims.roles,
            jti: claims.jti,
        };
        req.extensions_mut().insert(ctx);
        Ok(req)
    }
}
