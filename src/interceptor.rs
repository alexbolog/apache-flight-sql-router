use crate::auth::{AuthContext, RevocationList, validate_jwt_token};
use tonic::{Request, Status};

pub fn auth_interceptor(
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
