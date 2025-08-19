use crate::auth::{AuthContext, RevocationList, validate_jwt_token};
use std::sync::Arc;

pub fn auth_interceptor(
    revocations: Arc<RevocationList>,
    issuer: String,
    audience: String,
) -> impl Fn(tonic::Request<()>) -> Result<tonic::Request<()>, tonic::Status> + Clone {
    move |mut req| {
        // no auth header? let the service method decide (handshake succeeds, others fail)
        let Some(h) = req.metadata().get("authorization") else {
            return Ok(req);
        };
        let Ok(h) = h.to_str() else { return Ok(req) };
        let Some(token) = h.strip_prefix("Bearer ") else {
            return Ok(req);
        };

        let claims = validate_jwt_token(token, &issuer, &audience)
            .map_err(|e| tonic::Status::unauthenticated(format!("invalid token: {e}")))?;
        if revocations.is_revoked(&claims.jti) {
            return Err(tonic::Status::unauthenticated("token revoked"));
        }

        req.extensions_mut().insert(AuthContext {
            user: claims.sub,
            tenant_id: claims.tid,
            roles: claims.roles,
            jti: claims.jti,
        });
        Ok(req)
    }
}
