use argon2::PasswordHasher;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use once_cell::sync::Lazy;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::{Arc, RwLock};
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct Account {
    pub username: String,
    // Argon2 hash of password
    pub pwd_hash: String,
    pub tenant_id: String,
    pub roles: Vec<String>,
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
pub struct Claims {
    pub sub: String, // username or user id
    pub tid: String, // tenant id
    pub roles: Vec<String>,
    pub exp: usize,
    pub iat: usize,
    pub jti: String,
    pub iss: String,
    pub aud: String,
}

#[derive(Clone, Debug)]
pub struct AuthContext {
    pub user: String,
    pub tenant_id: String,
    pub roles: Vec<String>,
    pub jti: String,
}

// In-memory denylist for token revocation (opaque-like control for demo)
#[derive(Default, Clone)]
pub struct RevocationList(Arc<RwLock<HashSet<String>>>);

impl RevocationList {
    pub fn revoke(&self, jti: String) {
        self.0.write().unwrap().insert(jti);
    }
    
    pub fn is_revoked(&self, jti: &str) -> bool {
        self.0.read().unwrap().contains(jti)
    }

    pub fn is_empty(&self) -> bool {
        self.0.read().unwrap().is_empty()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HandshakeCreds {
    pub username: String,
    pub password: String,
}

pub fn get_accounts() -> &'static Vec<Account> {
    &ACCOUNTS
}

pub fn get_jwt_secret() -> &'static [u8; 32] {
    &JWT_SECRET
}

pub fn verify_password(username: &str, password: &str) -> Result<Account, String> {
    let acct = ACCOUNTS
        .iter()
        .find(|a| a.username == username)
        .ok_or("unknown user")?;

    use argon2::password_hash::{PasswordHash, PasswordVerifier};
    let parsed = PasswordHash::new(&acct.pwd_hash).map_err(|_| "bad hash")?;
    argon2::Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .map_err(|_| "bad password")?;

    Ok(acct.clone())
}

pub fn create_jwt_token(
    account: &Account,
    issuer: &str,
    audience: &str,
) -> Result<String, jsonwebtoken::errors::Error> {
    let now = chrono::Utc::now().timestamp() as usize;
    let jti = Uuid::new_v4().to_string();

    let claims = Claims {
        sub: account.username.clone(),
        tid: account.tenant_id.clone(),
        roles: account.roles.clone(),
        iat: now,
        exp: now + 10 * 60, // 10 minutes
        jti: jti.clone(),
        iss: issuer.to_string(),
        aud: audience.to_string(),
    };

    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(&*JWT_SECRET),
    )
}

pub fn validate_jwt_token(
    token: &str,
    issuer: &str,
    audience: &str,
) -> Result<Claims, jsonwebtoken::errors::Error> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_audience(&[audience]);
    validation.set_issuer(&[issuer]);

    let data = decode::<Claims>(token, &DecodingKey::from_secret(&*JWT_SECRET), &validation)?;
    Ok(data.claims)
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
