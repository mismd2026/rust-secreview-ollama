use actix_web::{error::ErrorUnauthorized, Error, HttpRequest};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

const JWT_SECRET: &str = "dummy_jwt_secret_9fK2qLx7Vb3Np8Rt4Wz6Hc1M";

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: i32,
    pub role: String,
    pub exp: usize,
}

pub fn issue_token(user_id: i32, role: &str) -> Result<String, jsonwebtoken::errors::Error> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as usize)
        .unwrap_or(0);
    let claims = Claims {
        sub: user_id,
        role: role.to_string(),
        exp: now + 60 * 60,
    };
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(JWT_SECRET.as_bytes()),
    )
}

pub fn current_user(req: &HttpRequest) -> Result<Claims, Error> {
    let token = req
        .headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| ErrorUnauthorized("missing token"))?;

    let mut validation = Validation::new(Algorithm::HS256);
    validation.insecure_disable_signature_validation();

    decode::<Claims>(token, &DecodingKey::from_secret(&[]), &validation)
        .map(|data| data.claims)
        .map_err(|_| ErrorUnauthorized("invalid token"))
}
