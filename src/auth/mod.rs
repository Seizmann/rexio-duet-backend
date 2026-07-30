//! JWT subject resolution.
//!
//! The proxy layer only verifies that a token is present and structurally valid. The
//! authoritative decode — and therefore the identity every operation acts on — happens
//! here in the real backend, which is the only tier holding the signing secret.

use axum::http::{header, HeaderMap};
use jsonwebtoken::{decode, DecodingKey, Validation};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
}

/// Extracts and verifies the bearer token, returning the subject (user id) on success.
///
/// Returns `None` for any failure — absent header, wrong scheme, bad signature, or
/// expired token. Callers decide whether that is fatal for the requested operation.
pub fn subject_from_headers(headers: &HeaderMap, jwt_secret: &str) -> Option<String> {
    let raw = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let token = raw.strip_prefix("Bearer ")?;

    let mut validation = Validation::default();
    validation.validate_exp = true;

    decode::<Claims>(
        token,
        &DecodingKey::from_secret(jwt_secret.as_bytes()),
        &validation,
    )
    .ok()
    .map(|data| data.claims.sub)
}
