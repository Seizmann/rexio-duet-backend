//! JWT subject resolution.
//!
//! Sessions are access tokens issued by the identity provider, signed **ES256**
//! with a rotating asymmetric key — the project's `JWT_SECRET` is that provider's
//! *legacy* HS256 secret and no longer verifies anything it issues. Verification
//! therefore runs against the published JWKS.
//!
//! The proxy layer only checks that the session cookie looks like a JWT. The
//! authoritative decode — and therefore the identity every operation acts on — happens
//! here in the real backend.

use axum::http::{header, HeaderMap};
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Issued access tokens carry `aud: "authenticated"` for signed-in users. Anonymous
/// and service tokens do not, so requiring it keeps them out of user operations.
const EXPECTED_AUDIENCE: &str = "authenticated";

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
}

/// Verification keys published by the identity provider, indexed by `kid`.
pub type JwtKeys = HashMap<String, DecodingKey>;

/// Fetches the identity provider's JWKS.
///
/// ponytail: fetched once at startup, not cached with a TTL. The provider's signing
/// keys rotate manually and rarely; a rotation needs a container restart. Add
/// background refresh only if rotation ever becomes automatic.
#[allow(dead_code)] // Used by main; invisible to the path-imported test harness.
pub async fn fetch_jwks(client: &reqwest::Client, identity_url: &str) -> Result<JwtKeys, String> {
    let url = format!("{}/auth/v1/.well-known/jwks.json", identity_url.trim_end_matches('/'));

    let set: JwkSet = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("JWKS unreachable at {url}: {e}"))?
        .json()
        .await
        .map_err(|e| format!("JWKS at {url} is not a valid key set: {e}"))?;

    let keys: JwtKeys = set
        .keys
        .iter()
        .filter_map(|jwk| {
            let kid = jwk.common.key_id.clone()?;
            let key = DecodingKey::from_jwk(jwk).ok()?;
            Some((kid, key))
        })
        .collect();

    if keys.is_empty() {
        return Err(format!("JWKS at {url} contained no usable keys"));
    }

    Ok(keys)
}

/// Extracts and verifies the session token, returning the subject (user id) on success.
///
/// The token lives in the `duet_session` cookie — set there by the auth handlers and
/// forwarded by the proxy, which reads the same cookie. No client sends an
/// `Authorization` header.
///
/// Returns `None` for any failure — absent cookie, unknown signing key, bad signature,
/// wrong audience, or expired token. Callers decide whether that is fatal for the
/// requested operation.
pub fn subject_from_headers(headers: &HeaderMap, keys: &JwtKeys) -> Option<String> {
    let token = headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .find_map(|c| c.trim().strip_prefix("duet_session="))?;

    let kid = decode_header(token).ok()?.kid?;
    let key = keys.get(&kid)?;

    let mut validation = Validation::new(Algorithm::ES256);
    validation.validate_exp = true;
    validation.set_audience(&[EXPECTED_AUDIENCE]);

    decode::<Claims>(token, key, &validation)
        .ok()
        .map(|data| data.claims.sub)
}
