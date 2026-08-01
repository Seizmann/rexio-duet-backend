//! Backend security checks.
//!
//! These cover the security-critical paths added with the encrypted gateway: payload
//! confidentiality, tamper rejection, signature verification, and password hashing.
//!
//! The modules under test are pulled in by path rather than through a library target,
//! since this crate ships as a binary. Both are self-contained and touch no shared
//! application state. Written with RexiO Code, powered by RexiO Prothom 1.5.

#[path = "../src/crypto/mod.rs"]
mod crypto;
#[path = "../src/password/mod.rs"]
mod password;
#[path = "../src/auth/mod.rs"]
mod auth;

use auth::{subject_from_headers, JwtKeys};
use axum::http::{header, HeaderMap};
use crypto::{compute_signature, verify_signature, PayloadCipher};
use password::{hash_password, verify_password};

/// Test-only key material — deliberately not a value any environment uses.
///
/// These two constants previously held the live `GATEWAY_PAYLOAD_KEY` and
/// `GATEWAY_SIGNING_KEY` verbatim, which put the keys that seal every gateway
/// payload into the Git history of a repository that publishes container images.
/// Both were rotated; the replacements below exist only here and unlock nothing.
const TEST_KEY: &str = "ojtxuEvjhv8RP2DXbG+e6Umfiuju8v93adQUvN/r3pI=";
const OTHER_KEY: &str = "9uqiFYOIOEcT5yNQVT9at8rSWaBHwh8PGBmF2aReiho=";

/// Test-only ES256 keypairs. Supabase signs sessions with ES256 against a published
/// JWKS, so the auth path cannot be exercised with a symmetric secret.
const TEST_KID: &str = "test-kid";
const KEY_A_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgNkTDJDWF7rVExavE\nIKDZ1lK3yO2rjzpfUniIXLDI8bqhRANCAATmNIEYzSwXf3H2LBp/a3AbDSt/yVlH\n5dzBrADx19222qIlVMWpCKiZM1Izl+DUa7DrUEEDLa/ULd4OAPxfrqRZ\n-----END PRIVATE KEY-----\n";
const KEY_A_X: &str = "5jSBGM0sF39x9iwaf2twGw0rf8lZR-XcwawA8dfdtto";
const KEY_A_Y: &str = "oiVUxakIqJkzUjOX4NRrsOtQQQMtr9Qt3g4A_F-upFk";
const KEY_B_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgRic9BdlRE8XA4YLN\nZATB3UCChyJHZRf/PRAhF6GndYGhRANCAAQOMeWJjb/UPNmM5ztUm3IO2WLmvL7a\neX+deErRKYFci4xECDfTk22KFz95OzWzcUEbFnXFi8duYMXhz+bHEAbl\n-----END PRIVATE KEY-----\n";

fn signing_key(pem: &str) -> jsonwebtoken::EncodingKey {
    jsonwebtoken::EncodingKey::from_ec_pem(pem.as_bytes()).expect("valid EC private key")
}

/// The published verification key set, as the backend would load it from JWKS.
fn published_keys() -> JwtKeys {
    let key = jsonwebtoken::DecodingKey::from_ec_components(KEY_A_X, KEY_A_Y).expect("valid EC point");
    JwtKeys::from([(TEST_KID.to_string(), key)])
}

fn cipher() -> PayloadCipher {
    PayloadCipher::from_base64_key(TEST_KEY).expect("valid test key")
}

#[test]
fn sealed_payload_roundtrips() {
    let plaintext = br#"{"op":"v2","data":{"raw_vent_text":"I felt unheard today"}}"#;
    let sealed = cipher().seal(plaintext).expect("seal");
    let opened = cipher().open(&sealed).expect("open");
    assert_eq!(opened, plaintext);
}

#[test]
fn wire_format_leaks_no_plaintext() {
    // The whole point of the gateway: an observer must not read field names or values.
    let sealed = cipher()
        .seal(br#"{"op":"v2","data":{"raw_vent_text":"secret confession"}}"#)
        .expect("seal");
    for leak in ["raw_vent_text", "secret confession"] {
        assert!(!sealed.contains(leak), "`{leak}` visible in encrypted blob");
    }
}

#[test]
fn same_plaintext_produces_different_blobs() {
    // A fresh nonce per call: identical requests must not be correlatable on the wire.
    let c = cipher();
    assert_ne!(
        c.seal(b"identical").expect("seal"),
        c.seal(b"identical").expect("seal")
    );
}

#[test]
fn tampered_payload_is_rejected() {
    let sealed = cipher().seal(b"authentic payload").expect("seal");

    // Flip a character mid-blob — the Poly1305 tag must catch it rather than
    // yielding partially-decrypted garbage.
    let mut chars: Vec<char> = sealed.chars().collect();
    let mid = chars.len() / 2;
    chars[mid] = if chars[mid] == 'A' { 'B' } else { 'A' };
    let tampered: String = chars.into_iter().collect();

    assert!(cipher().open(&tampered).is_err(), "tampered blob decrypted");
}

#[test]
fn wrong_key_cannot_open_payload() {
    let sealed = cipher().seal(b"for the gateway key only").expect("seal");
    let other = PayloadCipher::from_base64_key(OTHER_KEY).expect("valid key");
    assert!(other.open(&sealed).is_err(), "foreign key decrypted payload");
}

#[test]
fn truncated_and_garbage_input_fail_closed() {
    for bad in ["", "!!!not-base64!!!", "AAAA"] {
        assert!(cipher().open(bad).is_err(), "`{bad}` was accepted");
    }
}

#[test]
fn short_and_malformed_keys_are_refused() {
    // Silently accepting a wrong-length key would weaken every payload.
    for bad in ["", "c2hvcnQ=", "not-base64"] {
        assert!(
            PayloadCipher::from_base64_key(bad).is_err(),
            "`{bad}` accepted as a key"
        );
    }
}

#[test]
fn signature_verifies_only_for_matching_body_and_key() {
    let body = br#"{"op":"a1"}"#;
    let sig = compute_signature("signing-key", body).expect("sign");

    assert!(verify_signature("signing-key", body, &sig).is_ok());
    // Body swapped under a previously valid signature.
    assert!(verify_signature("signing-key", br#"{"op":"v2"}"#, &sig).is_err());
    // Correct body, attacker's key.
    assert!(verify_signature("wrong-key", body, &sig).is_err());
    // Absent or malformed signatures must not pass.
    assert!(verify_signature("signing-key", body, "").is_err());
    assert!(verify_signature("signing-key", body, "zz").is_err());
}

#[test]
fn passwords_are_hashed_not_stored() {
    let password = "DUET-correct-horse-battery";
    let hash = hash_password(password).expect("hash");

    assert!(!hash.contains(password), "password recoverable from hash");
    assert!(hash.starts_with("$argon2"), "unexpected hash format: {hash}");
    assert!(verify_password(password, &hash));
    assert!(!verify_password("wrong-password", &hash));

    // Distinct salts: two users with the same password must not share a hash.
    assert_ne!(hash, hash_password(password).expect("hash"));
}

/// The session token travels in the `duet_session` cookie — no client sends an
/// `Authorization` header. Reading the wrong header made every authenticated op
/// return 401, so a logged-in user always fell through to the landing page.
///
/// Signed here with ES256 because that is what Supabase issues; the project's
/// `JWT_SECRET` is its legacy HS256 secret and verifies none of its tokens.
#[test]
fn subject_is_read_from_the_session_cookie() {
    let encoding = signing_key(KEY_A_PEM);
    let keys = published_keys();
    let sub = "8f2a1c40-0000-4000-8000-000000000001";

    let sign = |claims: serde_json::Value| {
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
        header.kid = Some(TEST_KID.to_string());
        jsonwebtoken::encode(&header, &claims, &encoding).expect("encode")
    };
    let valid = sign(serde_json::json!({ "sub": sub, "aud": "authenticated", "exp": 4_102_444_800u64 }));

    let subject_for = |cookie: &str| {
        let mut headers = HeaderMap::new();
        headers.insert(header::COOKIE, cookie.parse().unwrap());
        subject_from_headers(&headers, &keys)
    };

    assert_eq!(subject_for(&format!("duet_session={valid}")).as_deref(), Some(sub));
    // Real browsers send it alongside the CSRF cookie, in either order.
    assert_eq!(
        subject_for(&format!("csrf_token=abc; duet_session={valid}")).as_deref(),
        Some(sub)
    );

    assert_eq!(subject_for("csrf_token=abc"), None, "no session cookie");
    assert_eq!(subject_for("duet_session=garbage"), None, "malformed token");
    assert_eq!(subject_from_headers(&HeaderMap::new(), &keys), None, "no cookie header");

    // Expired.
    let expired = sign(serde_json::json!({ "sub": sub, "aud": "authenticated", "exp": 1_600_000_000u64 }));
    assert_eq!(subject_for(&format!("duet_session={expired}")), None, "expired token accepted");

    // Wrong audience: service and anonymous tokens must not pass as a user.
    let wrong_aud = sign(serde_json::json!({ "sub": sub, "aud": "service_role", "exp": 4_102_444_800u64 }));
    assert_eq!(subject_for(&format!("duet_session={wrong_aud}")), None, "wrong audience accepted");

    // Signed by an attacker's key, under a kid we do publish.
    let attacker = signing_key(KEY_B_PEM);
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
    header.kid = Some(TEST_KID.to_string());
    let forged = jsonwebtoken::encode(
        &header,
        &serde_json::json!({ "sub": sub, "aud": "authenticated", "exp": 4_102_444_800u64 }),
        &attacker,
    )
    .expect("encode");
    assert_eq!(subject_for(&format!("duet_session={forged}")), None, "forged signature accepted");
}
