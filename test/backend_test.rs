//! Backend security checks.
//!
//! These cover the security-critical paths added with the encrypted gateway: payload
//! confidentiality, tamper rejection, signature verification, and session decoding.
//!
//! The modules under test are pulled in by path rather than through a library target,
//! since this crate ships as a binary. Both are self-contained and touch no shared
//! application state. Written with RexiO Code, powered by RexiO Prothom 1.5.

#[path = "../src/crypto/mod.rs"]
mod crypto;
#[path = "../src/auth/mod.rs"]
mod auth;

// Only the response parser is exercised here — the request path needs a
// database-resolved config this suite deliberately does without. The parser is a pure
// function over a body precisely so it can be tested offline; the rest of the module
// comes along with the path import and reads as dead code from here.
#[allow(dead_code, unused_imports)]
#[path = "../src/ai/mod.rs"]
mod ai;

use ai::{parse_completion, AiError};
use auth::{subject_from_headers, JwtKeys};
use axum::http::{header, HeaderMap};
use crypto::{compute_signature, verify_signature, PayloadCipher};

/// Test-only key material — deliberately not a value any environment uses.
///
/// These two constants previously held the live `GATEWAY_PAYLOAD_KEY` and
/// `GATEWAY_SIGNING_KEY` verbatim, which put the keys that seal every gateway
/// payload into the Git history of a repository that publishes container images.
/// Both were rotated; the replacements below exist only here and unlock nothing.
const TEST_KEY: &str = "ojtxuEvjhv8RP2DXbG+e6Umfiuju8v93adQUvN/r3pI=";
const OTHER_KEY: &str = "9uqiFYOIOEcT5yNQVT9at8rSWaBHwh8PGBmF2aReiho=";

/// Test-only ES256 keypairs. Sessions are signed with ES256 against a published
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

/// The session token travels in the `duet_session` cookie — no client sends an
/// `Authorization` header. Reading the wrong header made every authenticated op
/// return 401, so a logged-in user always fell through to the landing page.
///
/// Signed here with ES256 because that is what the identity provider issues; the
/// project's `JWT_SECRET` is its legacy HS256 secret and verifies none of its tokens.
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

/// Reads every Rust source file under `src/`.
///
/// The two checks below are assertions about the source itself, not about runtime
/// behaviour. They live here because the alternative — importing the modules by path
/// — would drag in `AppState` and with it a database connection, which this suite
/// deliberately does without.
fn source_files() -> Vec<(std::path::PathBuf, String)> {
    fn walk(dir: &std::path::Path, out: &mut Vec<(std::path::PathBuf, String)>) {
        for entry in std::fs::read_dir(dir).expect("readable source directory") {
            let path = entry.expect("readable entry").path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                let text = std::fs::read_to_string(&path).expect("readable source file");
                out.push((path, text));
            }
        }
    }
    let mut out = Vec::new();
    walk(std::path::Path::new("src"), &mut out);
    assert!(!out.is_empty(), "found no source files to check");
    out
}

/// The profile row is written on a path that cannot be rolled back: the identity
/// record already exists by the time the insert runs, and the same insert runs again
/// as a back-fill whenever a session finds no profile. Both depend on repeating the
/// insert being harmless, so the conflict clause is load-bearing rather than
/// defensive.
#[test]
fn profile_insert_is_idempotent() {
    let profile = std::fs::read_to_string("src/profile/mod.rs").expect("profile module");
    let sql_start = profile.find("INSERT_PROFILE_SQL").expect("insert statement is a named const");
    let sql = &profile[sql_start..];

    assert!(
        sql.contains("ON CONFLICT (id) DO NOTHING"),
        "the profile insert must be safe to repeat — it runs again as a back-fill",
    );
    assert!(
        profile.contains(".persistent(false)"),
        "queries must be non-persistent: the pooler is transaction-mode",
    );
}

/// AGENTS.md forbids naming the database vendor anywhere in source. The rule had no
/// enforcement, and by the time it was written the code had already broken it in four
/// places. An unenforced rule teaches the next agent to skip the whole file.
#[test]
fn database_vendor_is_not_named_in_source() {
    // The two environment variable names are the documented exception: they are CI and
    // VPS secrets, so renaming them would break every deploy.
    const ALLOWED: [&str; 2] = ["SUPABASE_URL", "SUPABASE_SERVICE_KEY"];

    for (path, text) in source_files() {
        let scrubbed = ALLOWED.iter().fold(text, |acc, name| acc.replace(name, ""));
        assert!(
            !scrubbed.to_lowercase().contains("supabase"),
            "{} names the database vendor — use \"identity provider\", \
             \"Primary SQL Storage\" or \"Isolated Postgres Cluster\"",
            path.display(),
        );
    }
}

// --- Agent response handling ------------------------------------------------------
//
// The bodies below are the live endpoint's real output, recorded while wiring the
// provider up. Both failure cases were observed, not imagined: the default model
// reasons before it answers, and a tight token budget means it never gets as far as
// answering. A parser that shrugs at that stores an empty string as the mediated
// message, and the thing the user typed disappears with no error raised anywhere.

/// Recorded with max_tokens=200. Note the 200 OK, the empty content, and the 200
/// completion tokens spent entirely on reasoning.
const TRUNCATED_BY_BUDGET: &str = r#"{"choices":[{"index":0,"message":{"role":"assistant","content":"","reasoning_content":"We need to rewrite the given message calmly."},"finish_reason":"length"}],"usage":{"prompt_tokens":105,"completion_tokens":200,"total_tokens":305,"completion_tokens_details":{"reasoning_tokens":200}}}"#;

/// The same request with max_tokens=2000.
const COMPLETED: &str = r#"{"choices":[{"index":0,"message":{"role":"assistant","content":"I feel frustrated because I don't feel heard when I speak.","reasoning_content":"The original is an exaggeration; soften it."},"finish_reason":"stop"}],"usage":{"prompt_tokens":105,"completion_tokens":77,"total_tokens":182,"completion_tokens_details":{"reasoning_tokens":63}}}"#;

#[test]
fn budget_truncation_is_a_failure_not_a_partial_answer() {
    assert!(
        matches!(parse_completion(TRUNCATED_BY_BUDGET), Err(AiError::TokenBudgetExhausted)),
        "a completion cut off mid-answer must not be delivered as a message",
    );
}

/// The most important check here. Without it an empty mediated message reaches a real
/// couple, and the sender is told their message was delivered.
#[test]
fn empty_content_is_never_treated_as_a_message() {
    for body in [
        r#"{"choices":[{"message":{"content":""},"finish_reason":"stop"}]}"#,
        r#"{"choices":[{"message":{"content":"   \n  "},"finish_reason":"stop"}]}"#,
        r#"{"choices":[{"message":{"role":"assistant"},"finish_reason":"stop"}]}"#,
    ] {
        assert!(
            matches!(parse_completion(body), Err(AiError::EmptyContent)),
            "empty completion accepted: {body}",
        );
    }
}

/// `reasoning_content` is the model's private working and can restate the raw vent
/// verbatim. The product's central promise is that those words are never shown to
/// anyone, so it must never be read as output — including as a fallback when
/// `content` is missing.
#[test]
fn reasoning_content_never_becomes_output() {
    let body = r#"{"choices":[{"message":{"content":"The delivered sentence.","reasoning_content":"They typed: you never listen to me, it is infuriating."},"finish_reason":"stop"}],"usage":{}}"#;

    let completion = parse_completion(body).expect("valid completion");
    assert_eq!(completion.content, "The delivered sentence.");
    assert!(
        !completion.content.contains("you never listen"),
        "the model's private reasoning reached the output",
    );

    // And with no content at all, the reasoning must not be substituted for it.
    let reasoning_only = r#"{"choices":[{"message":{"reasoning_content":"They typed something private."},"finish_reason":"stop"}]}"#;
    assert!(matches!(parse_completion(reasoning_only), Err(AiError::EmptyContent)));
}

#[test]
fn valid_completion_parses_with_its_token_counts() {
    let completion = parse_completion(COMPLETED).expect("valid completion");
    assert_eq!(completion.content, "I feel frustrated because I don't feel heard when I speak.");
    assert_eq!(completion.input_tokens, 105);
    // Includes the 63 reasoning tokens: billing-accurate, not answer length.
    assert_eq!(completion.output_tokens, 77);
}

#[test]
fn malformed_bodies_fail_closed() {
    for body in ["", "not json", "{}", r#"{"choices":[]}"#] {
        assert!(parse_completion(body).is_err(), "`{body}` was accepted");
    }
}

/// Retrying a 4xx cannot succeed and spends provider quota a real user needs.
#[test]
fn only_transient_failures_are_retried() {
    assert!(AiError::Upstream(500).is_retryable());
    assert!(AiError::Upstream(429).is_retryable());
    assert!(AiError::Transport("timed out".into()).is_retryable());

    assert!(!AiError::Upstream(401).is_retryable());
    assert!(!AiError::Upstream(400).is_retryable());
    assert!(!AiError::NoConfig("tone_rewriter".into()).is_retryable());
}
