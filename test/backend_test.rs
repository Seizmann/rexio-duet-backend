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

use crypto::{compute_signature, verify_signature, PayloadCipher};
use password::{hash_password, verify_password};

/// Test-only key material. Real keys come from the environment; see .env.example.
const TEST_KEY: &str = "hMZLKtN3wtC/Tll2MDjrasBqTX5Oza9NBHEr8B8Etus=";
const OTHER_KEY: &str = "U9AqHqREHiu22Cb5CSL4FQdaSlvtxgZkErvCi15wCos=";

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
