//! Password hashing.
//!
//! Argon2id with per-password random salts. The previous code path stored the
//! submitted password verbatim, so any read of the users table was a credential
//! dump; this closes that.

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};

pub fn hash_password(plaintext: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    Ok(Argon2::default()
        .hash_password(plaintext.as_bytes(), &salt)?
        .to_string())
}

/// Verifies a password against a stored PHC-format hash.
pub fn verify_password(plaintext: &str, stored_hash: &str) -> bool {
    match PasswordHash::new(stored_hash) {
        Ok(parsed) => Argon2::default()
            .verify_password(plaintext.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => false,
    }
}
