//! Seals a provider API key for storage in `ai_providers.api_key_sealed`.
//!
//! The sealed value cannot be written by hand, and pasting a plaintext key into a
//! migration would defeat the point of the column. Usage:
//!
//! ```text
//! PROVIDER_KEY_SEALING_KEY=... cargo run --bin seal_key <<< 'sk-...'
//! ```

use std::io::Read;

#[path = "../crypto/mod.rs"]
mod crypto;

fn main() {
    let _ = dotenvy::dotenv();

    let sealing_key = std::env::var("PROVIDER_KEY_SEALING_KEY")
        .expect("PROVIDER_KEY_SEALING_KEY must be set");
    let cipher = crypto::PayloadCipher::from_base64_key(&sealing_key)
        .expect("PROVIDER_KEY_SEALING_KEY must be a base64-encoded 32-byte key");

    let mut plaintext = String::new();
    std::io::stdin()
        .read_to_string(&mut plaintext)
        .expect("could not read the key from stdin");

    let sealed = cipher
        .seal(plaintext.trim().as_bytes())
        .expect("sealing failed");

    println!("{sealed}");
}
