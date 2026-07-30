//! Payload encryption and request signing for the single gateway endpoint.
//!
//! ChaCha20-Poly1305 is used rather than AES-GCM: the VPS runs on shared vCPUs with
//! no guaranteed AES-NI instruction set, where AES in software is both slower and
//! vulnerable to cache-timing attacks. ChaCha20 is constant-time in pure software.
//! Both are AEAD ciphers with the same 32-byte key and 96-bit nonce shape, so this
//! choice can be revisited without touching the envelope format.

use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    ChaCha20Poly1305, Key, Nonce,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Nonce length mandated by ChaCha20-Poly1305 (96 bits).
const NONCE_LEN: usize = 12;

#[derive(Debug)]
pub enum CryptoError {
    InvalidKey,
    Decrypt,
    Encoding,
    BadSignature,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Deliberately vague: a caller probing the gateway must not learn whether
        // it failed on base64, the nonce, or the authentication tag.
        f.write_str("payload could not be processed")
    }
}

/// An AEAD cipher bound to one 32-byte key, built once at startup and shared.
#[derive(Clone)]
pub struct PayloadCipher {
    cipher: ChaCha20Poly1305,
}

impl PayloadCipher {
    /// Builds a cipher from a base64-encoded 32-byte key.
    pub fn from_base64_key(encoded: &str) -> Result<Self, CryptoError> {
        let raw = B64.decode(encoded.trim()).map_err(|_| CryptoError::InvalidKey)?;
        if raw.len() != 32 {
            return Err(CryptoError::InvalidKey);
        }
        let key = Key::from_slice(&raw);
        Ok(Self {
            cipher: ChaCha20Poly1305::new(key),
        })
    }

    /// Encrypts plaintext, returning base64 of `nonce || ciphertext || tag`.
    ///
    /// A fresh random nonce per call is what keeps key reuse safe; never derive
    /// the nonce from message content or a counter that could restart at zero.
    pub fn seal(&self, plaintext: &[u8]) -> Result<String, CryptoError> {
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);

        let ciphertext = self
            .cipher
            .encrypt(&nonce, plaintext)
            .map_err(|_| CryptoError::Encoding)?;

        let mut combined = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        combined.extend_from_slice(nonce.as_slice());
        combined.extend_from_slice(&ciphertext);
        Ok(B64.encode(combined))
    }

    /// Reverses `seal`. Fails closed on any tampering — the Poly1305 tag is
    /// verified before plaintext is returned, so a modified blob never decodes.
    pub fn open(&self, encoded: &str) -> Result<Vec<u8>, CryptoError> {
        let combined = B64.decode(encoded.trim()).map_err(|_| CryptoError::Decrypt)?;
        if combined.len() <= NONCE_LEN {
            return Err(CryptoError::Decrypt);
        }
        let (nonce_bytes, ciphertext) = combined.split_at(NONCE_LEN);
        let nonce = Nonce::from_slice(nonce_bytes);

        self.cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| CryptoError::Decrypt)
    }
}

/// Verifies an HMAC-SHA256 request signature over the raw request body.
///
/// Uses constant-time verification via `Mac::verify_slice`; a byte-by-byte
/// comparison here would leak the expected signature through timing.
pub fn verify_signature(signing_key: &str, body: &[u8], provided_hex: &str) -> Result<(), CryptoError> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(signing_key.as_bytes())
        .map_err(|_| CryptoError::InvalidKey)?;
    mac.update(body);

    let provided = hex_decode(provided_hex).ok_or(CryptoError::BadSignature)?;
    mac.verify_slice(&provided).map_err(|_| CryptoError::BadSignature)
}

/// Computes the signature a client is expected to send for a given body.
pub fn compute_signature(signing_key: &str, body: &[u8]) -> Result<String, CryptoError> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(signing_key.as_bytes())
        .map_err(|_| CryptoError::InvalidKey)?;
    mac.update(body);
    Ok(mac
        .finalize()
        .into_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}
