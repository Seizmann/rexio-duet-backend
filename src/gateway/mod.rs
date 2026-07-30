//! Single encrypted gateway endpoint.
//!
//! All client traffic enters through one route (`/api/gateway`). The request body is
//! an opaque encrypted blob, so a network observer sees neither field names nor the
//! operation being invoked. Inside the blob, operations are addressed by short action
//! codes rather than readable names like `sendMessage`.
//!
//! The action-code mapping is obfuscation, not a security control — the real
//! guarantee is that the payload is authenticated-encrypted and that each code
//! declares its own auth requirement, enforced here in the backend. The proxy layer
//! stays deliberately dumb: it checks for JWT presence and forwards, and never holds
//! the payload key.

use crate::handlers::{register_op, vent_op};
use crate::AppState;
use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;

/// Header carrying the HMAC-SHA256 signature of the raw request body.
const SIGNATURE_HEADER: &str = "x-duet-signature";
/// Header carrying a client-supplied correlation id, echoed into logs and responses.
const TRACE_HEADER: &str = "x-duet-trace-id";

/// The decrypted request envelope.
#[derive(Debug, Deserialize)]
pub struct GatewayEnvelope {
    /// Short obfuscated operation code, e.g. `a1`.
    pub op: String,
    /// Operation-specific arguments, shape determined by `op`.
    pub data: Value,
    /// Client-generated trace id, mirrored back for request correlation.
    #[serde(default)]
    pub trace_id: Option<String>,
}

/// The envelope returned to the client before encryption.
#[derive(Debug, Serialize)]
pub struct GatewayReply {
    pub ok: bool,
    pub data: Value,
    pub trace_id: String,
}

/// Whether an action code may be invoked without an authenticated subject.
///
/// Registration and login are the only unauthenticated entry points. Because the
/// operation now lives inside an encrypted body, the proxy can no longer make this
/// decision by inspecting the URL path — so it is made here, per code, where the
/// plaintext op is actually known.
fn requires_auth(op: &str) -> bool {
    !matches!(op, "a1" | "a2")
}

/// Resolves an action code to its handler.
///
/// Codes are intentionally terse and carry no semantic hint. The mapping is expected
/// to migrate into DB/Redis-backed config so new operations need no redeploy; it is
/// inlined here while the operation set is still this small.
async fn dispatch(
    state: &Arc<AppState>,
    op: &str,
    data: Value,
    subject: Option<String>,
) -> Result<Value, (StatusCode, String)> {
    match op {
        // a1 — account registration
        "a1" => register_op(state, data).await,
        // v2 — private vent submission to the mediation orchestrator
        "v2" => vent_op(state, data, subject).await,
        _ => Err((StatusCode::BAD_REQUEST, "unknown operation".to_string())),
    }
}

pub async fn gateway_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // 1. Verify the request signature over the raw bytes, before any parsing.
    //    Rejecting unsigned traffic here keeps malformed input away from the cipher.
    let provided_sig = headers
        .get(SIGNATURE_HEADER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();

    if crate::crypto::verify_signature(&state.gateway_signing_key, &body, provided_sig).is_err() {
        tracing::warn!("Gateway request rejected: invalid or missing request signature");
        return opaque_error(StatusCode::UNAUTHORIZED);
    }

    // 2. Decrypt the envelope. A tampered blob fails the AEAD tag check and lands here.
    let plaintext = match state.gateway_cipher.open(std::str::from_utf8(&body).unwrap_or_default()) {
        Ok(bytes) => bytes,
        Err(_) => {
            tracing::warn!("Gateway request rejected: payload failed authenticated decryption");
            return opaque_error(StatusCode::BAD_REQUEST);
        }
    };

    let envelope: GatewayEnvelope = match serde_json::from_slice(&plaintext) {
        Ok(env) => env,
        Err(_) => return opaque_error(StatusCode::BAD_REQUEST),
    };

    // Trace id: prefer the client's, fall back to the header, else synthesize one.
    let trace_id = envelope
        .trace_id
        .clone()
        .or_else(|| headers.get(TRACE_HEADER).and_then(|v| v.to_str().ok()).map(String::from))
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    // 3. Enforce auth per action code. The proxy only proved a token was present and
    //    well-formed; the authoritative subject is resolved here from the JWT.
    let subject = crate::auth::subject_from_headers(&headers, &state.jwt_secret);

    if requires_auth(&envelope.op) && subject.is_none() {
        tracing::warn!(op = %envelope.op, trace_id = %trace_id, "Gateway request rejected: op requires an authenticated subject");
        return opaque_error(StatusCode::UNAUTHORIZED);
    }

    let started = std::time::Instant::now();
    let outcome = dispatch(&state, &envelope.op, envelope.data, subject).await;
    // Latency logging is a documented requirement for every gateway call.
    tracing::info!(
        op = %envelope.op,
        trace_id = %trace_id,
        latency_ms = started.elapsed().as_millis(),
        "Gateway operation completed"
    );

    match outcome {
        Ok(data) => encrypted_reply(&state, StatusCode::OK, GatewayReply { ok: true, data, trace_id }),
        Err((status, message)) => {
            tracing::warn!(op = %envelope.op, trace_id = %trace_id, "Gateway operation failed: {message}");
            encrypted_reply(
                &state,
                status,
                GatewayReply {
                    ok: false,
                    data: serde_json::json!({ "message": message }),
                    trace_id,
                },
            )
        }
    }
}

/// Encrypts a reply envelope so responses are as opaque on the wire as requests.
fn encrypted_reply(state: &Arc<AppState>, status: StatusCode, reply: GatewayReply) -> Response {
    let trace_id = reply.trace_id.clone();
    let json = match serde_json::to_vec(&reply) {
        Ok(bytes) => bytes,
        Err(_) => return opaque_error(StatusCode::INTERNAL_SERVER_ERROR),
    };

    match state.gateway_cipher.seal(&json) {
        Ok(blob) => (
            status,
            [
                ("content-type", "application/octet-stream"),
                (TRACE_HEADER, trace_id.as_str()),
            ],
            blob,
        )
            .into_response(),
        Err(_) => opaque_error(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

/// Returns a bodyless status. Errors before decryption cannot be encrypted, and an
/// explanatory plaintext message would hand a prober a free oracle.
fn opaque_error(status: StatusCode) -> Response {
    status.into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_auth_entry_points_skip_authentication() {
        assert!(!requires_auth("a1"), "registration must stay reachable");
        assert!(!requires_auth("a2"), "login must stay reachable");
        // The vent op touches the isolated sensitive store; it must never be open.
        assert!(requires_auth("v2"));
        assert!(requires_auth("unknown-op"));
    }
}
