use crate::models::{AuthPayload, AuthResponse, VentPayload, VentResponse};
use crate::AppState;
use axum::http::StatusCode;
use jsonwebtoken::{encode, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}

/// Operation result: JSON payload on success, or a status plus a client-safe message.
type OpResult = Result<Value, (StatusCode, String)>;

/// Registers a new account. Reachable without authentication by design.
pub async fn register_op(state: &Arc<AppState>, data: Value) -> OpResult {
    let payload: AuthPayload = serde_json::from_value(data)
        .map_err(|_| (StatusCode::BAD_REQUEST, "malformed registration payload".to_string()))?;

    let user_id = Uuid::new_v4();
    let username = payload.username.unwrap_or_else(|| "user".to_string());

    // Argon2id with a per-user random salt. Storing the password as-is would make a
    // single database read a full credential dump.
    let password_hash = crate::password::hash_password(&payload.password)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "could not secure credentials".to_string()))?;

    let query = "INSERT INTO users (id, email, username, password_hash) VALUES ($1, $2, $3, $4)";
    sqlx::query(query).persistent(false)
        .bind(user_id)
        .bind(&payload.email)
        .bind(&username)
        .bind(&password_hash)
        .execute(&state.main_db_pool)
        .await
        .map_err(|err| {
            // Logged server-side in full; the client is told only that it failed.
            tracing::error!("Registration insert failed: {err:?}");
            (StatusCode::INTERNAL_SERVER_ERROR, "registration failed".to_string())
        })?;

    let claims = Claims {
        sub: user_id.to_string(),
        exp: (chrono::Utc::now() + chrono::Duration::days(7)).timestamp() as usize,
    };
    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(state.jwt_secret.as_bytes()),
    )
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "token issuance failed".to_string()))?;

    serde_json::to_value(AuthResponse {
        token,
        user_id: user_id.to_string(),
        username,
    })
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "response encoding failed".to_string()))
}

/// Accepts a private vent, stores it encrypted in the isolated cluster, and returns
/// the mediated message generated for the partner.
///
/// `subject` is the authenticated user id resolved from the JWT. It overrides any
/// user id present in the payload — trusting a client-supplied id here would let one
/// account write vents attributed to another.
pub async fn vent_op(state: &Arc<AppState>, data: Value, subject: Option<String>) -> OpResult {
    let payload: VentPayload = serde_json::from_value(data)
        .map_err(|_| (StatusCode::BAD_REQUEST, "malformed vent payload".to_string()))?;

    let authenticated = subject.ok_or((StatusCode::UNAUTHORIZED, "authentication required".to_string()))?;
    let user_id = Uuid::parse_str(&authenticated)
        .map_err(|_| (StatusCode::UNAUTHORIZED, "invalid subject".to_string()))?;

    let vent_id = Uuid::new_v4();

    // Encrypt before the value ever reaches the database. The column is named for
    // encrypted content, so writing plaintext into it would leave the isolated
    // cluster holding readable confessions while appearing protected.
    let sealed_vent = state
        .vent_cipher
        .seal(payload.raw_vent_text.as_bytes())
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "could not secure vent".to_string()))?;

    let sensitive_query =
        "INSERT INTO ai_vent_logs (id, user_id, raw_encrypted_vent) VALUES ($1, $2, $3)";
    sqlx::query(sensitive_query).persistent(false)
        .bind(vent_id)
        .bind(user_id)
        .bind(&sealed_vent)
        .execute(&state.sensitive_db_pool)
        .await
        .map_err(|err| {
            tracing::error!("Sensitive vent insert failed: {err:?}");
            (StatusCode::INTERNAL_SERVER_ERROR, "could not record vent".to_string())
        })?;

    // Ephemeral processing: the orchestrator receives plaintext in memory only. The
    // moved String is dropped with this scope and is never logged.
    let agent_req = crate::orchestrator::AgentRequest {
        role: crate::orchestrator::AgentRole::ToneRewriter,
        user_id: user_id.to_string(),
        target_partner_id: payload.target_partner_id.clone(),
        input_text: payload.raw_vent_text,
    };

    let agent_res = state
        .orchestrator
        .process_request(agent_req)
        .await
        .map_err(|err| {
            tracing::error!("Orchestrator failed: {err}");
            (StatusCode::INTERNAL_SERVER_ERROR, "mediation unavailable".to_string())
        })?;

    // The mediated message is separately worded and carries no link back to the raw
    // vent, so the partner can never trace it to the confession that produced it.
    let mediated_id = Uuid::new_v4();
    let target_partner_uuid = payload
        .target_partner_id
        .and_then(|id| Uuid::parse_str(&id).ok())
        .unwrap_or(user_id);

    let mediated_query = "INSERT INTO mediated_messages (id, sender_id, recipient_id, mediated_content, tone_rating) VALUES ($1, $2, $3, $4, $5)";
    if let Err(err) = sqlx::query(mediated_query).persistent(false)
        .bind(mediated_id)
        .bind(user_id)
        .bind(target_partner_uuid)
        .bind(&agent_res.processed_output)
        .bind(&agent_res.emotional_rating)
        .execute(&state.main_db_pool)
        .await
    {
        tracing::error!("Mediated message insert failed: {err:?}");
        return Err((StatusCode::INTERNAL_SERVER_ERROR, "could not deliver mediated message".to_string()));
    }

    serde_json::to_value(VentResponse {
        vent_id: vent_id.to_string(),
        mediated_message_id: Some(mediated_id.to_string()),
        mediated_text: agent_res.processed_output,
        tone: agent_res.emotional_rating.unwrap_or_else(|| "Calm".to_string()),
    })
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "response encoding failed".to_string()))
}
