use crate::models::{AuthPayload, VentPayload, VentResponse};
use crate::AppState;
use axum::http::StatusCode;
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;
use uuid::Uuid;

/// Operation result: (JSON payload, optional Set-Cookie headers) on success.
pub type OpResult = Result<(Value, Option<Vec<String>>), (StatusCode, String)>;

#[derive(Deserialize)]
struct IdentityTokenResponse {
    access_token: String,
    user: IdentityUser,
}

#[derive(Deserialize)]
struct IdentityUser {
    id: String,
}

/// Helper to generate cookies
fn make_cookies(token: &str, csrf: &str) -> Vec<String> {
    vec![
        format!("duet_session={}; HttpOnly; Secure; SameSite=Lax; Path=/", token),
        format!("csrf_token={}; Secure; SameSite=Lax; Path=/", csrf),
    ]
}

/// Registers a new account with the identity cluster and mirrors it into a profile row.
pub async fn register_op(state: &Arc<AppState>, data: Value) -> OpResult {
    let payload: AuthPayload = serde_json::from_value(data)
        .map_err(|_| (StatusCode::BAD_REQUEST, "malformed registration payload".to_string()))?;

    let name = payload.username.unwrap_or_default();
    let email = payload.email.clone();

    let res = state.http_client.post(&format!("{}/auth/v1/signup", state.identity_url))
        .header("apikey", &state.identity_service_key)
        .header("Authorization", format!("Bearer {}", state.identity_service_key))
        .json(&json!({
            "email": payload.email,
            "password": payload.password,
            "data": { "name": name }
        }))
        .send()
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "identity provider unreachable".to_string()))?;

    if !res.status().is_success() {
        let err_body: Value = res.json().await.unwrap_or_default();
        let msg = err_body["msg"].as_str().unwrap_or("registration failed").to_string();
        return Err((StatusCode::BAD_REQUEST, msg));
    }

    let auth_data: IdentityTokenResponse = res.json().await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "bad response from identity provider".to_string()))?;

    // Every foreign key in the main schema points at this row, so without it the
    // account exists but can do nothing. It is still not worth failing the
    // registration over: the identity record is already created and cannot be
    // rolled back, so a failure here would hand the user working credentials while
    // telling them signup failed. `session_op` repairs it on the next request.
    if let Err(err) = crate::profile::create(state, &auth_data.user.id, &email, &name).await {
        tracing::error!(user_id = %auth_data.user.id, "Profile row not written at registration: {err:?}");
    }

    let csrf_token = Uuid::new_v4().to_string();
    let cookies = make_cookies(&auth_data.access_token, &csrf_token);

    let reply = json!({
        "user_id": auth_data.user.id,
        "username": name,
    });

    Ok((reply, Some(cookies)))
}

/// Exchanges credentials for a session with the identity cluster.
pub async fn login_op(state: &Arc<AppState>, data: Value) -> OpResult {
    let payload: AuthPayload = serde_json::from_value(data)
        .map_err(|_| (StatusCode::BAD_REQUEST, "malformed login payload".to_string()))?;

    let res = state.http_client.post(&format!("{}/auth/v1/token?grant_type=password", state.identity_url))
        .header("apikey", &state.identity_service_key)
        .header("Authorization", format!("Bearer {}", state.identity_service_key))
        .json(&json!({
            "email": payload.email,
            "password": payload.password
        }))
        .send()
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "identity provider unreachable".to_string()))?;

    if !res.status().is_success() {
        let err_body: Value = res.json().await.unwrap_or_default();
        let msg = err_body["error_description"].as_str().or(err_body["msg"].as_str()).unwrap_or("invalid credentials").to_string();
        return Err((StatusCode::BAD_REQUEST, msg));
    }

    let auth_data: IdentityTokenResponse = res.json().await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "bad response from identity provider".to_string()))?;

    let csrf_token = Uuid::new_v4().to_string();
    let cookies = make_cookies(&auth_data.access_token, &csrf_token);

    let reply = json!({
        "user_id": auth_data.user.id,
    });

    Ok((reply, Some(cookies)))
}

/// Validates the session and returns the user's profile.
///
/// Doubles as the repair path for a missing profile row — see `profile::ensure`.
pub async fn session_op(state: &Arc<AppState>, subject: Option<String>) -> OpResult {
    let authenticated = subject.ok_or((StatusCode::UNAUTHORIZED, "authentication required".to_string()))?;

    let profile = crate::profile::ensure(state, &authenticated)
        .await
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err))?;

    Ok((profile, None))
}

/// Accepts a private vent, seals it into the isolated cluster, and sends the mediated
/// rewrite — never the original words — on to the partner.
pub async fn vent_op(
    state: &Arc<AppState>,
    data: Value,
    subject: Option<String>,
    trace_id: Option<Uuid>,
) -> OpResult {
    let payload: VentPayload = serde_json::from_value(data)
        .map_err(|_| (StatusCode::BAD_REQUEST, "malformed vent payload".to_string()))?;

    let authenticated = subject.ok_or((StatusCode::UNAUTHORIZED, "authentication required".to_string()))?;
    let user_id = Uuid::parse_str(&authenticated)
        .map_err(|_| (StatusCode::UNAUTHORIZED, "invalid subject".to_string()))?;

    let vent_id = Uuid::new_v4();

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

    let agent_req = crate::orchestrator::AgentRequest {
        role: crate::orchestrator::AgentRole::ToneRewriter,
        user_id: user_id.to_string(),
        target_partner_id: payload.target_partner_id.clone(),
        input_text: payload.raw_vent_text,
    };

    // The vent is already stored, so a mediation failure loses nothing the user wrote.
    // The message surfaced here is the orchestrator's, which distinguishes "not
    // configured" from "temporarily unavailable" — the first needs an operator, the
    // second needs a retry, and a single generic string would hide which.
    let agent_res = state
        .orchestrator
        .process_request(agent_req, trace_id)
        .await
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err))?;

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

    let reply = serde_json::to_value(VentResponse {
        vent_id: vent_id.to_string(),
        mediated_message_id: Some(mediated_id.to_string()),
        mediated_text: agent_res.processed_output,
        // Absent unless an agent actually assessed it. This used to default to "Calm",
        // which reported a judgement on every message that nothing had made.
        tone: agent_res.emotional_rating,
    })
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "response encoding failed".to_string()))?;

    Ok((reply, None))
}
