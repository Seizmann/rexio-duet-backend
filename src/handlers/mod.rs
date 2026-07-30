use crate::models::{AuthPayload, AuthResponse, VentPayload, VentResponse};
use crate::AppState;
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use jsonwebtoken::{encode, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}

pub async fn register_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<AuthPayload>,
) -> impl IntoResponse {
    let user_id = Uuid::new_v4();
    let username = payload.username.unwrap_or_else(|| "user".to_string());

    // Insert user into Primary SQL Storage
    let query = "INSERT INTO users (id, email, username, password_hash) VALUES ($1, $2, $3, $4)";
    match sqlx::query(query)
        .bind(user_id)
        .bind(&payload.email)
        .bind(&username)
        .bind(&payload.password) // In production, hash via bcrypt/argon2
        .execute(&state.main_db_pool)
        .await
    {
        Ok(_) => {
            let claims = Claims {
                sub: user_id.to_string(),
                exp: (chrono::Utc::now() + chrono::Duration::days(7)).timestamp() as usize,
            };
            let jwt_secret = "czr6A57Ed2Da2DIDHJjs6RE2cfHvKUFKTyoutbSdPMjLK1kmu6GqxzRMfJi5J9inDX1kHQuyR8Xp3CU/EEMLvg==";
            let token = encode(
                &Header::default(),
                &claims,
                &EncodingKey::from_secret(jwt_secret.as_bytes()),
            )
            .unwrap_or_default();

            (
                StatusCode::CREATED,
                Json(AuthResponse {
                    token,
                    user_id: user_id.to_string(),
                    username,
                }),
            )
                .into_response()
        }
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": format!("Registration failed: {:?}", err) })),
        )
            .into_response(),
    }
}

pub async fn vent_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<VentPayload>,
) -> impl IntoResponse {
    let vent_id = Uuid::new_v4();
    let user_id = Uuid::parse_str(&payload.user_id).unwrap_or_else(|_| Uuid::new_v4());

    // 1. Save strictly into Isolated Sensitive Postgres Cluster
    let sensitive_query = "INSERT INTO ai_vent_logs (id, user_id, raw_encrypted_vent) VALUES ($1, $2, $3)";
    if let Err(err) = sqlx::query(sensitive_query)
        .bind(vent_id)
        .bind(user_id)
        .bind(&payload.raw_vent_text)
        .execute(&state.sensitive_db_pool)
        .await
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": format!("Failed to log sensitive vent: {:?}", err) })),
        )
            .into_response();
    }

    // 2. Process via Custom Multi-Agent Orchestrator
    let agent_req = crate::orchestrator::AgentRequest {
        role: crate::orchestrator::AgentRole::ToneRewriter,
        user_id: payload.user_id.clone(),
        target_partner_id: payload.target_partner_id.clone(),
        input_text: payload.raw_vent_text,
    };

    let agent_res = match state.orchestrator.process_request(agent_req).await {
        Ok(res) => res,
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": err })),
            )
                .into_response()
        }
    };

    // 3. Save mediated message into Main PostgreSQL Pool for Partner delivery
    let mediated_id = Uuid::new_v4();
    let mediated_query = "INSERT INTO mediated_messages (id, sender_id, recipient_id, mediated_content, tone_rating) VALUES ($1, $2, $3, $4, $5)";
    let target_partner_uuid = payload
        .target_partner_id
        .and_then(|id| Uuid::parse_str(&id).ok())
        .unwrap_or(user_id);

    let _ = sqlx::query(mediated_query)
        .bind(mediated_id)
        .bind(user_id)
        .bind(target_partner_uuid)
        .bind(&agent_res.processed_output)
        .bind(&agent_res.emotional_rating)
        .execute(&state.main_db_pool)
        .await;

    (
        StatusCode::OK,
        Json(VentResponse {
            vent_id: vent_id.to_string(),
            mediated_message_id: Some(mediated_id.to_string()),
            mediated_text: agent_res.processed_output,
            tone: agent_res.emotional_rating.unwrap_or_else(|| "Calm".to_string()),
        }),
    )
        .into_response()
}
