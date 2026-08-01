//! User profiles.
//!
//! Identity lives in the identity cluster; everything the product needs to *show*
//! a person — display name, avatar, badge, plan — lives here, in a row keyed by the
//! same subject the session carries.
//!
//! The two stores are joined by the application rather than by a foreign key, so
//! they can fall out of step: a signup can succeed and the profile write can fail
//! immediately after, and every account created before this module existed has no
//! row at all. `ensure` is the repair for both cases, and it is on the session path
//! so the repair happens the next time the user loads a page.

use crate::AppState;
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::Row;
use std::sync::Arc;
use uuid::Uuid;

/// Kept as a constant so a test can assert the conflict clause without a database:
/// the whole design depends on this insert being safe to repeat.
pub const INSERT_PROFILE_SQL: &str = "INSERT INTO users (id, email, username, display_name) \
     VALUES ($1, $2, $3, $4) ON CONFLICT (id) DO NOTHING";

const SELECT_PROFILE_SQL: &str = "SELECT id, email, username, display_name, avatar_url, is_pro, \
     verification_badge FROM users WHERE id = $1";

/// The subset of an identity record this table mirrors.
#[derive(Deserialize)]
struct IdentityRecord {
    id: String,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    user_metadata: Value,
}

/// Writes the profile row for a freshly registered account.
///
/// Returns `Err` only so the caller can log it. Registration must not fail on this:
/// the identity record has already been created and cannot be rolled back, so
/// reporting failure would leave the user holding valid credentials they were told
/// did not work. `ensure` repairs the gap on their first authenticated request.
pub async fn create(
    state: &Arc<AppState>,
    user_id: &str,
    email: &str,
    display_name: &str,
) -> Result<(), sqlx::Error> {
    let id = Uuid::parse_str(user_id).map_err(|_| sqlx::Error::RowNotFound)?;
    let name = (!display_name.is_empty()).then_some(display_name);

    sqlx::query(INSERT_PROFILE_SQL)
        .persistent(false)
        .bind(id)
        .bind(email)
        .bind(name)
        .bind(name)
        .execute(&state.main_db_pool)
        .await
        .map(|_| ())
}

/// Returns the profile for an authenticated subject, creating it from the identity
/// record if it is missing.
pub async fn ensure(state: &Arc<AppState>, subject: &str) -> Result<Value, String> {
    let id = Uuid::parse_str(subject).map_err(|_| "invalid subject".to_string())?;

    if let Some(profile) = fetch(state, id).await? {
        return Ok(profile);
    }

    // No row: either this account predates the profile table or its write failed
    // just after signup. The identity record is authoritative for both.
    let record = fetch_identity(state, subject).await?;
    let email = record.email.unwrap_or_default();
    let name = record.user_metadata["name"].as_str().unwrap_or_default();

    create(state, &record.id, &email, name)
        .await
        .map_err(|err| format!("could not back-fill profile: {err}"))?;

    fetch(state, id)
        .await?
        .ok_or_else(|| "profile missing immediately after back-fill".to_string())
}

async fn fetch(state: &Arc<AppState>, id: Uuid) -> Result<Option<Value>, String> {
    let row = sqlx::query(SELECT_PROFILE_SQL)
        .persistent(false)
        .bind(id)
        .fetch_optional(&state.main_db_pool)
        .await
        .map_err(|err| {
            tracing::error!("Profile read failed: {err:?}");
            "could not read profile".to_string()
        })?;

    Ok(row.map(|row| {
        json!({
            "user_id": row.get::<Uuid, _>("id").to_string(),
            "email": row.get::<Option<String>, _>("email"),
            "username": row.get::<Option<String>, _>("username"),
            "display_name": row.get::<Option<String>, _>("display_name"),
            "avatar_url": row.get::<Option<String>, _>("avatar_url"),
            "is_pro": row.get::<Option<bool>, _>("is_pro").unwrap_or(false),
            "verification_badge": row.get::<Option<String>, _>("verification_badge"),
        })
    }))
}

/// Reads one identity record through the provider's admin endpoint. Only reached on
/// the back-fill path, so it costs nothing on a normal session check.
async fn fetch_identity(state: &Arc<AppState>, subject: &str) -> Result<IdentityRecord, String> {
    let url = format!("{}/auth/v1/admin/users/{}", state.identity_url, subject);

    let res = state
        .http_client
        .get(&url)
        .header("apikey", &state.identity_service_key)
        .header("Authorization", format!("Bearer {}", state.identity_service_key))
        .send()
        .await
        .map_err(|_| "identity provider unreachable".to_string())?;

    if !res.status().is_success() {
        return Err("identity record not found".to_string());
    }

    res.json()
        .await
        .map_err(|_| "bad response from identity provider".to_string())
}
