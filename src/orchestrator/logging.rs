//! Writes agent runs to the audit trail in the isolated cluster.
//!
//! `ai_agent_logs` has existed since the first migration and nothing has ever written
//! to it, so there was no record of what any agent did, how long it took, or what it
//! cost. It lives in the sensitive cluster because it is the audit trail for
//! operations on confessional content.
//!
//! Deliberately records no input or output text — only which agent ran, when, and how
//! much. A log line that quoted a vent would defeat the isolation the table sits
//! behind.

use sqlx::PgPool;
use uuid::Uuid;

const INSERT_SQL: &str = "INSERT INTO ai_agent_logs \
     (agent_name, session_id, input_tokens, output_tokens, execution_time_ms) \
     VALUES ($1, $2, $3, $4, $5)";

/// Records one agent run.
///
/// Spawned rather than awaited: a mediation that succeeded must not fail because its
/// audit row could not be written. A failure is logged and dropped.
pub fn record(
    pool: &PgPool,
    agent_name: String,
    session_id: Option<Uuid>,
    input_tokens: i32,
    output_tokens: i32,
    execution_time_ms: i32,
) {
    let pool = pool.clone();
    tokio::spawn(async move {
        let result = sqlx::query(INSERT_SQL)
            .persistent(false)
            .bind(&agent_name)
            .bind(session_id)
            .bind(input_tokens)
            .bind(output_tokens)
            .bind(execution_time_ms)
            .execute(&pool)
            .await;

        if let Err(err) = result {
            tracing::error!(agent = %agent_name, "Agent audit row not written: {err:?}");
        }
    });
}
