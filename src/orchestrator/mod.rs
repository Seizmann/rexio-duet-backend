//! Multi-agent orchestrator.
//!
//! Each role is a named prompt against a configured model, both resolved from the
//! database at call time. The three public types below are unchanged from the stub
//! this replaces, so the callers using them did not have to move.
//!
//! Before this, every role returned a hardcoded string: a "mediated" message was the
//! user's own text with a prefix on it, and the tone was always reported as "Calm"
//! regardless of what was written.

pub mod logging;

use crate::ai::{self, AgentRegistry, AiError};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AgentRole {
    ToneRewriter,
    SeverityClassifier,
    Accountability,
    AdvocacySafety,
    PulseInsight,
    GroupMediation,
}

impl AgentRole {
    /// The `agent_configs.role_code` this role resolves to. The database owns the
    /// prompt and the model; this mapping is the only fixed part.
    fn role_code(&self) -> &'static str {
        match self {
            Self::ToneRewriter => "tone_rewriter",
            Self::SeverityClassifier => "severity_classifier",
            Self::Accountability => "accountability",
            Self::AdvocacySafety => "advocacy_safety",
            Self::PulseInsight => "pulse_insight",
            Self::GroupMediation => "group_mediation",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentRequest {
    pub role: AgentRole,
    pub user_id: String,
    pub target_partner_id: Option<String>,
    pub input_text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentResponse {
    pub agent_name: String,
    pub processed_output: String,
    pub emotional_rating: Option<String>,
    pub execution_time_ms: u128,
}

pub struct MultiAgentOrchestrator {
    http: reqwest::Client,
    registry: AgentRegistry,
    /// Configuration lives in primary storage; the audit trail lives in the isolated
    /// cluster, so both pools are held here.
    config_pool: PgPool,
    audit_pool: PgPool,
}

impl MultiAgentOrchestrator {
    pub fn new(
        http: reqwest::Client,
        registry: AgentRegistry,
        config_pool: PgPool,
        audit_pool: PgPool,
    ) -> Self {
        Self {
            http,
            registry,
            config_pool,
            audit_pool,
        }
    }

    /// Runs one agent. `trace_id` correlates the run with its gateway request.
    pub async fn process_request(
        &self,
        req: AgentRequest,
        trace_id: Option<Uuid>,
    ) -> Result<AgentResponse, String> {
        let started = std::time::Instant::now();

        let agent = self
            .registry
            .resolve(&self.config_pool, req.role.role_code())
            .await
            .map_err(|err| {
                tracing::error!("Agent configuration unavailable: {err}");
                describe(&err)
            })?;

        let outcome = ai::complete(&self.http, &agent, &req.input_text).await;
        let elapsed = started.elapsed();

        // Recorded on failure as well as success: a run that spent tokens and produced
        // nothing is precisely what an audit trail exists to show.
        let (input_tokens, output_tokens) = match &outcome {
            Ok(completion) => (completion.input_tokens, completion.output_tokens),
            Err(_) => (0, 0),
        };
        logging::record(
            &self.audit_pool,
            agent.role_code.clone(),
            trace_id,
            input_tokens,
            output_tokens,
            elapsed.as_millis().min(i32::MAX as u128) as i32,
        );

        let completion = outcome.map_err(|err| {
            tracing::error!(
                role = %agent.role_code,
                provider = %agent.provider.name,
                model = %agent.model_name,
                latency_ms = elapsed.as_millis(),
                "Agent call failed: {err}"
            );
            describe(&err)
        })?;

        tracing::info!(
            role = %agent.role_code,
            provider = %agent.provider.name,
            model = %agent.model_name,
            input_tokens = completion.input_tokens,
            output_tokens = completion.output_tokens,
            latency_ms = elapsed.as_millis(),
            "Agent call completed"
        );

        Ok(AgentResponse {
            agent_name: agent.role_code,
            processed_output: completion.content,
            // Tone is the severity agent's assessment and cannot be inferred from a
            // rewrite. Left absent rather than defaulted: labelling an unassessed
            // message "Calm" states something nothing checked.
            emotional_rating: None,
            execution_time_ms: elapsed.as_millis(),
        })
    }
}

/// Turns an internal failure into something a user can act on, without naming the
/// provider or model behind the product.
fn describe(err: &AiError) -> String {
    match err {
        AiError::NoConfig(_) | AiError::Config(_) => "mediation is not configured".to_string(),
        AiError::TokenBudgetExhausted | AiError::EmptyContent => {
            "mediation could not complete — nothing was sent".to_string()
        }
        _ => "mediation is temporarily unavailable".to_string(),
    }
}
