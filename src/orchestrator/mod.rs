use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AgentRole {
    ToneRewriter,
    SeverityClassifier,
    Accountability,
    AdvocacySafety,
    PulseInsight,
    GroupMediation,
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
    pub default_provider: String,
}

impl MultiAgentOrchestrator {
    pub fn new() -> Self {
        Self {
            default_provider: "rexio".to_string(),
        }
    }

    pub async fn process_request(&self, req: AgentRequest) -> Result<AgentResponse, String> {
        let start_time = std::time::Instant::now();

        let (agent_name, output) = match req.role {
            AgentRole::ToneRewriter => (
                "RexiO Tone Rewriter (Harmony Agent)",
                format!("Rewritten for calm clarity: {}", req.input_text),
            ),
            AgentRole::SeverityClassifier => (
                "RexiO Severity Classifier",
                "Assessed: Normal emotional miscommunication".to_string(),
            ),
            AgentRole::Accountability => (
                "RexiO Accountability Agent",
                "Impact analysis generated".to_string(),
            ),
            AgentRole::AdvocacySafety => (
                "RexiO Advocacy & Safety Agent",
                "User wellbeing prioritized".to_string(),
            ),
            AgentRole::PulseInsight => (
                "RexiO Pulse Insight Agent",
                "Weekly trend analyzed".to_string(),
            ),
            AgentRole::GroupMediation => (
                "RexiO Group Mediation Orchestrator",
                "Mediation turn allocated".to_string(),
            ),
        };

        let elapsed = start_time.elapsed().as_millis();

        Ok(AgentResponse {
            agent_name: agent_name.to_string(),
            processed_output: output,
            emotional_rating: Some("Calm".to_string()),
            execution_time_ms: elapsed,
        })
    }
}
