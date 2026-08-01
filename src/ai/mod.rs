//! AI inference: provider configuration, and the client that calls it.

pub mod client;
pub mod provider;

pub use client::{complete, parse_completion, Completion};
pub use provider::{AgentRegistry, ResolvedAgent};

#[derive(Debug)]
pub enum AiError {
    /// The provider answered a non-2xx status.
    Upstream(u16),
    /// Network or timeout failure reaching the provider.
    Transport(String),
    /// The response body was not the shape an OpenAI-compatible endpoint returns.
    Malformed(&'static str),
    /// `finish_reason: "length"` — the model ran out of budget mid-answer.
    TokenBudgetExhausted,
    /// A 200 carrying no answer. The reasoning pass consumed the whole allowance.
    EmptyContent,
    /// No active row for this role code.
    NoConfig(String),
    /// Configuration could not be read or decoded.
    Config(String),
}

impl AiError {
    /// Whether trying again could plausibly succeed. A 4xx will not fix itself, and
    /// retrying it wastes the provider quota that a real user needs.
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Upstream(status) => *status >= 500 || *status == 429,
            Self::Transport(_) => true,
            _ => false,
        }
    }
}

impl std::fmt::Display for AiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Upstream(status) => write!(f, "provider returned status {status}"),
            Self::Transport(err) => write!(f, "could not reach provider: {err}"),
            Self::Malformed(what) => write!(f, "unexpected provider response: {what}"),
            Self::TokenBudgetExhausted => f.write_str("model ran out of token budget mid-answer"),
            Self::EmptyContent => f.write_str("model returned no content"),
            Self::NoConfig(role) => write!(f, "no active configuration for agent role `{role}`"),
            Self::Config(err) => write!(f, "agent configuration unavailable: {err}"),
        }
    }
}
