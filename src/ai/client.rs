//! Chat completion client for OpenAI-compatible providers.
//!
//! The response handling here is deliberately strict, because of how the default
//! model behaves. It reasons before it answers, spending completion budget on hidden
//! `reasoning_content` tokens first. Measured against the live endpoint: a 200-token
//! ceiling produced `finish_reason: "length"` with `content: ""` — a 200 OK carrying
//! no answer at all. A lenient parser stores that empty string as the mediated
//! message, and the thing the user actually said disappears without an error
//! anywhere. So an empty or truncated completion is a failure, not a partial success.

use super::provider::ResolvedAgent;
use super::AiError;

/// What a completed call returns. Token counts come straight from the provider.
#[derive(Debug)]
pub struct Completion {
    pub content: String,
    pub input_tokens: i32,
    pub output_tokens: i32,
}

/// Parses a chat-completion response body.
///
/// Split out as a pure function over the raw body so the failure modes above can be
/// asserted against real recorded responses without a network call.
pub fn parse_completion(body: &str) -> Result<Completion, AiError> {
    let parsed: serde_json::Value =
        serde_json::from_str(body).map_err(|_| AiError::Malformed("response was not JSON"))?;

    let choice = parsed
        .get("choices")
        .and_then(|c| c.get(0))
        .ok_or(AiError::Malformed("response carried no choices"))?;

    // Checked before the content, so the diagnosis is "ran out of budget" rather than
    // the misleading "returned nothing".
    if choice.get("finish_reason").and_then(|f| f.as_str()) == Some("length") {
        return Err(AiError::TokenBudgetExhausted);
    }

    // Never `reasoning_content`. That field is the model's private working — it can
    // restate the raw vent verbatim, which is exactly what the product guarantees is
    // never shown to anyone.
    let content = choice
        .get("message")
        .and_then(|m| m.get("content"))
        .and_then(|c| c.as_str())
        .unwrap_or_default();

    if content.trim().is_empty() {
        return Err(AiError::EmptyContent);
    }

    let usage = parsed.get("usage");
    let tokens = |field: &str| {
        usage
            .and_then(|u| u.get(field))
            .and_then(|v| v.as_i64())
            .unwrap_or(0) as i32
    };

    Ok(Completion {
        content: content.trim().to_string(),
        input_tokens: tokens("prompt_tokens"),
        // Includes reasoning tokens — 63 of 77 in the measured call. This is
        // billing-accurate, not a measure of how long the answer was.
        output_tokens: tokens("completion_tokens"),
    })
}

/// Runs one agent against its configured provider.
///
/// Retries a transport or server failure up to the provider's `max_retries`, and
/// retries an exhausted budget exactly once with double the ceiling — the observed
/// failure is the reasoning pass eating the allowance, so more allowance is the
/// targeted fix rather than a generic backoff.
pub async fn complete(
    http: &reqwest::Client,
    agent: &ResolvedAgent,
    user_input: &str,
) -> Result<Completion, AiError> {
    let url = format!(
        "{}{}",
        agent.provider.base_url.trim_end_matches('/'),
        agent.provider.chat_path
    );

    let mut budget = agent.max_tokens;
    let mut budget_retried = false;
    let mut attempt = 0;

    loop {
        let outcome = attempt_once(http, agent, &url, user_input, budget).await;

        match outcome {
            Ok(completion) => return Ok(completion),

            // One doubling, then give up. Retrying forever on a model that will never
            // emit content just burns the provider quota.
            Err(AiError::TokenBudgetExhausted) | Err(AiError::EmptyContent) if !budget_retried => {
                tracing::warn!(
                    agent = %agent.role_code,
                    budget,
                    "Completion produced no content; retrying with a doubled token budget"
                );
                budget *= 2;
                budget_retried = true;
            }

            Err(err) if err.is_retryable() && attempt < agent.provider.max_retries => {
                attempt += 1;
                tracing::warn!(agent = %agent.role_code, attempt, "Provider call failed: {err}; retrying");
                tokio::time::sleep(std::time::Duration::from_millis(250 * attempt as u64)).await;
            }

            Err(err) => return Err(err),
        }
    }
}

async fn attempt_once(
    http: &reqwest::Client,
    agent: &ResolvedAgent,
    url: &str,
    user_input: &str,
    max_tokens: i32,
) -> Result<Completion, AiError> {
    let res = http
        .post(url)
        .bearer_auth(&agent.provider.api_key)
        .timeout(std::time::Duration::from_millis(
            agent.provider.request_timeout_ms as u64,
        ))
        .json(&serde_json::json!({
            "model": agent.model_name,
            "messages": [
                { "role": "system", "content": agent.system_prompt },
                { "role": "user", "content": user_input },
            ],
            "max_tokens": max_tokens,
            "temperature": agent.temperature,
        }))
        .send()
        .await
        .map_err(|err| AiError::Transport(err.to_string()))?;

    let status = res.status();
    let body = res
        .text()
        .await
        .map_err(|err| AiError::Transport(err.to_string()))?;

    if !status.is_success() {
        return Err(AiError::Upstream(status.as_u16()));
    }

    parse_completion(&body)
}
