//! Agent configuration, loaded from the database.
//!
//! Nothing here is hardcoded or read from the environment except the key that
//! unseals the provider credential. A model change, a prompt change, or a new
//! provider is a row edit — AGENTS.md requires that, and it is also what makes the
//! six agents tunable without a Rust build.

use super::AiError;
use crate::crypto::PayloadCipher;
use sqlx::{PgPool, Row};
use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

/// How long a loaded configuration is trusted before being re-read.
///
/// ponytail: a TTL rather than an invalidation hook. A per-call read would add a
/// pooled round-trip to every mediation, and an admin edit taking up to a minute to
/// take effect is not a problem worth a cache-busting API.
const CACHE_TTL: Duration = Duration::from_secs(60);

/// Everything one call needs, with the provider credential already unsealed.
#[derive(Clone, Debug)]
pub struct ResolvedAgent {
    pub role_code: String,
    pub system_prompt: String,
    pub model_name: String,
    pub max_tokens: i32,
    pub temperature: f32,
    pub provider: Provider,
}

#[derive(Clone, Debug)]
pub struct Provider {
    pub name: String,
    pub base_url: String,
    pub chat_path: String,
    /// Unsealed. Never logged and never returned through the gateway.
    pub api_key: String,
    pub request_timeout_ms: i32,
    pub max_retries: u8,
}

const LOAD_SQL: &str = "SELECT a.role_code, a.system_prompt, \
     COALESCE(a.max_tokens, m.max_tokens, p.default_max_tokens) AS max_tokens, \
     COALESCE(a.temperature, p.default_temperature) AS temperature, \
     m.model_name, p.name AS provider_name, p.base_url, p.chat_path, \
     p.api_key_sealed, p.request_timeout_ms, p.max_retries \
     FROM agent_configs a \
     JOIN ai_providers p ON p.id = a.provider_id \
     JOIN ai_provider_models m ON m.id = a.model_id \
     WHERE a.is_active AND p.is_active AND m.is_active AND a.role_code IS NOT NULL \
     ORDER BY p.priority";

/// Caches resolved agents so a mediation does not pay for a config read.
pub struct AgentRegistry {
    cipher: PayloadCipher,
    cache: RwLock<Option<(Instant, HashMap<String, ResolvedAgent>)>>,
}

impl AgentRegistry {
    pub fn new(cipher: PayloadCipher) -> Self {
        Self {
            cipher,
            cache: RwLock::new(None),
        }
    }

    /// Returns the configuration for a role code.
    pub async fn resolve(&self, pool: &PgPool, role_code: &str) -> Result<ResolvedAgent, AiError> {
        if let Some(agent) = self.cached(role_code) {
            return Ok(agent);
        }

        let agents = self.load(pool).await?;
        let found = agents.get(role_code).cloned();

        if let Ok(mut cache) = self.cache.write() {
            *cache = Some((Instant::now(), agents));
        }

        // A missing role means the seed did not run or a row was deactivated. Failing
        // is correct: silently substituting another agent's prompt would put the wrong
        // instructions on a sensitive conversation.
        found.ok_or_else(|| AiError::NoConfig(role_code.to_string()))
    }

    fn cached(&self, role_code: &str) -> Option<ResolvedAgent> {
        let guard = self.cache.read().ok()?;
        let (loaded_at, agents) = guard.as_ref()?;
        (loaded_at.elapsed() < CACHE_TTL).then(|| agents.get(role_code).cloned())?
    }

    async fn load(&self, pool: &PgPool) -> Result<HashMap<String, ResolvedAgent>, AiError> {
        let rows = sqlx::query(LOAD_SQL)
            .persistent(false)
            .fetch_all(pool)
            .await
            .map_err(|err| AiError::Config(format!("could not read agent configuration: {err}")))?;

        let mut agents = HashMap::new();

        for row in rows {
            let role_code: String = row.get("role_code");
            let sealed: String = row.get("api_key_sealed");

            let api_key = match self.cipher.open(&sealed) {
                Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
                Err(_) => {
                    // Almost always a rotated sealing key. Skip the provider rather
                    // than abort the load, so one bad row cannot take down every role.
                    tracing::error!(
                        role = %role_code,
                        "Provider credential could not be unsealed; check PROVIDER_KEY_SEALING_KEY"
                    );
                    continue;
                }
            };

            agents.insert(
                role_code.clone(),
                ResolvedAgent {
                    role_code,
                    system_prompt: row.get::<Option<String>, _>("system_prompt").unwrap_or_default(),
                    model_name: row.get("model_name"),
                    max_tokens: row.get("max_tokens"),
                    temperature: row.get("temperature"),
                    provider: Provider {
                        name: row.get("provider_name"),
                        base_url: row.get("base_url"),
                        chat_path: row.get("chat_path"),
                        api_key,
                        request_timeout_ms: row.get("request_timeout_ms"),
                        max_retries: row.get::<i32, _>("max_retries").clamp(0, 5) as u8,
                    },
                },
            );
        }

        Ok(agents)
    }
}
