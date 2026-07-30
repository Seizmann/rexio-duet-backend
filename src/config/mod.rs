//! Runtime secret and connection configuration.
//!
//! Every value here is process-environment driven. Nothing in this file may carry a
//! literal credential fallback: a hardcoded default silently ships a working secret
//! into the image and into Git history, which is exactly the class of bug this
//! module exists to prevent. Missing config fails loudly at startup instead.
//!
//! Note: business rules (rate limits, provider configs, feature flags) do NOT belong
//! here — per AGENTS.md those stay DB/Redis-driven. This is strictly infrastructure
//! credentials and cryptographic key material.

/// Reads a required secret, aborting startup when absent.
fn require(key: &str) -> String {
    match std::env::var(key) {
        Ok(val) if !val.trim().is_empty() => val,
        _ => panic!(
            "Missing required environment variable `{key}`. \
             Populate it from private-project-data.md for local runs, \
             or from the CI/CD secret store for deployed environments."
        ),
    }
}

pub struct Config {
    pub main_db_url: String,
    pub sensitive_db_url: String,
    pub jwt_secret: String,
    pub gateway_payload_key: String,
    pub gateway_signing_key: String,
    pub vent_encryption_key: String,
    pub supabase_url: String,
    pub supabase_service_key: String,
    pub port: u16,
}

impl Config {
    pub fn from_env() -> Self {
        Self {
            main_db_url: require("MAIN_DATABASE_URL"),
            sensitive_db_url: require("SENSITIVE_DATABASE_URL"),
            jwt_secret: require("JWT_SECRET"),
            gateway_payload_key: require("GATEWAY_PAYLOAD_KEY"),
            gateway_signing_key: require("GATEWAY_SIGNING_KEY"),
            vent_encryption_key: require("VENT_ENCRYPTION_KEY"),
            supabase_url: require("SUPABASE_URL"),
            supabase_service_key: require("SUPABASE_SERVICE_KEY"),
            port: std::env::var("PORT")
                .ok()
                .and_then(|p| p.parse().ok())
                .unwrap_or(40000),
        }
    }
}
