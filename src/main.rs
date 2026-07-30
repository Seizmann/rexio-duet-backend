pub mod auth;
pub mod config;
pub mod crypto;
pub mod gateway;
pub mod handlers;
pub mod models;
pub mod orchestrator;
pub mod password;

use axum::{
    extract::State,
    http::{header, HeaderName, HeaderValue, Method, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use config::Config;
use crypto::PayloadCipher;
use orchestrator::MultiAgentOrchestrator;
use serde::Serialize;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::PgPool;
use std::{net::SocketAddr, sync::Arc};
use tower_http::cors::CorsLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Clone)]
pub struct AppState {
    pub main_db_pool: PgPool,
    pub sensitive_db_pool: PgPool,
    pub orchestrator: Arc<MultiAgentOrchestrator>,
    /// Seals and opens gateway request/response envelopes.
    pub gateway_cipher: PayloadCipher,
    /// Separate key for vent content at rest, so a gateway key rotation does not
    /// invalidate stored confessions (and vice versa).
    pub vent_cipher: PayloadCipher,
    pub jwt_secret: String,
    pub gateway_signing_key: String,
    pub supabase_url: String,
    pub supabase_service_key: String,
    pub http_client: reqwest::Client,
}

#[derive(Serialize)]
struct SystemHealthResponse {
    status: String,
    main_db: String,
    sensitive_db: String,
    version: String,
}

pub const ALLOWED_ORIGINS: [&str; 2] = ["https://duet.rexio.pro", "https://duet222.rexio.pro"];

pub fn cors_layer() -> CorsLayer {
    CorsLayer::new()
        .allow_origin(
            ALLOWED_ORIGINS
                .iter()
                .map(|o| o.parse::<HeaderValue>().unwrap())
                .collect::<Vec<_>>(),
        )
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        // The gateway's signature and trace headers must survive preflight, otherwise
        // every signed browser request is blocked before it is sent.
        .allow_headers([
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            HeaderName::from_static("x-duet-signature"),
            HeaderName::from_static("x-duet-trace-id"),
        ])
}

#[tokio::main]
async fn main() {
    // Load a local .env when present; deployed environments inject real env vars.
    let _ = dotenvy::dotenv();

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "duet_backend=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let config = Config::from_env();

    let gateway_cipher = PayloadCipher::from_base64_key(&config.gateway_payload_key)
        .expect("GATEWAY_PAYLOAD_KEY must be a base64-encoded 32-byte key");
    let vent_cipher = PayloadCipher::from_base64_key(&config.vent_encryption_key)
        .expect("VENT_ENCRYPTION_KEY must be a base64-encoded 32-byte key");

    // Transaction-mode poolers (PgBouncer, port 6543) hand each query a different
    // server connection, so server-side prepared statements collide across requests
    // with "prepared statement already exists". Queries must therefore be issued
    // non-persistently — see `persistent(false)` on each query in `handlers`. The
    // cache is also zeroed here so sqlx allocates no statement names of its own.
    let pool_options = |url: &str| -> Result<PgConnectOptions, sqlx::Error> {
        Ok(url.parse::<PgConnectOptions>()?.statement_cache_capacity(0))
    };

    let main_db_pool = PgPoolOptions::new()
        .max_connections(20)
        .connect_with(pool_options(&config.main_db_url).expect("invalid main database URL"))
        .await
        .expect("Failed to connect to Primary SQL Storage pool");

    let sensitive_db_pool = PgPoolOptions::new()
        .max_connections(10)
        .connect_with(pool_options(&config.sensitive_db_url).expect("invalid sensitive database URL"))
        .await
        .expect("Failed to connect to Isolated Postgres Cluster pool");

    tracing::info!("Successfully established connection pools to both PostgreSQL instances.");

    let state = Arc::new(AppState {
        main_db_pool,
        sensitive_db_pool,
        orchestrator: Arc::new(MultiAgentOrchestrator::new()),
        gateway_cipher,
        vent_cipher,
        jwt_secret: config.jwt_secret,
        gateway_signing_key: config.gateway_signing_key,
        supabase_url: config.supabase_url,
        supabase_service_key: config.supabase_service_key,
        http_client: reqwest::Client::new(),
    });

    // One public operational surface: every client action flows through /api/gateway
    // as an encrypted envelope. Per-operation routes are gone — the operation now
    // lives inside the encrypted body, addressed by action code.
    let app = Router::new()
        .route("/api/gateway", post(gateway::gateway_handler))
        .route("/api/health", get(health_check_handler))
        .layer(cors_layer())
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], config.port));
    tracing::info!("RexiO Duet Real Backend running on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn health_check_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let main_db_status = match sqlx::query("SELECT 1").execute(&state.main_db_pool).await {
        Ok(_) => "Connected",
        Err(_) => "Disconnected",
    };

    let sensitive_db_status = match sqlx::query("SELECT 1").execute(&state.sensitive_db_pool).await {
        Ok(_) => "Connected",
        Err(_) => "Disconnected",
    };

    (
        StatusCode::OK,
        Json(SystemHealthResponse {
            status: "Online".to_string(),
            main_db: main_db_status.to_string(),
            sensitive_db: sensitive_db_status.to_string(),
            version: "1.0.0".to_string(),
        }),
    )
}

#[cfg(test)]
mod cors_tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    fn probe(origin: &str) -> Option<String> {
        let app = Router::new()
            .route("/api/health", get(|| async { "ok" }))
            .layer(cors_layer());
        let res = tokio::runtime::Runtime::new().unwrap().block_on(
            app.oneshot(
                Request::builder()
                    .method(Method::OPTIONS)
                    .uri("/api/health")
                    .header(header::ORIGIN, origin)
                    .header(header::ACCESS_CONTROL_REQUEST_METHOD, "GET")
                    .body(Body::empty())
                    .unwrap(),
            ),
        );
        res.unwrap()
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .map(|v| v.to_str().unwrap().to_string())
    }

    #[test]
    fn only_the_two_duet_origins_are_allowed() {
        for origin in ALLOWED_ORIGINS {
            assert_eq!(probe(origin).as_deref(), Some(origin), "{origin} rejected");
        }
        for origin in [
            "https://evil.com",
            "http://duet.rexio.pro",
            "https://duet.rexio.pro.evil.com",
            "https://sub.duet.rexio.pro",
        ] {
            assert_eq!(probe(origin), None, "{origin} wrongly allowed");
        }
    }
}
