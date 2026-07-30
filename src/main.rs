pub mod handlers;
pub mod models;
pub mod orchestrator;

use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use handlers::{register_handler, vent_handler};
use orchestrator::{AgentRequest, MultiAgentOrchestrator};
use serde::Serialize;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::{net::SocketAddr, sync::Arc};
use tower_http::cors::{Any, CorsLayer};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Clone)]
pub struct AppState {
    pub main_db_pool: PgPool,
    pub sensitive_db_pool: PgPool,
    pub orchestrator: Arc<MultiAgentOrchestrator>,
}

#[derive(Serialize)]
struct SystemHealthResponse {
    status: String,
    main_db: String,
    sensitive_db: String,
    version: String,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "duet_backend=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Default Connection Strings (or read from environment)
    let main_db_url = std::env::var("MAIN_DATABASE_URL").unwrap_or_else(|_| {
        "postgresql://postgres.biywvvbvzvyxkbawieff:DUET-MAN-PARSHA75vvv78@aws-0-eu-central-1.pooler.supabase.com:6543/postgres".to_string()
    });

    let sensitive_db_url = std::env::var("SENSITIVE_DATABASE_URL").unwrap_or_else(|_| {
        "postgresql://postgres.plyfokdbsgeoybukuogc:DUET-MAN-PARSHA75vvv78hhh2ndddd@aws-0-ap-southeast-1.pooler.supabase.com:6543/postgres".to_string()
    });

    let port: u16 = std::env::var("PORT")
        .unwrap_or_else(|_| "10000".to_string())
        .parse()
        .unwrap_or(10000);

    // PgBouncer connection pooling
    let main_db_pool = PgPoolOptions::new()
        .max_connections(20)
        .connect(&main_db_url)
        .await
        .expect("Failed to connect to Main PostgreSQL DB pool");

    let sensitive_db_pool = PgPoolOptions::new()
        .max_connections(10)
        .connect(&sensitive_db_url)
        .await
        .expect("Failed to connect to Sensitive Isolated PostgreSQL DB pool");

    tracing::info!("Successfully established connection pools to both PostgreSQL instances.");

    let orchestrator = Arc::new(MultiAgentOrchestrator::new());

    let state = Arc::new(AppState {
        main_db_pool,
        sensitive_db_pool,
        orchestrator,
    });

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .route("/api/health", get(health_check_handler))
        .route("/api/agent/process", post(agent_process_handler))
        .route("/api/auth/register", post(register_handler))
        .route("/api/vent/process", post(vent_handler))
        .layer(cors)
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::info!("RexiO Duet Real Backend running on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn health_check_handler(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
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

async fn agent_process_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<AgentRequest>,
) -> impl IntoResponse {
    match state.orchestrator.process_request(payload).await {
        Ok(res) => (StatusCode::OK, Json(res)).into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": err })),
        )
            .into_response(),
    }
}
