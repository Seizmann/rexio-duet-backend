use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthPayload {
    pub email: String,
    pub password: String,
    pub username: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthResponse {
    pub token: String,
    pub user_id: String,
    pub username: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VentPayload {
    pub user_id: String,
    pub target_partner_id: Option<String>,
    pub raw_vent_text: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VentResponse {
    pub vent_id: String,
    pub mediated_message_id: Option<String>,
    pub mediated_text: String,
    pub tone: String,
}
