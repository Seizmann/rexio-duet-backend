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
    // No user_id field: the author is taken from the authenticated JWT subject.
    // Accepting it from the client would let one account file vents as another.
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
