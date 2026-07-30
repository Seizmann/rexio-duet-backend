-- Migration for Second Isolated Sensitive Supabase Database
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- 1. Confidential User Vent Logs (X's private confessionals to AI)
-- Partner Y NEVER has query/API access to this table
CREATE TABLE IF NOT EXISTS ai_vent_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL, -- Logical reference to user ID in Main DB
    target_partner_id UUID, -- Logical reference to recipient partner
    raw_encrypted_vent TEXT NOT NULL,
    ai_emotional_analysis JSONB DEFAULT '{}'::jsonb,
    linked_mediated_message_id UUID, -- Internal audit link only
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 2. Sensitive Audit Trail Logs
CREATE TABLE IF NOT EXISTS ai_agent_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    agent_name VARCHAR(100) NOT NULL,
    session_id UUID,
    input_tokens INT DEFAULT 0,
    output_tokens INT DEFAULT 0,
    execution_time_ms INT DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
