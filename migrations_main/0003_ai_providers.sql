-- AI provider and agent configuration.
--
-- AGENTS.md requires business configuration to be database-driven: switching a
-- model or adding a provider must not need a redeploy. What stays in the
-- environment is exactly one thing — the key that unseals `api_key_sealed`, since
-- a key cannot decrypt itself.
--
-- Sealing the provider key in the database defends against a database-only
-- compromise: a leaked backup, an injection, or anyone reading the cluster without
-- reaching the backend host. It does not defend against a compromised backend
-- environment, which holds the sealing key. That is a real and worthwhile boundary,
-- and it is the only one being claimed.

BEGIN;

CREATE TABLE IF NOT EXISTS ai_providers (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(64) UNIQUE NOT NULL,
    base_url TEXT NOT NULL,
    chat_path TEXT NOT NULL DEFAULT '/chat/completions',
    -- Sealed with PROVIDER_KEY_SEALING_KEY, same construction as the vent cipher:
    -- base64(nonce || ciphertext || tag). Never logged, never returned to a client.
    api_key_sealed TEXT NOT NULL,
    -- 2000, not the more usual few hundred. The default model reasons before it
    -- answers, spending completion budget on hidden tokens first: measured against
    -- the live endpoint, a 200-token ceiling returned finish_reason 'length' with an
    -- empty content string, while 2000 answered correctly using 77. A low ceiling
    -- here does not truncate the reply, it erases it.
    default_max_tokens INT NOT NULL DEFAULT 2000,
    default_temperature REAL NOT NULL DEFAULT 0.7,
    request_timeout_ms INT NOT NULL DEFAULT 60000,
    max_retries INT NOT NULL DEFAULT 2,
    -- Lower runs first. Fallback order when a provider is unreachable.
    priority INT NOT NULL DEFAULT 100,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS ai_provider_models (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    provider_id UUID NOT NULL REFERENCES ai_providers(id) ON DELETE CASCADE,
    model_name VARCHAR(128) NOT NULL,
    supports_vision BOOLEAN NOT NULL DEFAULT FALSE,
    -- Recorded so an operator choosing a model knows why its token budget must be
    -- generous. The client rejects empty content regardless of this flag.
    is_reasoning BOOLEAN NOT NULL DEFAULT FALSE,
    max_tokens INT,   -- NULL inherits the provider default
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    UNIQUE (provider_id, model_name)
);

-- agent_configs already exists. It carried provider and model as loose strings with
-- nothing to resolve them against, and no prompt at all.
ALTER TABLE agent_configs ADD COLUMN IF NOT EXISTS role_code VARCHAR(40);
ALTER TABLE agent_configs ADD COLUMN IF NOT EXISTS provider_id UUID REFERENCES ai_providers(id);
ALTER TABLE agent_configs ADD COLUMN IF NOT EXISTS model_id UUID REFERENCES ai_provider_models(id);
ALTER TABLE agent_configs ADD COLUMN IF NOT EXISTS system_prompt TEXT;
ALTER TABLE agent_configs ADD COLUMN IF NOT EXISTS max_tokens INT;
ALTER TABLE agent_configs ADD COLUMN IF NOT EXISTS temperature REAL;

-- Partial, because the pre-existing rows have no role_code and a plain unique
-- constraint would collide them all on NULL.
CREATE UNIQUE INDEX IF NOT EXISTS agent_configs_role_code_key
    ON agent_configs (role_code) WHERE role_code IS NOT NULL;

DROP TRIGGER IF EXISTS ai_providers_touch_updated_at ON ai_providers;
CREATE TRIGGER ai_providers_touch_updated_at
    BEFORE UPDATE ON ai_providers
    FOR EACH ROW EXECUTE FUNCTION touch_updated_at();

COMMIT;
