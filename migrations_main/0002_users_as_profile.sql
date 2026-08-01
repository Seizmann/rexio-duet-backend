-- Turns `users` into a profile table keyed by the identity provider's user id.
--
-- The problem this fixes: sessions carry a subject issued by the identity cluster,
-- but this table minted its own ids and registration never wrote a row here at all.
-- Every foreign key pointing at `users(id)` — `mediated_messages.sender_id` chief
-- among them — therefore rejected every real account, so the vent flow failed with
-- `23503` for anyone who had actually signed up.
--
-- Deliberately NOT adding `REFERENCES auth.users(id)`. A foreign key into the
-- identity provider's own schema couples primary storage to their internal layout
-- and breaks on their upgrades. The id is written by the application at
-- registration, and `a3` back-fills anything missing, which keeps the boundary in
-- code where it can be reasoned about.
--
-- ponytail: the three `gateway-probe-*` rows from the July gateway session are left
-- in place. Their ids exist in no identity record, but nothing reads them and
-- nothing can create more, so deleting live rows to tidy up buys nothing.

BEGIN;

-- The identity cluster hashes and verifies passwords. A second hash here has no
-- verifier and no reader — it is credential material kept for no reason.
ALTER TABLE users DROP COLUMN IF EXISTS password_hash;

-- The id now always arrives from the caller. Without a default, an insert that
-- forgets to supply one fails loudly instead of minting an orphan profile that no
-- session will ever match.
ALTER TABLE users ALTER COLUMN id DROP DEFAULT;

-- Registration collects a display name, not a handle. Usernames arrive later, if at
-- all, so the column cannot stay NOT NULL.
ALTER TABLE users ALTER COLUMN username DROP NOT NULL;

-- `updated_at` was declared NOT NULL DEFAULT NOW() and then never maintained, so it
-- has only ever recorded row creation.
CREATE OR REPLACE FUNCTION touch_updated_at() RETURNS trigger AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS users_touch_updated_at ON users;
CREATE TRIGGER users_touch_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION touch_updated_at();

COMMIT;
