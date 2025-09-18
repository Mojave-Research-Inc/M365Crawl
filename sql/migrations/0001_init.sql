-- Core metadata schema
CREATE TABLE IF NOT EXISTS tenants (
    id TEXT PRIMARY KEY,
    domain TEXT NOT NULL,
    consented_scopes TEXT NOT NULL,
    key_ids TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS identities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_upn TEXT,
    identity_type TEXT NOT NULL, -- mailbox, site, team
    last_delta_token TEXT,
    last_sync TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS items (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    identity_id UUID REFERENCES identities(id) ON DELETE SET NULL,
    kind TEXT NOT NULL, -- mail, file, event, chatMessage
    title TEXT,
    summary TEXT,
    source_url TEXT,
    acl_hash TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS chunks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    item_id TEXT NOT NULL REFERENCES items(id) ON DELETE CASCADE,
    ord INT NOT NULL,
    text TEXT NOT NULL,
    hash TEXT
);

-- vectors table for pgvector setups (optional)
-- Requires extension: CREATE EXTENSION IF NOT EXISTS vector;
-- CREATE TABLE IF NOT EXISTS vectors (
--     id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
--     chunk_id UUID NOT NULL REFERENCES chunks(id) ON DELETE CASCADE,
--     embedding vector(1536),
--     meta JSONB
-- );

