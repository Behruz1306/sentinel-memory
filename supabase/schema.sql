-- Sentinel Memory — run once in Supabase SQL Editor (https://supabase.com/dashboard)
-- Project → SQL → New query → paste → Run

CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    name TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'analyst',
    org TEXT DEFAULT '',
    title TEXT DEFAULT '',
    onboarded BOOLEAN DEFAULT FALSE,
    created_at DOUBLE PRECISION NOT NULL DEFAULT extract(epoch from now())
);

CREATE TABLE IF NOT EXISTS auth_tokens (
    token TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at DOUBLE PRECISION NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    company_id TEXT NOT NULL DEFAULT 'acme-logistics',
    channel TEXT NOT NULL DEFAULT 'chat',
    user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
    caller_name TEXT DEFAULT '',
    claimed_identity TEXT DEFAULT 'guest',
    verification TEXT DEFAULT 'claimed_only',
    origin TEXT DEFAULT 'unknown',
    voice_anomaly DOUBLE PRECISION DEFAULT 0,
    trust_score INTEGER DEFAULT 100,
    created_at DOUBLE PRECISION NOT NULL,
    updated_at DOUBLE PRECISION NOT NULL,
    meta JSONB DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS turns (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    role TEXT NOT NULL,
    content TEXT NOT NULL,
    verdict TEXT DEFAULT '',
    trust_score INTEGER DEFAULT 0,
    analysis JSONB DEFAULT '{}'::jsonb,
    created_at DOUBLE PRECISION NOT NULL
);

CREATE TABLE IF NOT EXISTS activity (
    id BIGSERIAL PRIMARY KEY,
    kind TEXT NOT NULL,
    summary TEXT NOT NULL,
    detail JSONB DEFAULT '{}'::jsonb,
    session_id TEXT,
    created_at DOUBLE PRECISION NOT NULL DEFAULT extract(epoch from now())
);

CREATE TABLE IF NOT EXISTS company_uploads (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at DOUBLE PRECISION NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_turns_session ON turns(session_id);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_activity_ts ON activity(created_at DESC);

-- Disable RLS for server-side service role access (API uses service_role key only).
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE auth_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE turns ENABLE ROW LEVEL SECURITY;
ALTER TABLE activity ENABLE ROW LEVEL SECURITY;
ALTER TABLE company_uploads ENABLE ROW LEVEL SECURITY;
