# Supabase setup for Sentinel Memory

Sentinel stores users, sessions, conversation turns, audits, and activity in **Supabase PostgreSQL** so data survives every Render redeploy.

## 1. Create a project

1. Go to [supabase.com](https://supabase.com) → **New project**
2. Pick a region close to your Render service (e.g. US West)
3. Save the database password

## 2. Run the schema

1. In Supabase dashboard → **SQL Editor** → **New query**
2. Paste the contents of `supabase/schema.sql` from this repo
3. Click **Run**

You should see tables: `users`, `auth_tokens`, `sessions`, `turns`, `activity`, `company_uploads`.

## 3. Copy API keys

**Project Settings → API**

| Key | Use |
|-----|-----|
| **Project URL** | `SUPABASE_URL` |
| **service_role** (secret) | `SUPABASE_SERVICE_ROLE_KEY` |

Never expose `service_role` in the browser — only on Render/server.

## 4. Add to Render

In your Render service → **Environment**:

```
SUPABASE_URL=https://xxxxx.supabase.co
SUPABASE_SERVICE_ROLE_KEY=eyJhbG...
```

Redeploy. Check `/api/health` — `persistence.backend` should be `"supabase"`.

## 5. Local development

Add the same vars to your `.env`. Without them, Sentinel uses SQLite at `data/sentinel.db`.

## What persists

- User accounts (registration + demo users)
- Auth tokens
- Every evaluation session and turn
- Global activity feed (immune system learning)
- Custom company uploads (JSON)

Threat memory (Moss) and knowledge graphs still warm in memory on boot; session **audit trail** is fully durable in Supabase.
