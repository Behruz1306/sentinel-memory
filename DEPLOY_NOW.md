# Deploy Sentinel NOW (AWS blocked? use Render)

Your Docker image is already built. If AWS account is still verifying, deploy in
five minutes on Render — free tier, public HTTPS, no Docker on your Mac.

## Step 1 — Render account

Open https://render.com → Sign up → **Sign up with GitHub** → authorize repo access.

## Step 2 — Deploy from Blueprint

1. Render Dashboard → **New +** → **Blueprint**
2. Connect repository **Behruz1306/sentinel-memory**
3. Render reads `render.yaml` → **Apply**

Wait 5–10 minutes for the first Docker build.

## Step 3 — Add secrets (required)

Open the new **sentinel-memory** web service → **Environment**:

```
MINIMAX_API_KEY=...
QWEN_API_KEY=...
MOSS_PROJECT_ID=...
MOSS_PROJECT_KEY=...
LIVEKIT_URL=...
LIVEKIT_API_KEY=...
LIVEKIT_API_SECRET=...
```

(Copy from your local `.env`.)

Click **Save Changes** → service redeploys.

## Step 4 — Your live URL

Render gives you something like:

```
https://sentinel-memory.onrender.com
```

Open it → **Command Center** → Simulate deepfake call.

Health check: `https://sentinel-memory.onrender.com/api/health`

## Free tier note

On Render free plan the service sleeps after ~15 min idle. First visit after
sleep takes ~30s to wake — fine for a hackathon demo; click the URL once before
presenting.

## When AWS activates later

Your ECR image is ready. Add App Runner in parallel or migrate — no code changes.
