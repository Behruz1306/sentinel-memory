# Deploying Sentinel on AWS

This guide deploys the Sentinel dashboard and API as a single container on
AWS App Runner. You get an HTTPS URL with autoscaling and health checks.

The recommended path is GitHub Actions: every push to `main` builds the Docker
image in the cloud and pushes it to Amazon ECR. You do not need Docker on your
Mac.

## What gets deployed, and what does not

The container runs `server.py`, which serves the dashboard and every `/api`
route. That means the Command Center, Firewall Console, Immune System, Red Team,
and breach logging all work on the deployed URL.

The in-browser Live Voice agent is a separate long running worker
(`livekit_agent`). LiveKit media runs on LiveKit Cloud. The deployed site mints
join tokens; run the voice worker locally or on a small EC2 instance for the
full voice demo.

## Path A — GitHub Actions to ECR (recommended, no local Docker)

### Step 1. One-time AWS setup

Pick a region, for example `us-east-1`.

In IAM, create a user (for example `github-sentinel-deploy`) and attach a policy.
Either attach `AmazonEC2ContainerRegistryFullAccess`, or use
`AmazonEC2ContainerRegistryPowerUser` **and** create the ECR repository manually
first (PowerUser can push images but cannot create new repositories).

Quick manual repo (Console → search **ECR** → **Create repository** → name
`sentinel`, keep the same region as `AWS_REGION` in GitHub, default `us-east-1`).

Create an access key for that user. You will put it in GitHub, not in the repo.

### Step 2. GitHub repository secrets

Open your repo on GitHub → Settings → Secrets and variables → Actions.

Add these secrets:

```
AWS_ACCESS_KEY_ID       (from the IAM user)
AWS_SECRET_ACCESS_KEY   (from the IAM user)
```

Optional variables (Settings → Variables → Actions):

```
AWS_REGION=us-east-1
ECR_REPOSITORY=sentinel
```

### Step 3. Push code — image builds automatically

Push to `main` (or run the workflow manually: Actions → Deploy to ECR → Run workflow).

The workflow `.github/workflows/deploy-ecr.yml` builds the image and pushes to:

```
<ACCOUNT_ID>.dkr.ecr.us-east-1.amazonaws.com/sentinel:latest
```

Check the Actions tab for the green check and the printed image URI in the log.

### Step 4. Create the App Runner service (one time, AWS Console)

Open AWS App Runner → Create service → Container registry → Amazon ECR.

Select the `sentinel:latest` image. Then set:

Port: 8000
Health check path: `/api/health`
CPU and memory: 1 vCPU, 2 GB

Under environment variables, add your application secrets (see list below). Never
bake secrets into the image.

Create the service. After a few minutes you get a URL like
`https://xxxxx.us-east-1.awsapprunner.com`.

### Step 5. Redeploy after code changes

Push to `main` again. The workflow updates `sentinel:latest` in ECR.

In App Runner, open your service → Deploy → Deploy latest revision (or enable
automatic deployment when the ECR image tag updates).

## Path B — Build on your Mac (optional)

If you prefer local Docker instead of GitHub Actions:

```bash
export AWS_REGION=us-east-1
export AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
docker build -t sentinel:latest .
./deploy/push-to-ecr.sh
```

Then create App Runner as in Step 4 above.

## Environment variables for App Runner

Set these on the App Runner service (same as your local `.env`):

```
SENTINEL_LLM_PROVIDERS=minimax,qwen
MINIMAX_API_KEY=...
QWEN_API_KEY=...
MOSS_PROJECT_ID=...
MOSS_PROJECT_KEY=...
LIVEKIT_URL=wss://...livekit.cloud        (optional, for Live Voice tab)
LIVEKIT_API_KEY=...
LIVEKIT_API_SECRET=...
AWS_REGION=us-east-1
SENTINEL_LOG_GROUP=/sentinel/security
```

For CloudWatch breach logging, attach an IAM role to App Runner with
`logs:CreateLogGroup`, `logs:CreateLogStream`, and `logs:PutEvents`. Without it,
breaches fall back to a local file and the demo still works.

## Optional — Live Voice worker

```bash
uv pip install --python .venv -r requirements.txt
.venv/bin/python -m src.middleware.livekit_agent download-files
.venv/bin/python -m src.middleware.livekit_agent start
```

Set agent name to `sentinel` in the LiveKit frontend. The deployed dashboard
mints tokens; your worker answers calls.
