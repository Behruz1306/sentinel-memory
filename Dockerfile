# Sentinel Memory — container image for the dashboard + API server.
# Cloud-agnostic: runs on AWS App Runner / ECS Fargate / EC2 (and Alibaba, GCP,
# Fly, Render, ...). Uses the lean server dependency set; the heavy LiveKit
# voice worker runs separately (see DEPLOY_AWS.md).
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PORT=8000 \
    RENDER=true \
    SENTINEL_CLOUD_DEPLOY=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY requirements-server.txt .
RUN pip install --upgrade pip && pip install -r requirements-server.txt

COPY . .

# Secrets are provided at runtime via environment variables — never baked in.
EXPOSE 8000

# Honour $PORT (App Runner / many PaaS set it); default to 8000 locally.
CMD ["sh", "-c", "uvicorn server:app --host 0.0.0.0 --port ${PORT:-8000}"]
