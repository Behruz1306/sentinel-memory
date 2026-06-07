#!/usr/bin/env bash
# Build the Sentinel server image and push it to Amazon ECR.
#
# Usage:
#   export AWS_REGION=us-east-1
#   export AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
#   ./deploy/push-to-ecr.sh
#
# Optional overrides: ECR_REPO (default "sentinel"), IMAGE_TAG (default "latest").
set -euo pipefail

cd "$(dirname "$0")/.."

: "${AWS_REGION:?Set AWS_REGION, e.g. export AWS_REGION=us-east-1}"
: "${AWS_ACCOUNT_ID:?Set AWS_ACCOUNT_ID, e.g. export AWS_ACCOUNT_ID=\$(aws sts get-caller-identity --query Account --output text)}"
ECR_REPO="${ECR_REPO:-sentinel}"
IMAGE_TAG="${IMAGE_TAG:-latest}"

REGISTRY="${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com"
IMAGE_URI="${REGISTRY}/${ECR_REPO}:${IMAGE_TAG}"

echo "==> Ensuring ECR repository '${ECR_REPO}' exists"
aws ecr describe-repositories --repository-names "${ECR_REPO}" --region "${AWS_REGION}" >/dev/null 2>&1 \
  || aws ecr create-repository --repository-name "${ECR_REPO}" --region "${AWS_REGION}" >/dev/null

echo "==> Logging Docker in to ${REGISTRY}"
aws ecr get-login-password --region "${AWS_REGION}" \
  | docker login --username AWS --password-stdin "${REGISTRY}"

echo "==> Building image"
docker build -t "${ECR_REPO}:${IMAGE_TAG}" .

echo "==> Tagging and pushing ${IMAGE_URI}"
docker tag "${ECR_REPO}:${IMAGE_TAG}" "${IMAGE_URI}"
docker push "${IMAGE_URI}"

echo
echo "Pushed: ${IMAGE_URI}"
echo "Use this image URI when creating the App Runner service (port 8000, health /api/health)."
