#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Project VANGUARD — One-shot deployment script
#
# Usage:
#   ./deploy/deploy.sh [target] [options]
#
# Targets:
#   local       — docker-compose (default)
#   aws         — Amazon ECS via ECR
#   gcp         — GCP Cloud Run
#   cloudflare  — Cloudflare Worker
#   k8s         — Kubernetes
#   all         — all remote targets in sequence
#
# Options:
#   --no-build  Skip Docker build (use existing image)
#   --dry-run   Print commands without executing
#   --dojo      Start with Continuous Dojo adversarial trainer enabled
#
# Environment variables (can also be set in .env):
#   ORIGIN_URL              Your origin server URL (required for all targets)
#   AWS_ECR_REGISTRY        e.g. 123456789012.dkr.ecr.us-east-1.amazonaws.com
#   AWS_ECR_REPOSITORY      ECR repository name           (default: vanguard)
#   AWS_REGION              AWS region                    (default: us-east-1)
#   AWS_ECS_CLUSTER         ECS cluster name              (default: vanguard-cluster)
#   AWS_ECS_SERVICE         ECS service name              (default: vanguard-service)
#   GCP_PROJECT_ID          GCP project ID
#   GCP_REGION              GCP region                    (default: us-central1)
#   GCP_ARTIFACT_REGISTRY   Artifact Registry host
#   GCP_AR_REPOSITORY       Artifact Registry repository  (default: vanguard)
#   CF_API_TOKEN            Cloudflare API token
#   CF_ACCOUNT_ID           Cloudflare account ID
#   CF_WORKER_NAME          Cloudflare Worker name        (default: vanguard-edge)
#   KUBECONFIG              Path to kubeconfig            (default: ~/.kube/config)
#   K8S_NAMESPACE           Kubernetes namespace          (default: default)
#   K8S_REGISTRY            Image registry for K8s        (e.g. ghcr.io/org/vanguard)
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

# ─── Load .env if present ─────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "${SCRIPT_DIR}")"

if [[ -f "${ROOT_DIR}/.env" ]]; then
  echo "📄 Loading .env"
  # shellcheck disable=SC1090
  set -a && source "${ROOT_DIR}/.env" && set +a
fi

# ─── Defaults ─────────────────────────────────────────────────────────────────
TARGET="${1:-local}"
NO_BUILD=false
DRY_RUN=false
DOJO_FLAG=""

shift || true
while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-build) NO_BUILD=true ;;
    --dry-run)  DRY_RUN=true  ;;
    --dojo)     DOJO_FLAG="--dojo" ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
  shift
done

AWS_ECR_REPOSITORY="${AWS_ECR_REPOSITORY:-vanguard}"
AWS_REGION="${AWS_REGION:-us-east-1}"
AWS_ECS_CLUSTER="${AWS_ECS_CLUSTER:-vanguard-cluster}"
AWS_ECS_SERVICE="${AWS_ECS_SERVICE:-vanguard-service}"
GCP_REGION="${GCP_REGION:-us-central1}"
GCP_AR_REPOSITORY="${GCP_AR_REPOSITORY:-vanguard}"
CF_WORKER_NAME="${CF_WORKER_NAME:-vanguard-edge}"
K8S_NAMESPACE="${K8S_NAMESPACE:-default}"
IMAGE_TAG="$(git -C "${ROOT_DIR}" rev-parse --short HEAD 2>/dev/null || echo 'latest')"

# ─── Helpers ──────────────────────────────────────────────────────────────────
run() {
  if [[ "$DRY_RUN" == "true" ]]; then
    echo "[dry-run] $*"
  else
    "$@"
  fi
}

require() {
  if ! command -v "$1" &>/dev/null; then
    echo "❌ Required tool not found: $1" >&2
    exit 1
  fi
}

require_env() {
  if [[ -z "${!1:-}" ]]; then
    echo "❌ Required environment variable not set: $1" >&2
    exit 1
  fi
}

banner() {
  echo ""
  echo "═══════════════════════════════════════════════"
  echo "  🛡  VANGUARD  →  $1"
  echo "═══════════════════════════════════════════════"
}

# ─── Build Docker image ────────────────────────────────────────────────────────
build_image() {
  local tag="$1"
  banner "Docker Build (tag: ${tag})"
  require docker
  run docker build -t "vanguard:${tag}" -t "vanguard:latest" "${ROOT_DIR}"
  echo "✅ Image built: vanguard:${tag}"
}

# ─── LOCAL (docker-compose) ───────────────────────────────────────────────────
deploy_local() {
  banner "Local (docker-compose)"
  require docker

  if [[ "$NO_BUILD" == "false" ]]; then
    build_image "local"
  fi

  require_env ORIGIN_URL
  run docker compose -f "${ROOT_DIR}/docker-compose.yml" \
    up -d --remove-orphans \
    --wait

  echo "✅ VANGUARD running locally on http://localhost:8080"
  echo "   Health: http://localhost:8080/healthz"
  echo "   Origin: ${ORIGIN_URL}"
}

# ─── AWS ──────────────────────────────────────────────────────────────────────
deploy_aws() {
  banner "AWS ECS"
  require aws
  require docker

  require_env AWS_ECR_REGISTRY
  require_env ORIGIN_URL

  local full_image="${AWS_ECR_REGISTRY}/${AWS_ECR_REPOSITORY}"

  if [[ "$NO_BUILD" == "false" ]]; then
    echo "🔐 Logging in to ECR..."
    run aws ecr get-login-password --region "${AWS_REGION}" \
      | docker login --username AWS --password-stdin "${AWS_ECR_REGISTRY}"

    build_image "${IMAGE_TAG}"

    echo "🚀 Pushing to ECR..."
    run docker tag "vanguard:${IMAGE_TAG}" "${full_image}:${IMAGE_TAG}"
    run docker tag "vanguard:${IMAGE_TAG}" "${full_image}:latest"
    run docker push "${full_image}:${IMAGE_TAG}"
    run docker push "${full_image}:latest"
  fi

  echo "📋 Updating ECS service..."
  run aws ecs update-service \
    --region "${AWS_REGION}" \
    --cluster "${AWS_ECS_CLUSTER}" \
    --service "${AWS_ECS_SERVICE}" \
    --force-new-deployment \
    --output text \
    --query "service.serviceArn"

  echo "⏳ Waiting for service stability..."
  run aws ecs wait services-stable \
    --region "${AWS_REGION}" \
    --cluster "${AWS_ECS_CLUSTER}" \
    --services "${AWS_ECS_SERVICE}"

  echo "✅ VANGUARD deployed to AWS ECS"
  echo "   Cluster: ${AWS_ECS_CLUSTER}  /  Service: ${AWS_ECS_SERVICE}"
}

# ─── GCP ──────────────────────────────────────────────────────────────────────
deploy_gcp() {
  banner "GCP Cloud Run"
  require gcloud
  require docker

  require_env GCP_PROJECT_ID
  require_env ORIGIN_URL

  local ar_host="${GCP_ARTIFACT_REGISTRY:-${GCP_REGION}-docker.pkg.dev}"
  local full_image="${ar_host}/${GCP_PROJECT_ID}/${GCP_AR_REPOSITORY}/vanguard"

  if [[ "$NO_BUILD" == "false" ]]; then
    echo "🔐 Configuring Docker for Artifact Registry..."
    run gcloud auth configure-docker "${ar_host}" --quiet

    build_image "${IMAGE_TAG}"

    echo "🚀 Pushing to Artifact Registry..."
    run docker tag "vanguard:${IMAGE_TAG}" "${full_image}:${IMAGE_TAG}"
    run docker tag "vanguard:${IMAGE_TAG}" "${full_image}:latest"
    run docker push "${full_image}:${IMAGE_TAG}"
    run docker push "${full_image}:latest"
  fi

  echo "🚀 Deploying to Cloud Run..."
  run gcloud run deploy vanguard \
    --project "${GCP_PROJECT_ID}" \
    --region "${GCP_REGION}" \
    --image "${full_image}:${IMAGE_TAG}" \
    --platform managed \
    --allow-unauthenticated \
    --port 8080 \
    --min-instances 1 \
    --max-instances 100 \
    --concurrency 500 \
    --cpu 2 \
    --memory 1Gi \
    --timeout 30s \
    --set-env-vars "ORIGIN_URL=${ORIGIN_URL},PROXY_PORT=8080,ENTROPY_BENIGN_THRESHOLD=0.45,ENTROPY_BLOCK_CONFIDENCE=0.85,DOJO_PAYLOADS_PER_MINUTE=1000"

  echo "✅ VANGUARD deployed to GCP Cloud Run"
}

# ─── CLOUDFLARE ───────────────────────────────────────────────────────────────
deploy_cloudflare() {
  banner "Cloudflare Worker"
  require_env CF_API_TOKEN
  require_env CF_ACCOUNT_ID
  require_env ORIGIN_URL

  # Require wrangler or install via npx
  if ! command -v wrangler &>/dev/null; then
    echo "ℹ️  wrangler not found — will use npx"
    WRANGLER="npx --yes wrangler"
  else
    WRANGLER="wrangler"
  fi

  local worker_dir="${SCRIPT_DIR}/cloudflare"
  local worker_src="${worker_dir}/worker.js"
  local worker_tmp="/tmp/vanguard-worker.js"

  echo "🔧 Injecting ORIGIN_URL into worker..."
  sed "s|https://your-origin.example.com|${ORIGIN_URL}|g" \
    "${worker_src}" > "${worker_tmp}"

  # Write a minimal wrangler.toml
  cat > /tmp/wrangler.toml << EOF
name = "${CF_WORKER_NAME}"
main = "${worker_tmp}"
compatibility_date = "2024-01-01"
compatibility_flags = ["nodejs_compat"]
account_id = "${CF_ACCOUNT_ID}"
EOF

  echo "🚀 Deploying worker..."
  run env CLOUDFLARE_API_TOKEN="${CF_API_TOKEN}" \
    ${WRANGLER} deploy --config /tmp/wrangler.toml

  rm -f "${worker_tmp}" /tmp/wrangler.toml

  echo "✅ VANGUARD Cloudflare Worker deployed: ${CF_WORKER_NAME}"
}

# ─── KUBERNETES ───────────────────────────────────────────────────────────────
deploy_k8s() {
  banner "Kubernetes"
  require kubectl
  require_env ORIGIN_URL

  local registry="${K8S_REGISTRY:-vanguard}"
  local ns="${K8S_NAMESPACE}"

  if [[ "$NO_BUILD" == "false" && "${registry}" != "vanguard" ]]; then
    build_image "${IMAGE_TAG}"
    run docker tag "vanguard:${IMAGE_TAG}" "${registry}:${IMAGE_TAG}"
    run docker push "${registry}:${IMAGE_TAG}"
  fi

  # Patch the manifest with real registry + image tag + origin URL
  local tmp_dir
  tmp_dir="$(mktemp -d)"
  cp "${SCRIPT_DIR}/kubernetes/deployment.yml" "${tmp_dir}/deployment.yml"
  cp "${SCRIPT_DIR}/kubernetes/service.yml"    "${tmp_dir}/service.yml"

  sed -i "s|image: vanguard:latest|image: ${registry}:${IMAGE_TAG}|g" \
    "${tmp_dir}/deployment.yml"
  sed -i "s|ORIGIN_URL: \"http://origin-service:8000\"|ORIGIN_URL: \"${ORIGIN_URL}\"|g" \
    "${tmp_dir}/deployment.yml"

  echo "📋 Applying manifests to namespace '${ns}'..."
  run kubectl apply -n "${ns}" -f "${tmp_dir}/deployment.yml"
  run kubectl apply -n "${ns}" -f "${tmp_dir}/service.yml"

  echo "⏳ Waiting for rollout..."
  run kubectl rollout status deployment/vanguard -n "${ns}" --timeout=300s

  echo "✅ VANGUARD deployed to Kubernetes"
  run kubectl get pods -n "${ns}" -l app=vanguard
  run kubectl get svc  -n "${ns}" vanguard

  rm -rf "${tmp_dir}"
}

# ─── Dispatch ─────────────────────────────────────────────────────────────────
case "$TARGET" in
  local)       deploy_local ;;
  aws)         deploy_aws ;;
  gcp)         deploy_gcp ;;
  cloudflare)  deploy_cloudflare ;;
  k8s)         deploy_k8s ;;
  all)
    deploy_aws
    deploy_gcp
    deploy_cloudflare
    deploy_k8s
    ;;
  *)
    echo "Unknown target: $TARGET"
    echo "Valid targets: local | aws | gcp | cloudflare | k8s | all"
    exit 1
    ;;
esac

echo ""
echo "🛡  VANGUARD deployment complete"
