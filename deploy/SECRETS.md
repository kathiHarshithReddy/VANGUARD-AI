# Project VANGUARD — CI/CD Secrets Reference

All GitHub Actions secrets are set in:
**Settings → Secrets and variables → Actions → New repository secret**

---

## Required for ALL deployments

| Secret | Example | Description |
|--------|---------|-------------|
| `ORIGIN_URL` | `https://api.your-app.com` | URL of the protected origin server |

---

## CI — Docker image push to GHCR

No extra secrets needed. The workflow uses the built-in `GITHUB_TOKEN` which automatically has `packages:write` on public repos.

For private repos, create a PAT with `packages:write` and set `GHCR_TOKEN`.

---

## AWS (ECS + ECR)

| Secret | Example | Description |
|--------|---------|-------------|
| `AWS_ACCESS_KEY_ID` | `AKIAIOSFODNN7EXAMPLE` | IAM access key |
| `AWS_SECRET_ACCESS_KEY` | `wJalrXUtnFEMI/...` | IAM secret key |
| `AWS_REGION` | `us-east-1` | AWS region |
| `AWS_ECR_REGISTRY` | `123456789012.dkr.ecr.us-east-1.amazonaws.com` | ECR registry endpoint |
| `AWS_ECR_REPOSITORY` | `vanguard` | ECR repository name |
| `AWS_ECS_CLUSTER` | `vanguard-cluster` | ECS cluster name |
| `AWS_ECS_SERVICE` | `vanguard-service` | ECS service name |
| `AWS_ECS_TASK_FAMILY` | `vanguard-sidecar` | ECS task definition family |
| `AWS_ECS_CONTAINER_NAME` | `vanguard` | Container name inside the task def |

### Minimum IAM policy
```json
{
  "Effect": "Allow",
  "Action": [
    "ecr:GetAuthorizationToken",
    "ecr:BatchCheckLayerAvailability",
    "ecr:InitiateLayerUpload",
    "ecr:UploadLayerPart",
    "ecr:CompleteLayerUpload",
    "ecr:PutImage",
    "ecs:DescribeTaskDefinition",
    "ecs:RegisterTaskDefinition",
    "ecs:UpdateService",
    "ecs:DescribeServices",
    "iam:PassRole"
  ],
  "Resource": "*"
}
```

---

## GCP (Cloud Run + Artifact Registry)

### Preferred: Workload Identity Federation (keyless)

| Secret | Example | Description |
|--------|---------|-------------|
| `GCP_PROJECT_ID` | `my-project-123456` | GCP project ID |
| `GCP_REGION` | `us-central1` | Cloud Run region |
| `GCP_WORKLOAD_IDENTITY_PROVIDER` | `projects/123/.../providers/github` | WIF provider resource name |
| `GCP_SERVICE_ACCOUNT` | `vanguard-deployer@my-project.iam.gserviceaccount.com` | Deployment SA email |
| `GCP_ARTIFACT_REGISTRY` | `us-central1-docker.pkg.dev` | Artifact Registry hostname |
| `GCP_AR_REPOSITORY` | `vanguard` | Artifact Registry repository |

**Setup WIF:**
```bash
gcloud iam workload-identity-pools create github \
  --location=global --display-name="GitHub Actions"

gcloud iam workload-identity-pools providers create-oidc github \
  --location=global \
  --workload-identity-pool=github \
  --attribute-mapping="google.subject=assertion.sub,attribute.repository=assertion.repository" \
  --issuer-uri="https://token.actions.githubusercontent.com"
```

### Alternative: Service Account Key
Set `GCP_SA_KEY` to the JSON key of a SA with `roles/run.admin` + `roles/artifactregistry.writer`.

---

## Cloudflare Worker

| Secret | Example | Description |
|--------|---------|-------------|
| `CF_API_TOKEN` | `abc123...` | Cloudflare API token (Workers:Edit) |
| `CF_ACCOUNT_ID` | `abcd1234...` | Cloudflare account ID |

**Variable (not secret):**
| Variable | Default | Description |
|----------|---------|-------------|
| `CF_WORKER_NAME` | `vanguard-edge` | Name of the deployed Worker |

**Create token:** Cloudflare Dashboard → My Profile → API Tokens → Create Token → Workers (Edit)

---

## Kubernetes

| Secret | Example | Description |
|--------|---------|-------------|
| `KUBECONFIG_BASE64` | `base64(~/.kube/config)` | Base64-encoded kubeconfig |
| `K8S_NAMESPACE` | `default` | Target namespace |
| `REGISTRY` | `ghcr.io/your-org/vanguard` | Image registry + repo for the K8s pod |

**Generate kubeconfig secret:**
```bash
cat ~/.kube/config | base64 -w 0
# Paste the output as the KUBECONFIG_BASE64 secret value
```

---

## GitHub Environments

Each deployment workflow uses a GitHub Environment for protection rules (e.g. required reviewers, wait timers):

| Workflow | Environment name |
|----------|-----------------|
| AWS | `aws-production` |
| GCP | `gcp-production` |
| Cloudflare | `cloudflare-production` |
| Kubernetes | `k8s-production` |

Create environments: **Settings → Environments → New environment**
