# 🛡 Project VANGUARD

> **Immutable Defense for the Post-Botnet Era**

VANGUARD is an AI-powered, self-healing web security shield that uses machine learning to proactively block DDoS, bot traffic, and injection attacks at the edge — before they reach your origin server.

---

## Architecture

```
Internet Traffic
      │
      ▼
┌─────────────────────────────────────┐
│         Global Edge Layer           │  ← Cloudflare Worker (fast heuristics)
│   Distributed scrubbing nodes       │
└──────────────┬──────────────────────┘
               │ Clean-ish traffic
               ▼
┌─────────────────────────────────────┐
│          The Neutralizer            │  ← VANGUARD Edge Proxy
│                                     │
│  ┌──────────────────────────────┐   │
│  │  Layer 7 Entropy Detector    │   │  47-dimensional behavioral analysis
│  │  (DDoS / Bot Detection)      │   │  ML ensemble intent classification
│  └──────────┬───────────────────┘   │
│             │ Pass                  │
│  ┌──────────▼───────────────────┐   │
│  │  AST Injection Shield        │   │  SQL / NoSQL / GraphQL AST parsing
│  │  (SQL / NoSQL / GraphQL)     │   │  Grammar anomaly detection
│  └──────────┬───────────────────┘   │
│             │ Pass                  │
│  ┌──────────▼───────────────────┐   │
│  │  Continuous Dojo             │   │  Adversarial training loop
│  │  (Adversarial Training)      │   │  1000+ payloads/min fuzzing
│  └──────────────────────────────┘   │
└──────────────┬──────────────────────┘
               │ Validated traffic only
               ▼
┌─────────────────────────────────────┐
│           Origin Server             │  ← Your application (zero refactoring)
└─────────────────────────────────────┘
```

---

## Core Features

### 1. Layer 7 Heuristic DDoS Mitigation
- **47-dimensional behavioral analysis** across request structure, header anomalies, temporal jitter, path patterns, and payload shape
- Entropy-based scoring combined with ML ensemble (IsolationForest + RandomForest)
- Drops non-human traffic using `BLOCK` / `CHALLENGE` decisions
- Pipeline: `Traffic Ingestion → Entropy Analysis → Intent Classification → Edge-Blocking`

### 2. Context-Aware Injection Shield
- Parses SQL, NoSQL (JSON), and GraphQL queries into **Abstract Syntax Trees**
- Three-layer validation:
  1. Static signature matching (fast-path against 30+ known attack patterns)
  2. AST structural analysis (nesting depth, DML statement count)
  3. Grammar-based anomaly detection (n-gram cosine similarity)
- Blocks injection regardless of obfuscation (URL encoding, case mutation, comment insertion)

### 3. Continuous Dojo — Adversarial Training Loop
- **Fuzzing engine** generates 1000+ novel attack payloads per minute via seeds, mutations, and recombination
- **Defence sandbox** tests each payload against all active shields
- **Automatic model retraining** when enough new evasion samples accumulate
- Loop: `Attack Generation → Defence Testing → Model Retraining`

---

## Performance Targets

| Metric | Target |
|--------|--------|
| Latency overhead | 12ms |
| Detection accuracy | 99.9% |
| False positive rate | 0.02% |
| Zero-day evasion rate | <0.1% |
| Attack throughput | 500K RPS |

---

## Project Structure

```
VANGUARD-AI/
├── vanguard/
│   ├── config.py                  # Environment-driven configuration
│   ├── main.py                    # Entry point (proxy + optional Dojo)
│   ├── entropy/
│   │   ├── behavioral.py          # 47-dimensional feature extractor
│   │   ├── classifier.py          # ML ensemble intent classifier
│   │   └── detector.py            # Entropy detector + decision engine
│   ├── injection_shield/
│   │   ├── ast_parser.py          # SQL / NoSQL / GraphQL AST parser
│   │   ├── grammar_learner.py     # N-gram grammar learner
│   │   └── validator.py           # Three-layer injection validator
│   ├── dojo/
│   │   ├── fuzzer.py              # Attack payload fuzzing engine
│   │   ├── sandbox.py             # Defence testing sandbox
│   │   └── trainer.py             # Continuous adversarial trainer
│   └── proxy/
│       └── edge_proxy.py          # Flask-based edge proxy
├── deploy/
│   ├── aws/
│   │   ├── ec2-sidecar.json       # ECS Task Definition (sidecar)
│   │   └── cloudformation.yml     # Full CloudFormation stack
│   ├── gcp/
│   │   └── backend-service.yml    # Cloud Run backend service
│   ├── cloudflare/
│   │   └── worker.js              # Cloudflare Worker (edge heuristics)
│   └── kubernetes/
│       ├── deployment.yml         # K8s Deployment + HPA
│       └── service.yml            # K8s Service (LoadBalancer)
├── tests/
│   ├── test_entropy.py            # Entropy engine unit tests
│   ├── test_injection_shield.py   # Injection shield unit tests
│   └── test_dojo.py               # Continuous Dojo unit tests
├── Dockerfile                     # Multi-stage Docker build
├── docker-compose.yml             # Local development stack
└── requirements.txt
```

---

## Quick Start

### Prerequisites
- Python 3.11+
- Docker (optional, for containerised deployment)

### Local development

```bash
# Clone and install
git clone https://github.com/kathiHarshithReddy/VANGUARD-AI.git
cd VANGUARD-AI
pip install -r requirements.txt
pip install -e .

# Set your origin server URL
export ORIGIN_URL=http://localhost:8000

# Start the proxy (port 8080 by default)
python -m vanguard.main

# Start the proxy + Continuous Dojo adversarial trainer
python -m vanguard.main --dojo
```

### Docker

```bash
# Build
docker build -t vanguard:latest .

# Run
docker run -p 8080:8080 \
  -e ORIGIN_URL=http://your-origin:8000 \
  vanguard:latest

# Or use docker-compose
docker-compose up
```

### Run tests

```bash
pip install pytest pytest-cov
pytest tests/ -v --tb=short
```

---

## Deployment

### AWS (ECS Sidecar)
```bash
# Register the task definition
aws ecs register-task-definition \
  --cli-input-json file://deploy/aws/ec2-sidecar.json

# Deploy the full CloudFormation stack
aws cloudformation deploy \
  --template-file deploy/aws/cloudformation.yml \
  --stack-name vanguard-stack \
  --parameter-overrides \
    VpcId=vpc-xxxx \
    SubnetIds=subnet-xxxx,subnet-yyyy \
    VanguardImage=<ECR_URI> \
    OriginImage=<YOUR_APP_IMAGE>
```

### GCP (Cloud Run)
```bash
# Build and push
gcloud builds submit --tag gcr.io/<PROJECT_ID>/vanguard:latest

# Deploy to Cloud Run
gcloud run services replace deploy/gcp/backend-service.yml \
  --region us-central1
```

### Cloudflare Workers
```bash
npm install -g wrangler
wrangler login
# Edit deploy/cloudflare/worker.js — set CONFIG.ORIGIN to your origin
wrangler deploy deploy/cloudflare/worker.js
```

### Kubernetes
```bash
# Create the ConfigMap with your origin URL
kubectl create configmap vanguard-config \
  --from-literal=ORIGIN_URL=http://your-origin-service:8000

# Deploy
kubectl apply -f deploy/kubernetes/deployment.yml
kubectl apply -f deploy/kubernetes/service.yml
```

---

## Configuration

All settings can be overridden via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `ORIGIN_URL` | `http://localhost:8000` | Origin server URL |
| `PROXY_HOST` | `0.0.0.0` | Proxy bind address |
| `PROXY_PORT` | `8080` | Proxy listen port |
| `ENTROPY_BENIGN_THRESHOLD` | `0.45` | Min entropy score to pass traffic |
| `ENTROPY_BLOCK_CONFIDENCE` | `0.85` | ML confidence to auto-block |
| `ENTROPY_RPS_LIMIT` | `500` | Rate limit per IP (req/sec) |
| `SHIELD_SIMILARITY_THRESHOLD` | `0.60` | Min grammar similarity to pass query |
| `DOJO_PAYLOADS_PER_MINUTE` | `1000` | Fuzzer throughput |
| `DOJO_RETRAIN_THRESHOLD` | `100` | Samples needed before retrain |
| `VANGUARD_DEBUG` | `false` | Enable debug logging |

---

## License

MIT
