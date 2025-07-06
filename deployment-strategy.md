# PQ-Core Deployment Strategy

## Overview

This document outlines the strategy for deploying PQ-Core while maintaining separation between public and private components.

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Frontend      │    │   Public API    │    │  Private Core   │
│   Website       │───▶│   (REST API)    │───▶│   Library       │
│                 │    │                 │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         │                       │                       │
    Public Repo              Public Repo           Private Repo
    (Frontend)               (API Server)          (Core Crypto)
```

## Repository Structure

### 1. Public Repository: `pq-core-api`

**What to include:**

- REST API server (`rest-api/`)
- Public documentation (`docs/`)
- Client libraries and examples
- Docker deployment files
- Installation scripts
- Public README and LICENSE

**What to exclude:**

- Core cryptographic library (`core-lib/`)
- NIST implementations (`vendor/`)
- Internal security documentation
- Development/testing scripts

### 2. Private Repository: `pq-core-lib`

**What to include:**

- Core cryptographic library (`core-lib/`)
- NIST reference implementations (`vendor/`)
- Internal security implementations
- Private documentation
- Development and testing tools

## Deployment Options

### Option A: Binary Distribution (Recommended)

**Step 1: Build Private Core Library**

```bash
# In private repo
cd core-lib
cargo build --release
cargo package --no-verify
```

**Step 2: Publish to Private Registry**

```toml
# In public repo's Cargo.toml
[dependencies]
pq-core-lib = { version = "1.0.0", registry = "your-private-registry" }
```

**Step 3: Deploy Public API**

```bash
# Public repo only needs the REST API
docker build -f Dockerfile.production -t pq-core-api .
docker-compose up -d
```

### Option B: Linked Library Distribution

**Step 1: Build Static Library**

```bash
# In private repo
cd core-lib
cargo build --release --crate-type=staticlib
```

**Step 2: Include Pre-built Library**

```dockerfile
# In public repo Dockerfile
COPY lib/libpq_core.a /usr/local/lib/
COPY include/pq_core.h /usr/local/include/
```

### Option C: Container-based Distribution

**Step 1: Build Base Image (Private)**

```dockerfile
# private-base.dockerfile
FROM rust:1.75 as core-builder
COPY core-lib ./core-lib
RUN cargo build --release

FROM debian:bookworm-slim
COPY --from=core-builder /app/target/release/deps/libcore_lib* /usr/local/lib/
```

**Step 2: Public API Uses Base Image**

```dockerfile
# Dockerfile.production
FROM your-registry/pq-core-base:latest
COPY rest-api ./rest-api
RUN cargo build --release --bin rest-api
```

## Security Considerations

### Environment Variables

```bash
# Production environment
PQ_ENVIRONMENT=production
PQ_API_KEY_SECRET=your-secret-key
PQ_RATE_LIMIT=100
PQ_MAX_REQUEST_SIZE=10485760
PQ_ENABLE_SOC2=true
PQ_ENABLE_GDPR=true
```

### Secrets Management

```yaml
# kubernetes-secrets.yaml
apiVersion: v1
kind: Secret
metadata:
  name: pq-core-secrets
type: Opaque
data:
  api-key-secret: <base64-encoded-secret>
  tls-key: <base64-encoded-tls-key>
  tls-cert: <base64-encoded-tls-cert>
```

### Network Security

```nginx
# nginx.conf
server {
    listen 443 ssl http2;
    ssl_certificate /etc/nginx/ssl/cert.pem;
    ssl_certificate_key /etc/nginx/ssl/key.pem;
    
    location /api/ {
        proxy_pass http://pq-core-api:3000/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Rate limiting
        limit_req zone=api burst=20 nodelay;
    }
}
```

## CI/CD Pipeline

### Private Repository Pipeline

```yaml
# .github/workflows/private-build.yml
name: Build Private Core
on:
  push:
    branches: [ main ]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    - name: Build core library
      run: |
        cd core-lib
        cargo build --release
        cargo test --release
    - name: Publish to private registry
      run: |
        cargo publish --token ${{ secrets.CARGO_REGISTRY_TOKEN }}
```

### Public Repository Pipeline

```yaml
# .github/workflows/deploy.yml
name: Deploy Public API
on:
  push:
    branches: [ main ]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    - name: Build and push Docker image
      run: |
        docker build -f Dockerfile.production -t pq-core-api:latest .
        docker tag pq-core-api:latest ${{ secrets.DOCKER_REGISTRY }}/pq-core-api:latest
        docker push ${{ secrets.DOCKER_REGISTRY }}/pq-core-api:latest
    - name: Deploy to production
      run: |
        kubectl set image deployment/pq-core-api pq-core-api=${{ secrets.DOCKER_REGISTRY }}/pq-core-api:latest
```

## Monitoring and Observability

### Metrics Collection

```rust
// In public API
use prometheus::{Counter, Histogram, register_counter, register_histogram};

lazy_static! {
    static ref HTTP_REQUESTS_TOTAL: Counter = register_counter!(
        "http_requests_total", "Total number of HTTP requests"
    ).unwrap();
    
    static ref REQUEST_DURATION: Histogram = register_histogram!(
        "request_duration_seconds", "Request duration in seconds"
    ).unwrap();
}
```

### Logging Configuration

```yaml
# log4rs.yaml
refresh_rate: 30 seconds
appenders:
  stdout:
    kind: console
  file:
    kind: file
    path: "/app/logs/pq-core.log"
    encoder:
      pattern: "{d} [{l}] {M} - {m}{n}"

root:
  level: info
  appenders:
    - stdout
    - file

loggers:
  pq_core::security:
    level: debug
    additive: false
    appenders:
      - file
```

## Kubernetes Deployment

### Deployment Manifest

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: pq-core-api
spec:
  replicas: 3
  selector:
    matchLabels:
      app: pq-core-api
  template:
    metadata:
      labels:
        app: pq-core-api
    spec:
      containers:
      - name: pq-core-api
        image: your-registry/pq-core-api:latest
        ports:
        - containerPort: 3000
        env:
        - name: PQ_ENVIRONMENT
          value: "production"
        - name: PQ_API_KEY_SECRET
          valueFrom:
            secretKeyRef:
              name: pq-core-secrets
              key: api-key-secret
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /health
            port: 3000
          initialDelaySeconds: 30
          periodSeconds: 30
        readinessProbe:
          httpGet:
            path: /health
            port: 3000
          initialDelaySeconds: 5
          periodSeconds: 5
```

### Service and Ingress

```yaml
apiVersion: v1
kind: Service
metadata:
  name: pq-core-api-service
spec:
  selector:
    app: pq-core-api
  ports:
  - port: 80
    targetPort: 3000
  type: ClusterIP

---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: pq-core-api-ingress
  annotations:
    nginx.ingress.kubernetes.io/rate-limit: "100"
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
spec:
  tls:
  - hosts:
    - api.pq-core.com
    secretName: pq-core-tls
  rules:
  - host: api.pq-core.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: pq-core-api-service
            port:
              number: 80
```

## Cost Optimization

### Resource Scaling

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: pq-core-api-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: pq-core-api
  minReplicas: 2
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
```

## Recommended Approach

1. **Use Option A (Binary Distribution)** for maximum security
2. **Publish core-lib to a private Cargo registry**
3. **Deploy public API using Docker containers**
4. **Use Kubernetes for orchestration and scaling**
5. **Implement proper monitoring and alerting**

This approach ensures:

- Your proprietary cryptographic implementations remain private
- The public API can be easily deployed and scaled
- Clear separation of concerns
- Professional deployment practices
- Security best practices are maintained
