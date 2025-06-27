# Installation & Setup

This guide covers everything you need to get PQ-Core running in your environment, from local development to production deployment.

## Server Installation

### Prerequisites

**System Requirements**:
- Linux (Ubuntu 20.04+, RHEL 8+, or similar)
- 4+ GB RAM (8+ GB recommended for production)
- 2+ CPU cores
- 10+ GB disk space
- Network connectivity for dependencies

**Software Dependencies**:
- Rust 1.70+ (latest stable recommended)
- Git
- OpenSSL development libraries
- Build tools (gcc, make, etc.)

### Install Rust

```bash
# Install Rust using rustup
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# Verify installation
rustc --version
cargo --version
```

### Clone and Build

```bash
# Clone the repository
git clone https://github.com/your-org/pq-core.git
cd pq-core

# Install system dependencies (Ubuntu/Debian)
sudo apt update
sudo apt install -y build-essential pkg-config libssl-dev

# Install system dependencies (RHEL/CentOS)
sudo yum groupinstall -y "Development Tools"
sudo yum install -y openssl-devel pkg-config

# Build the project
cargo build --release

# Run tests to verify installation
cargo test
```

### Configuration

Create a configuration file:

```toml
# config/pq-core.toml
[server]
host = "127.0.0.1"
port = 3000
workers = 4

[security]
api_key_required = true
rate_limit_default = 60  # requests per minute
audit_logging = true

[algorithms]
enabled_kems = ["kyber512", "kyber768", "kyber1024"]
enabled_signatures = ["dilithium2", "dilithium3", "dilithium5", "falcon512", "falcon1024"]
enabled_hybrid = true

[logging]
level = "info"
format = "json"
file = "/var/log/pq-core/pq-core.log"
```

### Start the Server

```bash
# Development mode
cargo run --bin rest-api

# Production mode
./target/release/rest-api --config config/pq-core.toml
```

## Docker Installation

### Using Docker Compose (Recommended)

Create a `docker-compose.yml` file:

```yaml
version: '3.8'

services:
  pq-core:
    image: pq-core/api:latest
    ports:
      - "3000:3000"
    environment:
      - RUST_LOG=info
      - PQ_CORE_CONFIG=/app/config/production.toml
    volumes:
      - ./config:/app/config
      - ./logs:/var/log/pq-core
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:3000/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data
    restart: unless-stopped

volumes:
  redis_data:
```

### Build and Run

```bash
# Build the Docker image
docker build -t pq-core/api:latest .

# Start services
docker-compose up -d

# View logs
docker-compose logs -f pq-core

# Check status
docker-compose ps
```

### Dockerfile

```dockerfile
FROM rust:1.75 as builder

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY core-lib/ ./core-lib/
COPY rest-api/ ./rest-api/
COPY cli/ ./cli/

RUN cargo build --release --bin rest-api

FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/target/release/rest-api ./
COPY config/ ./config/

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:3000/health || exit 1

CMD ["./rest-api", "--config", "config/production.toml"]
```

## Kubernetes Deployment

### Kubernetes Manifests

**Namespace**:
```yaml
# k8s/namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: pq-core
```

**ConfigMap**:
```yaml
# k8s/configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: pq-core-config
  namespace: pq-core
data:
  pq-core.toml: |
    [server]
    host = "0.0.0.0"
    port = 3000
    workers = 8
    
    [security]
    api_key_required = true
    rate_limit_default = 1000
    audit_logging = true
    
    [algorithms]
    enabled_kems = ["kyber512", "kyber768", "kyber1024"]
    enabled_signatures = ["dilithium2", "dilithium3", "dilithium5", "falcon512", "falcon1024"]
    
    [logging]
    level = "info"
    format = "json"
```

**Deployment**:
```yaml
# k8s/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: pq-core-api
  namespace: pq-core
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
        image: pq-core/api:v1.0.0
        ports:
        - containerPort: 3000
        env:
        - name: RUST_LOG
          value: "info"
        - name: PQ_CORE_CONFIG
          value: "/app/config/pq-core.toml"
        volumeMounts:
        - name: config
          mountPath: /app/config
        resources:
          requests:
            memory: "1Gi"
            cpu: "500m"
          limits:
            memory: "2Gi"
            cpu: "1000m"
        readinessProbe:
          httpGet:
            path: /health
            port: 3000
          initialDelaySeconds: 10
          periodSeconds: 5
        livenessProbe:
          httpGet:
            path: /health
            port: 3000
          initialDelaySeconds: 30
          periodSeconds: 10
      volumes:
      - name: config
        configMap:
          name: pq-core-config
```

**Service**:
```yaml
# k8s/service.yaml
apiVersion: v1
kind: Service
metadata:
  name: pq-core-api-service
  namespace: pq-core
spec:
  selector:
    app: pq-core-api
  ports:
  - protocol: TCP
    port: 80
    targetPort: 3000
  type: ClusterIP
```

**Ingress**:
```yaml
# k8s/ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: pq-core-ingress
  namespace: pq-core
  annotations:
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/force-ssl-redirect: "true"
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
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

### Deploy to Kubernetes

```bash
# Apply all manifests
kubectl apply -f k8s/

# Check deployment status
kubectl get pods -n pq-core
kubectl get services -n pq-core
kubectl get ingress -n pq-core

# View logs
kubectl logs -f deployment/pq-core-api -n pq-core

# Scale deployment
kubectl scale deployment pq-core-api --replicas=5 -n pq-core
```

## Cloud Deployments

### AWS ECS

**Task Definition**:
```json
{
  "family": "pq-core-api",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "1024",
  "memory": "2048",
  "executionRoleArn": "arn:aws:iam::account:role/ecsTaskExecutionRole",
  "taskRoleArn": "arn:aws:iam::account:role/ecsTaskRole",
  "containerDefinitions": [
    {
      "name": "pq-core-api",
      "image": "your-account.dkr.ecr.region.amazonaws.com/pq-core:latest",
      "portMappings": [
        {
          "containerPort": 3000,
          "protocol": "tcp"
        }
      ],
      "environment": [
        {
          "name": "RUST_LOG",
          "value": "info"
        }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/pq-core-api",
          "awslogs-region": "us-west-2",
          "awslogs-stream-prefix": "ecs"
        }
      },
      "healthCheck": {
        "command": ["CMD-SHELL", "curl -f http://localhost:3000/health || exit 1"],
        "interval": 30,
        "timeout": 5,
        "retries": 3
      }
    }
  ]
}
```

### Google Cloud Run

**Deploy to Cloud Run**:
```bash
# Build and push image to Google Container Registry
docker build -t gcr.io/PROJECT_ID/pq-core:latest .
docker push gcr.io/PROJECT_ID/pq-core:latest

# Deploy to Cloud Run
gcloud run deploy pq-core-api \
  --image gcr.io/PROJECT_ID/pq-core:latest \
  --platform managed \
  --region us-central1 \
  --allow-unauthenticated \
  --memory 2Gi \
  --cpu 2 \
  --concurrency 100 \
  --max-instances 10 \
  --port 3000
```

### Azure Container Instances

**Deploy to ACI**:
```bash
# Create resource group
az group create --name pq-core-rg --location eastus

# Create container instance
az container create \
  --resource-group pq-core-rg \
  --name pq-core-api \
  --image your-registry.azurecr.io/pq-core:latest \
  --cpu 2 \
  --memory 4 \
  --dns-name-label pq-core-api \
  --ports 3000 \
  --environment-variables RUST_LOG=info
```

## Load Balancer Configuration

### Nginx Configuration

```nginx
# /etc/nginx/sites-available/pq-core
upstream pq-core-backend {
    least_conn;
    server 127.0.0.1:3000 max_fails=3 fail_timeout=30s;
    server 127.0.0.1:3001 max_fails=3 fail_timeout=30s;
    server 127.0.0.1:3002 max_fails=3 fail_timeout=30s;
}

server {
    listen 80;
    server_name api.pq-core.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name api.pq-core.com;
    
    ssl_certificate /etc/ssl/certs/pq-core.crt;
    ssl_certificate_key /etc/ssl/private/pq-core.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256;
    ssl_prefer_server_ciphers off;
    
    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-Frame-Options DENY always;
    add_header X-XSS-Protection "1; mode=block" always;
    
    # Rate limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
    limit_req zone=api burst=20 nodelay;
    
    location / {
        proxy_pass http://pq-core-backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Timeouts
        proxy_connect_timeout 30s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
        
        # Health check
        proxy_next_upstream error timeout invalid_header http_500 http_502 http_503;
    }
    
    location /health {
        access_log off;
        proxy_pass http://pq-core-backend;
        proxy_set_header Host $host;
    }
}
```

### HAProxy Configuration

```bash
# /etc/haproxy/haproxy.cfg
global
    daemon
    maxconn 4096
    log stdout local0

defaults
    mode http
    timeout connect 5000ms
    timeout client 50000ms
    timeout server 50000ms
    option httplog
    
frontend pq-core-frontend
    bind *:80
    bind *:443 ssl crt /etc/ssl/certs/pq-core.pem
    redirect scheme https if !{ ssl_fc }
    
    # Rate limiting
    stick-table type ip size 100k expire 30s store http_req_rate(10s)
    http-request track-sc0 src
    http-request deny if { sc_http_req_rate(0) gt 20 }
    
    default_backend pq-core-backend

backend pq-core-backend
    balance roundrobin
    option httpchk GET /health
    
    server api1 127.0.0.1:3000 check
    server api2 127.0.0.1:3001 check
    server api3 127.0.0.1:3002 check
```

## Monitoring Setup

### Prometheus Configuration

```yaml
# prometheus.yml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'pq-core-api'
    static_configs:
      - targets: ['localhost:3000']
    metrics_path: /metrics
    scrape_interval: 10s
```

### Grafana Dashboard

```json
{
  "dashboard": {
    "title": "PQ-Core API Dashboard",
    "panels": [
      {
        "title": "Request Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(http_requests_total[5m])",
            "legendFormat": "{{method}} {{endpoint}}"
          }
        ]
      },
      {
        "title": "Response Time",
        "type": "graph", 
        "targets": [
          {
            "expr": "histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m]))",
            "legendFormat": "95th percentile"
          }
        ]
      }
    ]
  }
}
```

## Troubleshooting

### Common Issues

**Port Already in Use**:
```bash
# Find process using port 3000
sudo lsof -i :3000
# Kill the process
sudo kill -9 PID
```

**Permission Denied**:
```bash
# Check file permissions
ls -la ./target/release/rest-api
# Make executable
chmod +x ./target/release/rest-api
```

**SSL Certificate Issues**:
```bash
# Generate self-signed certificate for testing
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
```

**Memory Issues**:
```bash
# Check memory usage
free -h
# Check process memory
ps aux | grep rest-api
```

### Log Analysis

**View Logs**:
```bash
# Application logs
tail -f /var/log/pq-core/pq-core.log

# System logs
journalctl -u pq-core-api -f

# Docker logs
docker logs -f pq-core-api
```

**Log Patterns to Watch**:
- High error rates (>1% of requests)
- Slow responses (>1000ms)
- Authentication failures
- Rate limit violations
- Memory allocation errors

### Performance Tuning

**Rust Optimization**:
```toml
# Cargo.toml
[profile.release]
lto = true
codegen-units = 1
panic = "abort"
```

**System Tuning**:
```bash
# Increase file descriptor limits
echo "* soft nofile 65536" >> /etc/security/limits.conf
echo "* hard nofile 65536" >> /etc/security/limits.conf

# Optimize network settings
echo "net.core.somaxconn = 65536" >> /etc/sysctl.conf
echo "net.ipv4.tcp_max_syn_backlog = 65536" >> /etc/sysctl.conf
sysctl -p
```

## Next Steps

- **First API Call**: Try the [Quick Start Guide](quickstart.md)
- **Security Setup**: Configure [API Security Features](../security/api-security.md)
- **Monitoring**: Set up [Monitoring & Observability](../advanced/monitoring.md)
- **Production**: Review [Production Deployment](../advanced/deployment.md) best practices

---

*Installation complete? Make your first API call with the [Quick Start Guide](quickstart.md).*