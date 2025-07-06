# Website Integration Guide

## Architecture Overview

For website access, use this three-tier architecture:

```
Website (Public) → API Server (Public Container) → Core Library (Private Binary)
```

## 1. Frontend Website Setup

### Option A: Static Site with API Calls
```javascript
// website/src/api/pqcore.js
class PQCoreAPI {
    constructor(apiUrl = 'https://api.yourcompany.com') {
        this.apiUrl = apiUrl;
        this.apiKey = process.env.REACT_APP_PQ_API_KEY;
    }

    async generateKeys(algorithm = 'kyber768') {
        const response = await fetch(`${this.apiUrl}/kem/${algorithm}/keygen`, {
            method: 'POST',
            headers: {
                'X-API-Key': this.apiKey,
                'Content-Type': 'application/json'
            }
        });
        return response.json();
    }

    async signDocument(algorithm, privateKey, document) {
        const message = btoa(document); // Base64 encode
        const response = await fetch(`${this.apiUrl}/sig/${algorithm}/sign`, {
            method: 'POST',
            headers: {
                'X-API-Key': this.apiKey,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                private_key: privateKey,
                message: message
            })
        });
        return response.json();
    }

    async verifySignature(algorithm, publicKey, document, signature) {
        const message = btoa(document);
        const response = await fetch(`${this.apiUrl}/sig/${algorithm}/verify`, {
            method: 'POST',
            headers: {
                'X-API-Key': this.apiKey,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                public_key: publicKey,
                message: message,
                signature: signature
            })
        });
        return response.json();
    }
}

export default PQCoreAPI;
```

### Option B: React Component Example
```jsx
// website/src/components/DocumentSigner.jsx
import React, { useState } from 'react';
import PQCoreAPI from '../api/pqcore';

const DocumentSigner = () => {
    const [document, setDocument] = useState('');
    const [signature, setSignature] = useState('');
    const [keys, setKeys] = useState(null);
    const [loading, setLoading] = useState(false);
    const api = new PQCoreAPI();

    const generateKeys = async () => {
        setLoading(true);
        try {
            const newKeys = await api.generateKeys('dilithium3');
            setKeys(newKeys);
        } catch (error) {
            console.error('Key generation failed:', error);
        }
        setLoading(false);
    };

    const signDocument = async () => {
        if (!keys || !document) return;
        
        setLoading(true);
        try {
            const result = await api.signDocument('dilithium3', keys.sk, document);
            setSignature(result.signature);
        } catch (error) {
            console.error('Signing failed:', error);
        }
        setLoading(false);
    };

    const verifySignature = async () => {
        if (!keys || !document || !signature) return;
        
        try {
            const result = await api.verifySignature('dilithium3', keys.pk, document, signature);
            alert(result.valid ? 'Signature is valid!' : 'Signature is invalid!');
        } catch (error) {
            console.error('Verification failed:', error);
        }
    };

    return (
        <div className="document-signer">
            <h2>Post-Quantum Document Signing</h2>
            
            <div className="key-section">
                <button onClick={generateKeys} disabled={loading}>
                    {loading ? 'Generating...' : 'Generate Keys'}
                </button>
                {keys && (
                    <div className="keys-display">
                        <p>✅ Keys generated successfully</p>
                        <details>
                            <summary>View Public Key</summary>
                            <code>{keys.pk.substring(0, 100)}...</code>
                        </details>
                    </div>
                )}
            </div>

            <div className="document-section">
                <h3>Document to Sign</h3>
                <textarea
                    value={document}
                    onChange={(e) => setDocument(e.target.value)}
                    placeholder="Enter your document content here..."
                    rows={6}
                    cols={60}
                />
            </div>

            <div className="actions">
                <button 
                    onClick={signDocument} 
                    disabled={!keys || !document || loading}
                >
                    Sign Document
                </button>
                
                <button 
                    onClick={verifySignature} 
                    disabled={!signature || loading}
                >
                    Verify Signature
                </button>
            </div>

            {signature && (
                <div className="signature-section">
                    <h3>Digital Signature</h3>
                    <div className="signature-display">
                        <code>{signature.substring(0, 200)}...</code>
                    </div>
                </div>
            )}
        </div>
    );
};

export default DocumentSigner;
```

## 2. API Server Deployment

### Docker Build Strategy
```dockerfile
# Dockerfile.website-api
# Multi-stage build that includes private library as binary

FROM rust:1.75 as private-builder
# This stage runs in your private CI/CD environment
WORKDIR /app
COPY core-lib ./core-lib
RUN cd core-lib && cargo build --release

FROM rust:1.75 as api-builder
# This stage builds the public API
WORKDIR /app
COPY rest-api ./rest-api

# Copy the compiled private library (binary only, no source)
COPY --from=private-builder /app/core-lib/target/release/deps/libcore_lib* ./lib/

# Build the API server
RUN cd rest-api && cargo build --release

# Final runtime image
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates curl && rm -rf /var/lib/apt/lists/*

# Copy only the compiled binaries
COPY --from=api-builder /app/rest-api/target/release/rest-api /app/pq-core-api
COPY --from=api-builder /app/lib/* /usr/local/lib/

EXPOSE 3000
CMD ["/app/pq-core-api"]
```

### Cloud Deployment
```yaml
# docker-compose.cloud.yml
version: '3.8'

services:
  pq-core-api:
    image: your-registry/pq-core-api:latest
    ports:
      - "3000:3000"
    environment:
      - RUST_LOG=info
      - PQ_ENVIRONMENT=production
      - PQ_HOST=0.0.0.0
      - PQ_PORT=3000
      - PQ_CORS_ORIGINS=https://yourwebsite.com,https://www.yourwebsite.com
    restart: unless-stopped
    
  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
      - ./ssl:/etc/ssl:ro
    depends_on:
      - pq-core-api
    restart: unless-stopped
```

### NGINX Configuration for Website Integration
```nginx
# nginx/nginx.conf
events {
    worker_connections 1024;
}

http {
    upstream pq_core_api {
        server pq-core-api:3000;
    }

    server {
        listen 80;
        server_name api.yourcompany.com;
        return 301 https://$server_name$request_uri;
    }

    server {
        listen 443 ssl http2;
        server_name api.yourcompany.com;

        ssl_certificate /etc/ssl/cert.pem;
        ssl_certificate_key /etc/ssl/key.pem;

        # CORS headers for website integration
        add_header Access-Control-Allow-Origin "https://yourwebsite.com" always;
        add_header Access-Control-Allow-Methods "GET, POST, OPTIONS" always;
        add_header Access-Control-Allow-Headers "Content-Type, X-API-Key" always;

        # Handle preflight requests
        location / {
            if ($request_method = 'OPTIONS') {
                add_header Access-Control-Allow-Origin "https://yourwebsite.com";
                add_header Access-Control-Allow-Methods "GET, POST, OPTIONS";
                add_header Access-Control-Allow-Headers "Content-Type, X-API-Key";
                add_header Access-Control-Max-Age 86400;
                add_header Content-Length 0;
                add_header Content-Type text/plain;
                return 204;
            }

            proxy_pass http://pq_core_api;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;

            # Rate limiting
            limit_req zone=api burst=20 nodelay;
        }

        # Health check endpoint
        location /health {
            proxy_pass http://pq_core_api/health;
        }
    }

    # Rate limiting zone
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
}
```

## 3. CI/CD Pipeline for Website Integration

### GitHub Actions Workflow
```yaml
# .github/workflows/deploy-website-api.yml
name: Deploy Website API

on:
  push:
    branches: [ main ]

jobs:
  build-private:
    runs-on: ubuntu-latest
    environment: private-build
    steps:
    - uses: actions/checkout@v3
      with:
        token: ${{ secrets.PRIVATE_REPO_TOKEN }}
        repository: your-org/pq-core-lib-private
        
    - name: Build private core library
      run: |
        cd core-lib
        cargo build --release
        
    - name: Upload core library artifacts
      uses: actions/upload-artifact@v3
      with:
        name: core-lib-binaries
        path: core-lib/target/release/deps/libcore_lib*

  build-and-deploy:
    needs: build-private
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    
    - name: Download core library artifacts
      uses: actions/download-artifact@v3
      with:
        name: core-lib-binaries
        path: ./lib/
        
    - name: Build Docker image
      run: |
        docker build -f Dockerfile.website-api -t pq-core-api:latest .
        docker tag pq-core-api:latest ${{ secrets.DOCKER_REGISTRY }}/pq-core-api:latest
        
    - name: Push to registry
      run: |
        echo ${{ secrets.DOCKER_PASSWORD }} | docker login -u ${{ secrets.DOCKER_USERNAME }} --password-stdin
        docker push ${{ secrets.DOCKER_REGISTRY }}/pq-core-api:latest
        
    - name: Deploy to cloud
      run: |
        # Deploy to your cloud provider (AWS, GCP, Azure)
        # This depends on your chosen platform
        echo "Deploying to production..."
```

## 4. Security Considerations for Website Integration

### API Key Management
```javascript
// For website integration, use environment-specific API keys
const apiConfig = {
    development: {
        apiUrl: 'http://localhost:3000',
        apiKey: process.env.REACT_APP_DEV_API_KEY
    },
    production: {
        apiUrl: 'https://api.yourcompany.com',
        apiKey: process.env.REACT_APP_PROD_API_KEY
    }
};

const config = apiConfig[process.env.NODE_ENV] || apiConfig.development;
```

### Rate Limiting for Website Traffic
```rust
// In your API server - adjust for website traffic patterns
use tower_governor::{governor::GovernorConfigBuilder, GovernorLayer};

let config = GovernorConfigBuilder::default()
    .per_second(10)  // Allow 10 requests per second per IP
    .burst_size(30)  // Allow bursts up to 30 requests
    .finish()
    .unwrap();

let app = Router::new()
    .route("/", get(handler))
    .layer(GovernorLayer { config });
```

### CORS Configuration
```rust
// In your API server
use tower_http::cors::{CorsLayer, Any};

let cors = CorsLayer::new()
    .allow_origin("https://yourwebsite.com".parse::<HeaderValue>().unwrap())
    .allow_methods([Method::GET, Method::POST])
    .allow_headers([header::CONTENT_TYPE, HeaderName::from_static("x-api-key")]);

let app = Router::new()
    .route("/", get(handler))
    .layer(cors);
```

## 5. Deployment Options Comparison

| Option | Public Code | Private Code | Best For |
|--------|-------------|--------------|----------|
| **Container Deployment** | Website + API Container | Binary only in container | **Recommended for websites** |
| **Serverless Functions** | Website + Lambda functions | Binary in deployment package | High-scale websites |
| **Managed Service** | Website only | Hosted API service | Enterprise customers |

## 6. Example Website Structure

```
your-website/
├── public/
│   ├── index.html
│   └── favicon.ico
├── src/
│   ├── components/
│   │   ├── DocumentSigner.jsx
│   │   ├── KeyGenerator.jsx
│   │   └── SignatureVerifier.jsx
│   ├── api/
│   │   └── pqcore.js
│   ├── App.js
│   └── index.js
├── .env.development
├── .env.production
└── package.json
```

## Summary

**For website access, use the containerized deployment approach:**

1. **Frontend website** (public) calls your API
2. **API server** runs in Docker container (public container, private binary)
3. **Core library** compiled into the container (never exposed as source)

This gives you:
- ✅ **Complete privacy** of your cryptographic implementations
- ✅ **Easy website integration** via standard REST API calls
- ✅ **Scalable deployment** using standard cloud services
- ✅ **Professional architecture** that can handle production traffic
- ✅ **No source code exposure** - only compiled binaries in containers

The container approach is perfect for websites because it provides a clean API interface that any frontend can consume while keeping your proprietary code completely private.