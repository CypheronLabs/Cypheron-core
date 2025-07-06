# Hostinger Deployment Guide for PQ-Core

## Overview

Hostinger offers several hosting options that work well for your PQ-Core API:

1. **VPS Hosting** (Recommended for API)
2. **Cloud Hosting** (Good for high traffic)
3. **Shared Hosting** (For website only)

## Architecture on Hostinger

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Website       │    │   API Server    │    │  Private Core   │
│  (Shared/Cloud) │───▶│     (VPS)       │───▶│   (Binary)      │
│   Hostinger     │    │   Hostinger     │    │  Never Exposed  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Option 1: VPS Deployment (Recommended)

### Step 1: Set Up Hostinger VPS

```bash
# After creating your VPS on Hostinger, connect via SSH
ssh root@your-vps-ip

# Update system
apt update && apt upgrade -y

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sh get-docker.sh

# Install Docker Compose
curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose

# Install Nginx for reverse proxy
apt install nginx -y

# Install Certbot for SSL
apt install certbot python3-certbot-nginx -y
```

### Step 2: Upload Your API Container

```bash
# Build your container locally (with private core included)
docker build -f Dockerfile.production -t pq-core-api:latest .

# Save container to file
docker save pq-core-api:latest | gzip > pq-core-api.tar.gz

# Upload to your VPS (using SCP or SFTP)
scp pq-core-api.tar.gz root@your-vps-ip:/root/

# On VPS: Load the container
ssh root@your-vps-ip
docker load < pq-core-api.tar.gz
```

### Step 3: Docker Compose for Hostinger VPS

```yaml
# docker-compose.hostinger.yml
version: '3.8'

services:
  pq-core-api:
    image: pq-core-api:latest
    container_name: pq-core-api
    restart: unless-stopped
    ports:
      - "3000:3000"
    environment:
      - RUST_LOG=info
      - PQ_ENVIRONMENT=production
      - PQ_HOST=0.0.0.0
      - PQ_PORT=3000
      - PQ_TEST_API_KEY=${PQ_TEST_API_KEY}
      - PQ_RATE_LIMIT=60
    volumes:
      - ./logs:/app/logs
      - ./config:/app/config:ro
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:3000/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  redis:
    image: redis:alpine
    container_name: pq-redis
    restart: unless-stopped
    ports:
      - "127.0.0.1:6379:6379"
    volumes:
      - redis_data:/data
    command: redis-server --appendonly yes

volumes:
  redis_data:
```

### Step 4: Nginx Configuration for Hostinger

```nginx
# /etc/nginx/sites-available/pq-core-api
server {
    listen 80;
    server_name api.yourdomain.com;  # Use your domain from Hostinger

    # Redirect HTTP to HTTPS
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name api.yourdomain.com;

    # SSL certificates (will be configured by Certbot)
    ssl_certificate /etc/letsencrypt/live/api.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/api.yourdomain.com/privkey.pem;

    # Security headers
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    # CORS for your website
    add_header Access-Control-Allow-Origin "https://yourdomain.com" always;
    add_header Access-Control-Allow-Methods "GET, POST, OPTIONS" always;
    add_header Access-Control-Allow-Headers "Content-Type, X-API-Key" always;

    # Handle preflight requests
    location / {
        if ($request_method = 'OPTIONS') {
            add_header Access-Control-Allow-Origin "https://yourdomain.com";
            add_header Access-Control-Allow-Methods "GET, POST, OPTIONS";
            add_header Access-Control-Allow-Headers "Content-Type, X-API-Key";
            add_header Access-Control-Max-Age 86400;
            add_header Content-Length 0;
            add_header Content-Type text/plain;
            return 204;
        }

        proxy_pass http://localhost:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Rate limiting for API protection
        limit_req zone=api burst=10 nodelay;
    }

    # Health check endpoint
    location /health {
        proxy_pass http://localhost:3000/health;
        access_log off;
    }
}

# Rate limiting configuration
http {
    limit_req_zone $binary_remote_addr zone=api:10m rate=5r/s;
}
```

### Step 5: SSL Setup with Certbot

```bash
# Enable the site
ln -s /etc/nginx/sites-available/pq-core-api /etc/nginx/sites-enabled/
nginx -t  # Test configuration
systemctl reload nginx

# Get SSL certificate
certbot --nginx -d api.yourdomain.com

# Auto-renewal (certbot usually sets this up automatically)
crontab -e
# Add: 0 12 * * * /usr/bin/certbot renew --quiet
```

## Option 2: Hostinger Cloud Hosting

For high-traffic websites, use Hostinger's Cloud Hosting:

### Cloud Deployment Script

```bash
#!/bin/bash
# deploy-to-hostinger-cloud.sh

# Upload via SFTP to cloud hosting
# Note: Cloud hosting might have specific deployment requirements

# Create deployment package
mkdir -p deployment
cp docker-compose.hostinger.yml deployment/
cp -r nginx/ deployment/
cp pq-core-api.tar.gz deployment/

# Upload to Hostinger Cloud (adjust path as needed)
scp -r deployment/ user@your-cloud-host:/path/to/deployment/

# SSH into cloud host and deploy
ssh user@your-cloud-host << 'EOF'
cd /path/to/deployment
docker load < pq-core-api.tar.gz
docker-compose -f docker-compose.hostinger.yml up -d
EOF
```

## Website Integration on Hostinger

### Frontend Website Setup

If your website is also on Hostinger, here's how to integrate:

```javascript
// For websites hosted on Hostinger
// src/config/api.js
const API_CONFIG = {
    // Use your Hostinger VPS domain/IP for API
    baseURL: 'https://api.yourdomain.com',
    apiKey: process.env.REACT_APP_PQ_API_KEY || 'your-api-key',
    timeout: 10000
};

class PQCoreAPI {
    constructor() {
        this.baseURL = API_CONFIG.baseURL;
        this.apiKey = API_CONFIG.apiKey;
    }

    async makeRequest(endpoint, options = {}) {
        const url = `${this.baseURL}${endpoint}`;
        const config = {
            headers: {
                'Content-Type': 'application/json',
                'X-API-Key': this.apiKey,
                ...options.headers
            },
            ...options
        };

        try {
            const response = await fetch(url, config);
            if (!response.ok) {
                throw new Error(`API request failed: ${response.status}`);
            }
            return await response.json();
        } catch (error) {
            console.error('API request error:', error);
            throw error;
        }
    }

    // KEM operations
    async generateKemKeys(algorithm = 'kyber768') {
        return this.makeRequest(`/kem/${algorithm}/keygen`, {
            method: 'POST'
        });
    }

    async encapsulate(algorithm, publicKey) {
        return this.makeRequest(`/kem/${algorithm}/encapsulate`, {
            method: 'POST',
            body: JSON.stringify({ pk: publicKey })
        });
    }

    // Signature operations
    async generateSigKeys(algorithm = 'dilithium3') {
        return this.makeRequest(`/sig/${algorithm}/keygen`, {
            method: 'POST'
        });
    }

    async signMessage(algorithm, privateKey, message) {
        const encodedMessage = btoa(message); // Base64 encode
        return this.makeRequest(`/sig/${algorithm}/sign`, {
            method: 'POST',
            body: JSON.stringify({
                sk: privateKey,
                message: encodedMessage
            })
        });
    }

    async verifySignature(algorithm, publicKey, message, signature) {
        const encodedMessage = btoa(message);
        return this.makeRequest(`/sig/${algorithm}/verify`, {
            method: 'POST',
            body: JSON.stringify({
                pk: publicKey,
                message: encodedMessage,
                signature: signature
            })
        });
    }
}

export default PQCoreAPI;
```

### HTML Integration Example

```html
<!-- For static websites on Hostinger -->
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PQ-Core Demo</title>
    <style>
        .container { max-width: 800px; margin: 0 auto; padding: 20px; }
        .section { margin: 20px 0; padding: 20px; border: 1px solid #ddd; }
        button { padding: 10px 20px; margin: 5px; cursor: pointer; }
        textarea { width: 100%; height: 100px; margin: 10px 0; }
        .result { background: #f5f5f5; padding: 10px; margin: 10px 0; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Post-Quantum Cryptography Demo</h1>
        
        <div class="section">
            <h2>Digital Signature</h2>
            <button onclick="generateKeys()">Generate Keys</button>
            <div id="keys-result"></div>
            
            <textarea id="message" placeholder="Enter message to sign..."></textarea>
            <button onclick="signMessage()">Sign Message</button>
            <button onclick="verifySignature()">Verify Signature</button>
            <div id="signature-result"></div>
        </div>
    </div>

    <script>
        // Simple JavaScript integration
        const API_BASE = 'https://api.yourdomain.com';
        const API_KEY = 'your-api-key'; // In production, get this securely
        
        let currentKeys = null;
        let currentSignature = null;

        async function apiCall(endpoint, options = {}) {
            const response = await fetch(`${API_BASE}${endpoint}`, {
                headers: {
                    'Content-Type': 'application/json',
                    'X-API-Key': API_KEY,
                    ...options.headers
                },
                ...options
            });
            return response.json();
        }

        async function generateKeys() {
            try {
                const keys = await apiCall('/sig/dilithium3/keygen', { method: 'POST' });
                currentKeys = keys;
                document.getElementById('keys-result').innerHTML = `
                    <div class="result">
                        <strong>Keys Generated!</strong><br>
                        Public Key: ${keys.pk.substring(0, 50)}...<br>
                        Private Key: ${keys.sk.substring(0, 50)}...
                    </div>
                `;
            } catch (error) {
                console.error('Key generation failed:', error);
            }
        }

        async function signMessage() {
            if (!currentKeys) {
                alert('Please generate keys first');
                return;
            }

            const message = document.getElementById('message').value;
            if (!message) {
                alert('Please enter a message');
                return;
            }

            try {
                const encodedMessage = btoa(message);
                const result = await apiCall('/sig/dilithium3/sign', {
                    method: 'POST',
                    body: JSON.stringify({
                        sk: currentKeys.sk,
                        message: encodedMessage
                    })
                });
                
                currentSignature = result.signature;
                document.getElementById('signature-result').innerHTML = `
                    <div class="result">
                        <strong>Message Signed!</strong><br>
                        Signature: ${result.signature.substring(0, 100)}...
                    </div>
                `;
            } catch (error) {
                console.error('Signing failed:', error);
            }
        }

        async function verifySignature() {
            if (!currentKeys || !currentSignature) {
                alert('Please generate keys and sign a message first');
                return;
            }

            const message = document.getElementById('message').value;
            const encodedMessage = btoa(message);

            try {
                const result = await apiCall('/sig/dilithium3/verify', {
                    method: 'POST',
                    body: JSON.stringify({
                        pk: currentKeys.pk,
                        message: encodedMessage,
                        signature: currentSignature
                    })
                });

                document.getElementById('signature-result').innerHTML += `
                    <div class="result">
                        <strong>Verification Result:</strong> ${result.valid ? 'Valid ✅' : 'Invalid ❌'}
                    </div>
                `;
            } catch (error) {
                console.error('Verification failed:', error);
            }
        }
    </script>
</body>
</html>
```

## Deployment Checklist for Hostinger

### 1. VPS Setup
- [ ] Create Hostinger VPS
- [ ] Install Docker and Docker Compose
- [ ] Configure domain/subdomain (api.yourdomain.com)
- [ ] Set up firewall (allow ports 80, 443, 22)

### 2. API Deployment
- [ ] Build Docker container with private core library
- [ ] Upload container to VPS
- [ ] Configure environment variables
- [ ] Set up Nginx reverse proxy
- [ ] Obtain SSL certificate with Certbot

### 3. Website Integration
- [ ] Update API endpoints in website code
- [ ] Configure CORS properly
- [ ] Test API calls from website
- [ ] Set up monitoring and logging

### 4. Security
- [ ] Configure API rate limiting
- [ ] Set up proper API key management
- [ ] Enable security headers
- [ ] Configure firewall rules
- [ ] Set up automated backups

## Monitoring and Maintenance

### Log Management
```bash
# Set up log rotation
cat > /etc/logrotate.d/pq-core-api << 'EOF'
/path/to/logs/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    sharedscripts
    postrotate
        docker-compose restart pq-core-api
    endscript
}
EOF
```

### Health Monitoring
```bash
# Simple health check script
cat > /root/health-check.sh << 'EOF'
#!/bin/bash
if ! curl -f http://localhost:3000/health > /dev/null 2>&1; then
    echo "API health check failed, restarting..."
    docker-compose restart pq-core-api
fi
EOF

# Add to crontab
crontab -e
# Add: */5 * * * * /root/health-check.sh
```

## Cost Optimization

Hostinger VPS pricing is very reasonable:
- **VPS 1**: ~$3.99/month - Good for testing
- **VPS 2**: ~$8.99/month - Recommended for production
- **VPS 4**: ~$17.99/month - For high traffic

This setup gives you professional-grade deployment while keeping costs low and your core cryptographic code completely private.