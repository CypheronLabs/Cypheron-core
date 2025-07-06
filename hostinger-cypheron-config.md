# Cypheron Labs Hostinger Deployment Configuration

## Domain Structure

### Primary Domains

- **Main Website**: `cypheronlabs.com` (current Hostinger hosting)
- **API Endpoint**: `api.cypheronlabs.com` (new VPS)
- **Documentation**: `docs.cypheronlabs.com` (optional)

## Updated Configuration Files

### Nginx Configuration for Cypheron Labs

```nginx
# /etc/nginx/sites-available/cypheron-api
server {
    listen 80;
    server_name api.cypheronlabs.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name api.cypheronlabs.com;

    # SSL certificates
    ssl_certificate /etc/letsencrypt/live/api.cypheronlabs.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/api.cypheronlabs.com/privkey.pem;

    # Security headers
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    # CORS for Cypheron Labs website
    add_header Access-Control-Allow-Origin "https://cypheronlabs.com" always;
    add_header Access-Control-Allow-Origin "https://www.cypheronlabs.com" always;
    add_header Access-Control-Allow-Methods "GET, POST, OPTIONS" always;
    add_header Access-Control-Allow-Headers "Content-Type, X-API-Key, Authorization" always;

    # Handle preflight requests
    location / {
        if ($request_method = 'OPTIONS') {
            add_header Access-Control-Allow-Origin "https://cypheronlabs.com";
            add_header Access-Control-Allow-Origin "https://www.cypheronlabs.com";
            add_header Access-Control-Allow-Methods "GET, POST, OPTIONS";
            add_header Access-Control-Allow-Headers "Content-Type, X-API-Key, Authorization";
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

        # Rate limiting for production API
        limit_req zone=api burst=20 nodelay;
        limit_req zone=per_ip burst=5 nodelay;
    }

    # Health check endpoint
    location /health {
        proxy_pass http://localhost:3000/health;
        access_log off;
    }

    # API documentation endpoint
    location /docs {
        proxy_pass http://localhost:3000/docs;
    }

    # Metrics endpoint (protected)
    location /metrics {
        allow 127.0.0.1;
        deny all;
        proxy_pass http://localhost:3000/metrics;
    }
}

# Rate limiting zones
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
limit_req_zone $binary_remote_addr zone=per_ip:10m rate=1r/s;
```

### Docker Compose for Cypheron Labs

```yaml
# docker-compose.cypheron.yml
version: '3.8'

services:
  cypheron-api:
    image: cypheron-labs/pq-core-api:latest
    container_name: cypheron-pq-api
    restart: unless-stopped
    ports:
      - "3000:3000"
    environment:
      - RUST_LOG=info
      - PQ_ENVIRONMENT=production
      - PQ_HOST=0.0.0.0
      - PQ_PORT=3000
      - PQ_COMPANY_NAME=Cypheron Labs
      - PQ_API_BASE_URL=https://api.cypheronlabs.com
      - PQ_CORS_ORIGINS=https://cypheronlabs.com,https://www.cypheronlabs.com
      - PQ_TEST_API_KEY=${CYPHERON_API_KEY}
      - PQ_RATE_LIMIT=100
      - PQ_MAX_REQUEST_SIZE=10485760
      - PQ_ENABLE_SOC2=true
      - PQ_ENABLE_GDPR=true
      - PQ_ENABLE_METRICS=true
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
    container_name: cypheron-redis
    restart: unless-stopped
    ports:
      - "127.0.0.1:6379:6379"
    volumes:
      - redis_data:/data
    command: redis-server --appendonly yes

  watchtower:
    image: containrrr/watchtower
    container_name: cypheron-watchtower
    restart: unless-stopped
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    command: --interval 30 --cleanup
    environment:
      - WATCHTOWER_NOTIFICATIONS=email
      - WATCHTOWER_NOTIFICATION_EMAIL_FROM=noreply@cypheronlabs.com
      - WATCHTOWER_NOTIFICATION_EMAIL_TO=admin@cypheronlabs.com

volumes:
  redis_data:
```

### Website Integration for cypheronlabs.com

```javascript
// src/api/cypheronAPI.js
const CYPHERON_API_CONFIG = {
    baseURL: 'https://api.cypheronlabs.com',
    company: 'Cypheron Labs',
    version: 'v1',
    timeout: 15000
};

class CypheronPQAPI {
    constructor(apiKey) {
        this.baseURL = CYPHERON_API_CONFIG.baseURL;
        this.apiKey = apiKey;
        this.company = CYPHERON_API_CONFIG.company;
    }

    async makeRequest(endpoint, options = {}) {
        const url = `${this.baseURL}${endpoint}`;
        const config = {
            headers: {
                'Content-Type': 'application/json',
                'X-API-Key': this.apiKey,
                'User-Agent': 'CypheronLabs-WebClient/1.0',
                ...options.headers
            },
            ...options
        };

        try {
            const response = await fetch(url, config);
            
            if (!response.ok) {
                const errorData = await response.json().catch(() => ({}));
                throw new Error(`Cypheron API Error: ${response.status} - ${errorData.message || response.statusText}`);
            }
            
            return await response.json();
        } catch (error) {
            console.error('Cypheron Labs API request failed:', error);
            throw error;
        }
    }

    // Post-Quantum Key Encapsulation Mechanisms
    async generateKEMKeys(algorithm = 'kyber768') {
        return this.makeRequest(`/kem/${algorithm}/keygen`, {
            method: 'POST'
        });
    }

    async encapsulateSecret(algorithm, publicKey) {
        return this.makeRequest(`/kem/${algorithm}/encapsulate`, {
            method: 'POST',
            body: JSON.stringify({ pk: publicKey })
        });
    }

    async decapsulateSecret(algorithm, privateKey, ciphertext) {
        return this.makeRequest(`/kem/${algorithm}/decapsulate`, {
            method: 'POST',
            body: JSON.stringify({ 
                sk: privateKey, 
                ct: ciphertext 
            })
        });
    }

    // Post-Quantum Digital Signatures
    async generateSignatureKeys(algorithm = 'dilithium3') {
        return this.makeRequest(`/sig/${algorithm}/keygen`, {
            method: 'POST'
        });
    }

    async signDocument(algorithm, privateKey, document) {
        const encodedDocument = btoa(document);
        return this.makeRequest(`/sig/${algorithm}/sign`, {
            method: 'POST',
            body: JSON.stringify({
                sk: privateKey,
                message: encodedDocument
            })
        });
    }

    async verifySignature(algorithm, publicKey, document, signature) {
        const encodedDocument = btoa(document);
        return this.makeRequest(`/sig/${algorithm}/verify`, {
            method: 'POST',
            body: JSON.stringify({
                pk: publicKey,
                message: encodedDocument,
                signature: signature
            })
        });
    }

    // Hybrid Cryptography (Classical + Post-Quantum)
    async createHybridSignature(document, classicalAlg = 'ed25519', pqAlg = 'dilithium3') {
        const encodedDocument = btoa(document);
        return this.makeRequest('/hybrid/sign', {
            method: 'POST',
            body: JSON.stringify({
                message: encodedDocument,
                classical_algorithm: classicalAlg,
                pq_algorithm: pqAlg
            })
        });
    }

    // Utility methods
    async getAlgorithmInfo(type, algorithm) {
        return this.makeRequest(`/${type}/${algorithm}/info`);
    }

    async healthCheck() {
        return this.makeRequest('/health');
    }
}

// Export for use in Cypheron Labs website
export default CypheronPQAPI;

// Also provide a factory function
export function createCypheronAPI(apiKey) {
    return new CypheronPQAPI(apiKey);
}
```

### React Component for Cypheron Labs Website

```jsx
// src/components/PQCryptoDemo.jsx
import React, { useState, useEffect } from 'react';
import { createCypheronAPI } from '../api/cypheronAPI';

const PQCryptoDemo = ({ apiKey }) => {
    const [api] = useState(() => createCypheronAPI(apiKey));
    const [keys, setKeys] = useState(null);
    const [document, setDocument] = useState('');
    const [signature, setSignature] = useState('');
    const [loading, setLoading] = useState(false);
    const [status, setStatus] = useState('');

    useEffect(() => {
        // Check API health on component mount
        api.healthCheck()
            .then(() => setStatus('Connected to Cypheron Labs API'))
            .catch(() => setStatus('Unable to connect to Cypheron Labs API'));
    }, [api]);

    const generateKeys = async () => {
        setLoading(true);
        try {
            const newKeys = await api.generateSignatureKeys('dilithium3');
            setKeys(newKeys);
            setStatus('Keys generated successfully');
        } catch (error) {
            setStatus(`Key generation failed: ${error.message}`);
        }
        setLoading(false);
    };

    const signDocument = async () => {
        if (!keys || !document) return;
        
        setLoading(true);
        try {
            const result = await api.signDocument('dilithium3', keys.sk, document);
            setSignature(result.signature);
            setStatus('Document signed with post-quantum cryptography');
        } catch (error) {
            setStatus(`Signing failed: ${error.message}`);
        }
        setLoading(false);
    };

    const verifySignature = async () => {
        if (!keys || !document || !signature) return;
        
        setLoading(true);
        try {
            const result = await api.verifySignature('dilithium3', keys.pk, document, signature);
            setStatus(result.valid 
                ? 'Signature verified successfully! Document is authentic.' 
                : 'Signature verification failed! Document may be tampered.'
            );
        } catch (error) {
            setStatus(`Verification failed: ${error.message}`);
        }
        setLoading(false);
    };

    return (
        <div className="pq-crypto-demo">
            <div className="cypheron-header">
                <h2>Cypheron Labs - Post-Quantum Cryptography Demo</h2>
                <p className="status">{status}</p>
            </div>

            <div className="demo-section">
                <h3>Digital Signature with Dilithium-3</h3>
                
                <div className="key-management">
                    <button 
                        onClick={generateKeys} 
                        disabled={loading}
                        className="cypheron-btn primary"
                    >
                        {loading ? 'Generating...' : 'Generate PQ Keys'}
                    </button>
                    
                    {keys && (
                        <div className="keys-info">
                            <span className="success-indicator">✓</span>
                            <span>Post-quantum keys generated</span>
                        </div>
                    )}
                </div>

                <div className="document-input">
                    <label htmlFor="document">Document to Sign:</label>
                    <textarea
                        id="document"
                        value={document}
                        onChange={(e) => setDocument(e.target.value)}
                        placeholder="Enter your document content here..."
                        rows={4}
                        className="cypheron-textarea"
                    />
                </div>

                <div className="crypto-actions">
                    <button 
                        onClick={signDocument}
                        disabled={!keys || !document || loading}
                        className="cypheron-btn secondary"
                    >
                        Sign with PQ Crypto
                    </button>
                    
                    <button 
                        onClick={verifySignature}
                        disabled={!signature || loading}
                        className="cypheron-btn secondary"
                    >
                        Verify Signature
                    </button>
                </div>

                {signature && (
                    <div className="signature-display">
                        <h4>Post-Quantum Digital Signature</h4>
                        <div className="signature-preview">
                            {signature.substring(0, 100)}...
                        </div>
                        <small>Generated using NIST-standardized Dilithium-3 algorithm</small>
                    </div>
                )}
            </div>

            <div className="cypheron-footer">
                <p>Powered by Cypheron Labs PQ-Core API</p>
            </div>
        </div>
    );
};

export default PQCryptoDemo;
```

### CSS Styling for Cypheron Labs Branding

```css
/* src/styles/cypheron-demo.css */
.pq-crypto-demo {
    max-width: 800px;
    margin: 0 auto;
    padding: 20px;
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
}

.cypheron-header {
    text-align: center;
    margin-bottom: 30px;
    padding: 20px;
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
    border-radius: 10px;
}

.cypheron-header h2 {
    margin: 0 0 10px 0;
    font-size: 24px;
    font-weight: 600;
}

.status {
    margin: 10px 0;
    padding: 8px 16px;
    background: rgba(255, 255, 255, 0.1);
    border-radius: 6px;
    font-size: 14px;
}

.demo-section {
    background: #f8f9fa;
    padding: 25px;
    border-radius: 10px;
    margin: 20px 0;
}

.demo-section h3 {
    color: #333;
    margin-bottom: 20px;
    font-size: 20px;
}

.key-management {
    display: flex;
    align-items: center;
    gap: 15px;
    margin-bottom: 20px;
}

.keys-info {
    display: flex;
    align-items: center;
    gap: 8px;
    color: #28a745;
    font-weight: 500;
}

.success-indicator {
    color: #28a745;
    font-size: 18px;
}

.document-input {
    margin: 20px 0;
}

.document-input label {
    display: block;
    margin-bottom: 8px;
    font-weight: 500;
    color: #333;
}

.cypheron-textarea {
    width: 100%;
    padding: 12px;
    border: 2px solid #e1e5e9;
    border-radius: 6px;
    font-size: 14px;
    line-height: 1.5;
    resize: vertical;
    transition: border-color 0.2s;
}

.cypheron-textarea:focus {
    outline: none;
    border-color: #667eea;
}

.crypto-actions {
    display: flex;
    gap: 15px;
    margin: 20px 0;
}

.cypheron-btn {
    padding: 12px 24px;
    border: none;
    border-radius: 6px;
    font-size: 14px;
    font-weight: 500;
    cursor: pointer;
    transition: all 0.2s;
}

.cypheron-btn.primary {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
}

.cypheron-btn.secondary {
    background: #6c757d;
    color: white;
}

.cypheron-btn:hover:not(:disabled) {
    transform: translateY(-1px);
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
}

.cypheron-btn:disabled {
    opacity: 0.6;
    cursor: not-allowed;
}

.signature-display {
    margin-top: 25px;
    padding: 20px;
    background: white;
    border: 2px solid #e1e5e9;
    border-radius: 8px;
}

.signature-display h4 {
    margin: 0 0 15px 0;
    color: #333;
}

.signature-preview {
    font-family: 'Monaco', 'Menlo', monospace;
    background: #f1f3f4;
    padding: 12px;
    border-radius: 4px;
    word-break: break-all;
    font-size: 12px;
    margin-bottom: 10px;
}

.cypheron-footer {
    text-align: center;
    margin-top: 30px;
    padding: 15px;
    color: #6c757d;
    font-size: 14px;
}
```

### Environment Configuration

```bash
# .env.production for Cypheron Labs
CYPHERON_API_KEY=cypheron_prod_key_12345
COMPANY_NAME="Cypheron Labs"
API_BASE_URL=https://api.cypheronlabs.com
WEBSITE_URL=https://cypheronlabs.com
CONTACT_EMAIL=contact@cypheronlabs.com
SUPPORT_EMAIL=support@cypheronlabs.com
```

### SSL Certificate Setup for Cypheron Labs

```bash
# Set up SSL for api.cypheronlabs.com
certbot --nginx -d api.cypheronlabs.com \
  --email contact@cypheronlabs.com \
  --agree-tos \
  --no-eff-email

# Verify certificate
certbot certificates

# Test auto-renewal
certbot renew --dry-run
```

This configuration is now properly branded for Cypheron Labs and configured for your cypheronlabs.com domain structure.