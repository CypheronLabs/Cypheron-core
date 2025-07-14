#!/bin/bash
set -euo pipefail

# Production Docker Setup Script for Cypheron API
# This script sets up Docker secrets and initializes the production environment

echo "🔐 Setting up Cypheron API Production Environment"

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "❌ Docker is not running. Please start Docker and try again."
    exit 1
fi

# Check if we're in swarm mode for secrets support
if ! docker node ls > /dev/null 2>&1; then
    echo "🔄 Initializing Docker Swarm for secrets support..."
    docker swarm init --advertise-addr 127.0.0.1
fi

# Function to create a Docker secret
create_secret() {
    local secret_name=$1
    local secret_value=$2
    
    if docker secret inspect "$secret_name" > /dev/null 2>&1; then
        echo "⚠️  Secret $secret_name already exists. Skipping..."
    else
        echo "$secret_value" | docker secret create "$secret_name" -
        echo "✅ Created secret: $secret_name"
    fi
}

# Generate secure database credentials
DB_NAME="cypheron_crypto"
DB_USER="pq_user_$(openssl rand -hex 4)"
DB_PASSWORD="$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-25)"

echo "🔑 Creating database secrets..."
create_secret "pq_core_db_name" "$DB_NAME"
create_secret "pq_core_db_user" "$DB_USER"  
create_secret "pq_core_db_password" "$DB_PASSWORD"

# Create .env.production if it doesn't exist
if [ ! -f ".env.production" ]; then
    echo "📝 Creating .env.production file..."
    
    # Generate secure values
    ENCRYPTION_PASSWORD="$(openssl rand -base64 32)"
    REDIS_PASSWORD="$(openssl rand -base64 16)"
    
    cat > .env.production << EOF
# Production Environment Variables - Generated $(date)
DATABASE_URL=postgresql://${DB_USER}:${DB_PASSWORD}@postgres:5432/${DB_NAME}
PQ_ENCRYPTION_PASSWORD=${ENCRYPTION_PASSWORD}
REDIS_PASSWORD=${REDIS_PASSWORD}
EOF
    
    echo "✅ Created .env.production with secure random values"
    echo "⚠️  IMPORTANT: .env.production contains sensitive data - do not commit to git!"
else
    echo "⚠️  .env.production already exists. Keeping existing values."
fi

# Create logs directory
mkdir -p logs
chmod 755 logs

echo ""
echo "🎉 Production environment setup complete!"
echo ""
echo "Generated credentials:"
echo "  Database: $DB_NAME"
echo "  User: $DB_USER"
echo "  Password: [hidden]"
echo ""
echo "Next steps:"
echo "  1. Review .env.production file"
echo "  2. Run: docker-compose -f docker-compose.production.yml up -d"
echo "  3. Check logs: docker-compose -f docker-compose.production.yml logs -f"
echo ""
echo "🔐 Secrets stored in Docker Swarm:"
docker secret ls | grep pq_core || echo "  No secrets found"