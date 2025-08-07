#!/bin/bash

set -e

echo "🔄 Starting Local PostgreSQL Test Environment for Cypheron API"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if ! command -v docker &> /dev/null; then
    echo "❌ Docker is required but not installed. Please install Docker first."
    exit 1
fi

if ! command -v docker compose &> /dev/null; then
    echo "❌ Docker Compose is required but not installed. Please install Docker Compose first."
    exit 1
fi

export POSTGRES_DB="${POSTGRES_DB:-cypheron_test}"
export POSTGRES_USER="${POSTGRES_USER:-cypheron_user}"
export POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-test_password_123}"
export DB_HOST="${DB_HOST:-localhost}"
export DB_PORT="${DB_PORT:-5432}"
export DB_NAME="$POSTGRES_DB"
export DB_USER="$POSTGRES_USER"
export USE_POSTGRESQL="${USE_POSTGRESQL:-true}"
export PQ_ENCRYPTION_PASSWORD="${PQ_ENCRYPTION_PASSWORD:-test_encryption_password_minimum_32_chars}"
export PQ_MASTER_ADMIN_KEY="${PQ_MASTER_ADMIN_KEY:-test_admin_key_minimum_32_characters}"
export GOOGLE_CLOUD_PROJECT_ID="${GOOGLE_CLOUD_PROJECT_ID:-local-test-project}"
export PQ_ENVIRONMENT="${PQ_ENVIRONMENT:-development}"

echo "📊 Test Environment Configuration:"
echo "  - Database: PostgreSQL"
echo "  - Host: $DB_HOST:$DB_PORT"
echo "  - Database Name: $DB_NAME"
echo "  - Username: $DB_USER"
echo "  - USE_POSTGRESQL: $USE_POSTGRESQL"

if [ ! -f "docker-compose.local.yml" ]; then
    echo "❌ docker-compose.local.yml not found. Creating it first..."
    exit 1
fi

echo "🚀 Starting PostgreSQL container..."
docker compose -f docker-compose.local.yml up -d postgresql

echo "⏳ Waiting for PostgreSQL to be ready..."
for i in {1..30}; do
    if docker compose -f docker-compose.local.yml exec postgresql pg_isready -h localhost -U "$POSTGRES_USER" -d "$POSTGRES_DB" > /dev/null 2>&1; then
        echo "✅ PostgreSQL is ready!"
        break
    fi
    if [ $i -eq 30 ]; then
        echo "❌ PostgreSQL failed to start within 30 seconds"
        docker compose -f docker-compose.local.yml logs postgresql
        exit 1
    fi
    sleep 1
done

echo "🔧 Running database schema setup..."
if [ -f "rest-api/db/schema.sql" ]; then
    docker compose -f docker-compose.local.yml exec -T postgresql psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" < rest-api/db/schema.sql
    echo "✅ Database schema applied successfully"
else
    echo "⚠️  Schema file rest-api/db/schema.sql not found, skipping schema setup"
fi

echo "🏗️  Building Rust application with PostgreSQL support..."
cd rest-api
if ! cargo build --bin rest-api; then
    echo "❌ Failed to build Rust application"
    exit 1
fi
echo "✅ Application built successfully"

echo "🚀 Starting Cypheron API server with PostgreSQL backend..."
echo "📝 Server will be available at: http://localhost:3000"
echo "🔍 Health endpoint: http://localhost:3000/health"
echo "🔍 Detailed health: http://localhost:3000/health/detailed"
echo ""
echo "Press Ctrl+C to stop the server"

trap 'echo "🛑 Stopping services..."; docker compose -f ../docker-compose.local.yml down; exit 0' INT

PORT=3000 DATABASE_URL="postgresql://$DB_USER:$POSTGRES_PASSWORD@$DB_HOST:$DB_PORT/$DB_NAME" \
PQ_HOST="0.0.0.0" \
PQ_PORT="3000" \
cargo run --bin rest-api