#!/bin/bash

# Deployment script for Cypheron Core
# Usage: ./deploy.sh [environment] [image_tag]

set -e

ENVIRONMENT=${1:-production}
IMAGE_TAG=${2:-latest}
REGISTRY="ghcr.io"
IMAGE_NAME="cypheron-labs/cypheron-core"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}🚀 Deploying Cypheron Core${NC}"
echo -e "${YELLOW}Environment: $ENVIRONMENT${NC}"
echo -e "${YELLOW}Image Tag: $IMAGE_TAG${NC}"

# Check if docker-compose file exists
COMPOSE_FILE="docker-compose.${ENVIRONMENT}.yml"
if [ ! -f "$COMPOSE_FILE" ]; then
    echo -e "${RED}❌ Docker compose file not found: $COMPOSE_FILE${NC}"
    exit 1
fi

# Update image tag in docker-compose file
sed -i "s|image: ${REGISTRY}/${IMAGE_NAME}:.*|image: ${REGISTRY}/${IMAGE_NAME}:${IMAGE_TAG}|" "$COMPOSE_FILE"

echo -e "${GREEN}📦 Pulling latest image...${NC}"
docker pull "${REGISTRY}/${IMAGE_NAME}:${IMAGE_TAG}"

echo -e "${GREEN}🔄 Stopping existing containers...${NC}"
docker-compose -f "$COMPOSE_FILE" down

echo -e "${GREEN}🏗️ Starting containers...${NC}"
docker-compose -f "$COMPOSE_FILE" up -d

echo -e "${GREEN}🔍 Checking container health...${NC}"
sleep 5

if docker-compose -f "$COMPOSE_FILE" ps | grep -q "Up"; then
    echo -e "${GREEN}✅ Deployment successful!${NC}"
    
    echo -e "${GREEN}📊 Container status:${NC}"
    docker-compose -f "$COMPOSE_FILE" ps
    
    echo -e "${GREEN}📝 View logs with:${NC}"
    echo "docker-compose -f $COMPOSE_FILE logs -f"
else
    echo -e "${RED}❌ Deployment failed!${NC}"
    echo -e "${YELLOW}Check logs:${NC}"
    docker-compose -f "$COMPOSE_FILE" logs
    exit 1
fi