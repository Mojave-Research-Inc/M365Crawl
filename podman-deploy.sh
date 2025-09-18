#!/bin/bash

#############################################################################
# M365 Big Brain Crawl - Podman Deployment Script
# Containerized deployment for development and production
#############################################################################

set -e

# Configuration
CONTAINER_NAME="m365-brain-crawl"
IMAGE_NAME="m365-brain-crawl:latest"
REGISTRY="${REGISTRY:-localhost}"
PORT="${PORT:-7071}"

# Color codes
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}M365 Big Brain Crawl - Podman Deployment${NC}"
echo "========================================="

# Build container
echo -e "${YELLOW}Building container image...${NC}"
podman build -t ${IMAGE_NAME} -f Containerfile .

# Tag for registry if not localhost
if [ "$REGISTRY" != "localhost" ]; then
    echo -e "${YELLOW}Tagging image for registry ${REGISTRY}...${NC}"
    podman tag ${IMAGE_NAME} ${REGISTRY}/${IMAGE_NAME}
fi

# Stop existing container if running
if podman ps -a | grep -q ${CONTAINER_NAME}; then
    echo -e "${YELLOW}Stopping existing container...${NC}"
    podman stop ${CONTAINER_NAME} 2>/dev/null || true
    podman rm ${CONTAINER_NAME} 2>/dev/null || true
fi

# Run container with proper configuration
echo -e "${YELLOW}Starting container...${NC}"
podman run -d \
    --name ${CONTAINER_NAME} \
    -p ${PORT}:80 \
    -v ~/.cache/uv:/root/.cache/uv:Z \
    -v $(pwd):/workspace:Z \
    --env-file .env \
    --restart unless-stopped \
    ${IMAGE_NAME}

# Create .env file template if it doesn't exist
if [ ! -f .env ]; then
    echo -e "${YELLOW}Creating .env template...${NC}"
    cat > .env <<'EOF'
# Azure Configuration
TENANT_ID=your-tenant-id
CLIENT_ID=your-client-id
CLIENT_SECRET=your-client-secret
REDIRECT_URI=https://your-function-app.azurewebsites.net/api/auth/callback

# OpenAI Configuration
OPENAI_API_KEY=your-openai-api-key

# Azure Resources
STORAGE_CONNECTION=your-storage-connection
COSMOS_CONNECTION=your-cosmos-connection
SERVICEBUS_CONNECTION=your-servicebus-connection
KEY_VAULT_NAME=your-keyvault-name
APPINSIGHTS_INSTRUMENTATIONKEY=your-appinsights-key

# Deployment Mode
DEPLOYMENT_MODE=BOTH
EOF
    echo -e "${GREEN}✓ Created .env template. Please update with your values.${NC}"
fi

# Show container status
echo -e "${CYAN}Container Status:${NC}"
podman ps --filter name=${CONTAINER_NAME}

# Show logs
echo -e "${CYAN}Container Logs (last 10 lines):${NC}"
podman logs --tail 10 ${CONTAINER_NAME}

echo -e "${GREEN}✓ Deployment complete!${NC}"
echo -e "${CYAN}Access the function app at: http://localhost:${PORT}${NC}"
echo -e "${CYAN}View logs: podman logs -f ${CONTAINER_NAME}${NC}"
echo -e "${CYAN}Stop container: podman stop ${CONTAINER_NAME}${NC}"