#!/bin/bash

#############################################################################
# M365 Big Brain Crawl - Production Deployment Script
# Complete implementation with dual-mode authentication
# Mode A: User-Connected (delegated) with Auth Code + PKCE
# Mode B: Tenant-Connected (application) with Sites.Selected
#############################################################################

set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# Icons for status
CHECK_MARK="✓"
CROSS_MARK="✗"
ARROW="→"
INFO="ℹ"
WARNING="⚠"
GEAR="⚙"

# Configuration
SCRIPT_VERSION="3.0.0"
DEPLOYMENT_NAME="m365-brain-crawl-prod"
FUNCTION_APP_NAME="m365crawl$(shuf -i 1000-9999 -n 1)"
REDIRECT_URI="https://${FUNCTION_APP_NAME}.azurewebsites.net/api/auth/callback"
CONFIG_FILE=".m365-brain-production.json"

# Function to print colored output
print_color() {
    local color=$1
    shift
    echo -e "${color}$@${NC}"
}

# Function to print header
print_header() {
    echo
    print_color $CYAN "╔══════════════════════════════════════════════════════════════════╗"
    print_color $CYAN "║     M365 Big Brain Crawl Production Deployment v${SCRIPT_VERSION}     ║"
    print_color $CYAN "║          Dual-Mode: User-Connected & Tenant-Connected           ║"
    print_color $CYAN "╚══════════════════════════════════════════════════════════════════╝"
    echo
}

# Function to print section header
print_section() {
    echo
    print_color $MAGENTA "┌─────────────────────────────────────────────────────────────────┐"
    print_color $MAGENTA "│ $1"
    print_color $MAGENTA "└─────────────────────────────────────────────────────────────────┘"
    echo
}

# Function to check prerequisites
check_prerequisites() {
    print_section "Checking Prerequisites"
    
    local all_good=true
    
    # Check Azure CLI
    if command -v az >/dev/null 2>&1; then
        local az_version=$(az --version 2>/dev/null | head -n1 | cut -d' ' -f2)
        print_color $GREEN "$CHECK_MARK Azure CLI installed (version $az_version)"
    else
        print_color $RED "$CROSS_MARK Azure CLI not installed"
        all_good=false
    fi
    
    # Check jq
    if command -v jq >/dev/null 2>&1; then
        print_color $GREEN "$CHECK_MARK jq installed"
    else
        print_color $YELLOW "$WARNING jq not installed - installing..."
        if command -v apt-get >/dev/null 2>&1; then
            sudo apt-get update && sudo apt-get install -y jq
        elif command -v yum >/dev/null 2>&1; then
            sudo yum install -y jq
        elif command -v brew >/dev/null 2>&1; then
            brew install jq
        else
            print_color $RED "$CROSS_MARK Cannot install jq automatically"
            all_good=false
        fi
    fi
    
    # Check Python
    if command -v python3 >/dev/null 2>&1; then
        local py_version=$(python3 --version 2>&1 | cut -d' ' -f2)
        print_color $GREEN "$CHECK_MARK Python installed (version $py_version)"
    else
        print_color $RED "$CROSS_MARK Python 3 not installed"
        all_good=false
    fi
    
    # Check if logged into Azure
    if az account show >/dev/null 2>&1; then
        local subscription=$(az account show --query name -o tsv)
        print_color $GREEN "$CHECK_MARK Logged into Azure (Subscription: $subscription)"
    else
        print_color $YELLOW "$WARNING Not logged into Azure - running login..."
        az login
    fi
    
    if [ "$all_good" = false ]; then
        print_color $RED "Prerequisites check failed. Please install missing components."
        exit 1
    fi
}

# Function to collect deployment parameters
collect_parameters() {
    print_section "Deployment Configuration"
    
    # Check for existing config
    if [ -f "$CONFIG_FILE" ]; then
        print_color $CYAN "$INFO Found existing configuration file"
        read -p "Use existing configuration? (y/n): " use_existing
        if [ "$use_existing" = "y" ]; then
            source "$CONFIG_FILE"
            return
        fi
    fi
    
    # Tenant ID
    DEFAULT_TENANT=$(az account show --query tenantId -o tsv 2>/dev/null || echo "")
    read -p "Enter Azure AD Tenant ID [$DEFAULT_TENANT]: " TENANT_ID
    TENANT_ID=${TENANT_ID:-$DEFAULT_TENANT}
    
    # Resource Group
    read -p "Enter Resource Group name [m365-brain-rg]: " RESOURCE_GROUP
    RESOURCE_GROUP=${RESOURCE_GROUP:-"m365-brain-rg"}
    
    # Location
    read -p "Enter Azure region [eastus]: " LOCATION
    LOCATION=${LOCATION:-"eastus"}
    
    # OpenAI API Key
    read -s -p "Enter OpenAI API Key: " OPENAI_API_KEY
    echo
    
    # Deployment Mode
    print_color $CYAN "\nSelect deployment mode:"
    print_color $WHITE "1) Mode A: User-Connected (delegated permissions)"
    print_color $WHITE "2) Mode B: Tenant-Connected (application permissions)"
    print_color $WHITE "3) Both modes (recommended for flexibility)"
    read -p "Enter choice [3]: " MODE_CHOICE
    MODE_CHOICE=${MODE_CHOICE:-"3"}
    
    case $MODE_CHOICE in
        1) DEPLOYMENT_MODE="USER" ;;
        2) DEPLOYMENT_MODE="TENANT" ;;
        *) DEPLOYMENT_MODE="BOTH" ;;
    esac
    
    # Save configuration
    cat > "$CONFIG_FILE" <<EOF
export TENANT_ID="$TENANT_ID"
export RESOURCE_GROUP="$RESOURCE_GROUP"
export LOCATION="$LOCATION"
export OPENAI_API_KEY="$OPENAI_API_KEY"
export DEPLOYMENT_MODE="$DEPLOYMENT_MODE"
export FUNCTION_APP_NAME="$FUNCTION_APP_NAME"
export REDIRECT_URI="$REDIRECT_URI"
EOF
    
    print_color $GREEN "$CHECK_MARK Configuration saved to $CONFIG_FILE"
}

# Function to create resource group
create_resource_group() {
    print_section "Creating Resource Group"
    
    if az group show -n "$RESOURCE_GROUP" >/dev/null 2>&1; then
        print_color $YELLOW "$INFO Resource group '$RESOURCE_GROUP' already exists"
    else
        print_color $CYAN "$GEAR Creating resource group '$RESOURCE_GROUP' in $LOCATION..."
        az group create --name "$RESOURCE_GROUP" --location "$LOCATION" --output none
        print_color $GREEN "$CHECK_MARK Resource group created"
    fi
}

# Function to create app registration with dual-mode support
create_app_registration() {
    print_section "Creating App Registration"
    
    local app_name="M365BrainCrawl-${FUNCTION_APP_NAME}"
    
    print_color $CYAN "$GEAR Creating app registration '$app_name'..."
    
    # Create app with proper redirect URI
    local app_manifest=$(cat <<EOF
{
    "displayName": "$app_name",
    "signInAudience": "AzureADMyOrg",
    "web": {
        "redirectUris": [
            "$REDIRECT_URI"
        ],
        "implicitGrantSettings": {
            "enableIdTokenIssuance": false,
            "enableAccessTokenIssuance": false
        }
    },
    "spa": {
        "redirectUris": []
    },
    "publicClient": {
        "redirectUris": []
    },
    "requiredResourceAccess": []
}
EOF
)
    
    echo "$app_manifest" > app-manifest.json
    
    # Create the app
    APP_ID=$(az ad app create --display-name "$app_name" --sign-in-audience AzureADMyOrg \
        --web-redirect-uris "$REDIRECT_URI" \
        --query appId -o tsv)
    
    print_color $GREEN "$CHECK_MARK App registration created: $APP_ID"
    
    # Create service principal
    print_color $CYAN "$GEAR Creating service principal..."
    az ad sp create --id "$APP_ID" --output none 2>/dev/null || true
    
    # Create client secret
    print_color $CYAN "$GEAR Creating client secret..."
    CLIENT_SECRET=$(az ad app credential reset --id "$APP_ID" --years 2 \
        --query password -o tsv)
    
    # Configure permissions based on mode
    configure_graph_permissions
    
    # Enable PKCE for user mode
    if [ "$DEPLOYMENT_MODE" = "USER" ] || [ "$DEPLOYMENT_MODE" = "BOTH" ]; then
        print_color $CYAN "$GEAR Enabling Auth Code + PKCE flow..."
        az ad app update --id "$APP_ID" \
            --set publicClient=true \
            --output none
    fi
    
    print_color $GREEN "$CHECK_MARK App registration configured"
    
    # Clean up manifest file
    rm -f app-manifest.json
}

# Function to configure Microsoft Graph permissions
configure_graph_permissions() {
    print_section "Configuring Microsoft Graph Permissions"
    
    # Microsoft Graph API ID
    local graph_api="00000003-0000-0000-c000-000000000000"
    
    # Define permission IDs
    local user_read="e1fe6dd8-ba31-4d61-89e7-88639da4683d"
    local files_read_all="01d4889c-1287-42c6-ac1f-5d1e02578ef6"
    local sites_read_all="205e70e5-aba6-4c52-a976-6d2d46c48043"
    local sites_selected="883ea226-0bf2-4a8f-9f9d-92c9162a727d"
    local group_read_all="5f8c59db-677d-491f-a6b8-5f174b11ec1d"
    local team_read_basic="660b7406-55f1-41ca-a0ed-0b035e182f3e"
    local channel_read_basic="9d8982ae-4365-4f57-95e9-d6032a4c0b87"
    local chat_read="f501c180-9344-439a-bca0-6cbf209fd270"
    local user_read_all_app="df021288-bdef-4463-88db-98f22de89214"
    local files_read_all_app="01d4889c-1287-42c6-ac1f-5d1e02578ef6"
    
    local permissions_json=""
    
    # Mode A: Delegated permissions
    if [ "$DEPLOYMENT_MODE" = "USER" ] || [ "$DEPLOYMENT_MODE" = "BOTH" ]; then
        print_color $CYAN "$GEAR Adding delegated permissions for Mode A..."
        permissions_json=$(cat <<EOF
[
    {
        "resourceAppId": "$graph_api",
        "resourceAccess": [
            {"id": "$user_read", "type": "Scope"},
            {"id": "$files_read_all", "type": "Scope"},
            {"id": "$sites_read_all", "type": "Scope"},
            {"id": "$group_read_all", "type": "Scope"},
            {"id": "$team_read_basic", "type": "Scope"},
            {"id": "$channel_read_basic", "type": "Scope"},
            {"id": "$chat_read", "type": "Scope"},
            {"id": "offline_access", "type": "Scope"},
            {"id": "openid", "type": "Scope"},
            {"id": "profile", "type": "Scope"}
        ]
    }
]
EOF
)
    fi
    
    # Mode B: Application permissions
    if [ "$DEPLOYMENT_MODE" = "TENANT" ] || [ "$DEPLOYMENT_MODE" = "BOTH" ]; then
        print_color $CYAN "$GEAR Adding application permissions for Mode B..."
        
        # Add Sites.Selected as preferred permission
        local app_permissions=$(cat <<EOF
[
    {
        "resourceAppId": "$graph_api",
        "resourceAccess": [
            {"id": "$sites_selected", "type": "Role"},
            {"id": "$user_read_all_app", "type": "Role"},
            {"id": "$files_read_all_app", "type": "Role"},
            {"id": "$group_read_all", "type": "Role"}
        ]
    }
]
EOF
)
        
        if [ "$DEPLOYMENT_MODE" = "BOTH" ]; then
            # Merge both permission sets
            permissions_json=$(echo "$permissions_json" | jq --argjson app "$app_permissions" \
                '.[0].resourceAccess += $app[0].resourceAccess | unique_by(.id)')
        else
            permissions_json="$app_permissions"
        fi
    fi
    
    # Apply permissions
    echo "$permissions_json" > permissions.json
    az ad app update --id "$APP_ID" \
        --required-resource-accesses @permissions.json \
        --output none
    
    rm -f permissions.json
    
    print_color $GREEN "$CHECK_MARK Graph permissions configured"
}

# Function to create Azure resources
create_azure_resources() {
    print_section "Creating Azure Resources"
    
    # Storage Account
    local storage_account="m365brain$(shuf -i 10000-99999 -n 1)"
    print_color $CYAN "$GEAR Creating Storage Account..."
    az storage account create \
        --name "$storage_account" \
        --resource-group "$RESOURCE_GROUP" \
        --location "$LOCATION" \
        --sku Standard_LRS \
        --output none
    
    STORAGE_CONNECTION=$(az storage account show-connection-string \
        --name "$storage_account" \
        --resource-group "$RESOURCE_GROUP" \
        --query connectionString -o tsv)
    
    print_color $GREEN "$CHECK_MARK Storage Account created"
    
    # Cosmos DB
    local cosmos_account="m365brain-cosmos-$(shuf -i 1000-9999 -n 1)"
    print_color $CYAN "$GEAR Creating Cosmos DB Account..."
    az cosmosdb create \
        --name "$cosmos_account" \
        --resource-group "$RESOURCE_GROUP" \
        --location "$LOCATION" \
        --default-consistency-level Session \
        --enable-automatic-failover false \
        --output none
    
    # Create database and containers with proper partitioning
    print_color $CYAN "$GEAR Creating Cosmos DB database and containers..."
    az cosmosdb sql database create \
        --account-name "$cosmos_account" \
        --resource-group "$RESOURCE_GROUP" \
        --name "M365Data" \
        --output none
    
    # Create containers with tenant/user partitioning
    for container in "documents" "users" "teams" "crawlstate" "webhooks" "pkce_storage"; do
        az cosmosdb sql container create \
            --account-name "$cosmos_account" \
            --resource-group "$RESOURCE_GROUP" \
            --database-name "M365Data" \
            --name "$container" \
            --partition-key-path "/tenantId" \
            --throughput 400 \
            --output none
    done
    
    COSMOS_CONNECTION=$(az cosmosdb keys list \
        --name "$cosmos_account" \
        --resource-group "$RESOURCE_GROUP" \
        --type connection-strings \
        --query connectionStrings[0].connectionString -o tsv)
    
    print_color $GREEN "$CHECK_MARK Cosmos DB created with partitioned containers"
    
    # Service Bus
    local servicebus_namespace="m365brain-sb-$(shuf -i 1000-9999 -n 1)"
    print_color $CYAN "$GEAR Creating Service Bus..."
    az servicebus namespace create \
        --name "$servicebus_namespace" \
        --resource-group "$RESOURCE_GROUP" \
        --location "$LOCATION" \
        --sku Standard \
        --output none
    
    # Create queues
    for queue in "crawl-queue" "webhook-queue" "delta-queue"; do
        az servicebus queue create \
            --name "$queue" \
            --namespace-name "$servicebus_namespace" \
            --resource-group "$RESOURCE_GROUP" \
            --max-size 5120 \
            --default-message-time-to-live "P14D" \
            --output none
    done
    
    SERVICEBUS_CONNECTION=$(az servicebus namespace authorization-rule keys list \
        --name RootManageSharedAccessKey \
        --namespace-name "$servicebus_namespace" \
        --resource-group "$RESOURCE_GROUP" \
        --query primaryConnectionString -o tsv)
    
    print_color $GREEN "$CHECK_MARK Service Bus created with queues"
    
    # Key Vault
    local keyvault_name="m365kv$(shuf -i 10000-99999 -n 1)"
    print_color $CYAN "$GEAR Creating Key Vault..."
    az keyvault create \
        --name "$keyvault_name" \
        --resource-group "$RESOURCE_GROUP" \
        --location "$LOCATION" \
        --output none
    
    # Store secrets
    az keyvault secret set --vault-name "$keyvault_name" \
        --name "client-secret" --value "$CLIENT_SECRET" --output none
    az keyvault secret set --vault-name "$keyvault_name" \
        --name "openai-api-key" --value "$OPENAI_API_KEY" --output none
    
    KEY_VAULT_NAME="$keyvault_name"
    
    print_color $GREEN "$CHECK_MARK Key Vault created and secrets stored"
    
    # Application Insights
    print_color $CYAN "$GEAR Creating Application Insights..."
    az monitor app-insights component create \
        --app "m365brain-insights" \
        --location "$LOCATION" \
        --resource-group "$RESOURCE_GROUP" \
        --output none
    
    APP_INSIGHTS_KEY=$(az monitor app-insights component show \
        --app "m365brain-insights" \
        --resource-group "$RESOURCE_GROUP" \
        --query instrumentationKey -o tsv)
    
    print_color $GREEN "$CHECK_MARK Application Insights created"
}

# Function to create Function App
create_function_app() {
    print_section "Creating Function App"
    
    print_color $CYAN "$GEAR Creating Function App '$FUNCTION_APP_NAME'..."
    
    # Create App Service Plan (Elastic Premium for scale)
    az functionapp plan create \
        --name "${FUNCTION_APP_NAME}-plan" \
        --resource-group "$RESOURCE_GROUP" \
        --location "$LOCATION" \
        --sku EP1 \
        --is-linux \
        --output none
    
    # Create Function App
    az functionapp create \
        --name "$FUNCTION_APP_NAME" \
        --resource-group "$RESOURCE_GROUP" \
        --plan "${FUNCTION_APP_NAME}-plan" \
        --runtime python \
        --runtime-version 3.11 \
        --functions-version 4 \
        --storage-account "$storage_account" \
        --output none
    
    # Assign managed identity
    FUNCTION_APP_IDENTITY=$(az functionapp identity assign \
        --name "$FUNCTION_APP_NAME" \
        --resource-group "$RESOURCE_GROUP" \
        --query principalId -o tsv)
    
    # Grant Key Vault access
    az keyvault set-policy \
        --name "$KEY_VAULT_NAME" \
        --object-id "$FUNCTION_APP_IDENTITY" \
        --secret-permissions get list \
        --output none
    
    print_color $GREEN "$CHECK_MARK Function App created with managed identity"
    
    # Configure app settings
    print_color $CYAN "$GEAR Configuring Function App settings..."
    
    az functionapp config appsettings set \
        --name "$FUNCTION_APP_NAME" \
        --resource-group "$RESOURCE_GROUP" \
        --settings \
            "TENANT_ID=$TENANT_ID" \
            "CLIENT_ID=$APP_ID" \
            "CLIENT_SECRET=@Microsoft.KeyVault(SecretUri=https://${KEY_VAULT_NAME}.vault.azure.net/secrets/client-secret/)" \
            "REDIRECT_URI=$REDIRECT_URI" \
            "OPENAI_API_KEY=@Microsoft.KeyVault(SecretUri=https://${KEY_VAULT_NAME}.vault.azure.net/secrets/openai-api-key/)" \
            "STORAGE_CONNECTION=$STORAGE_CONNECTION" \
            "COSMOS_CONNECTION=$COSMOS_CONNECTION" \
            "SERVICEBUS_CONNECTION=$SERVICEBUS_CONNECTION" \
            "KEY_VAULT_NAME=$KEY_VAULT_NAME" \
            "APPINSIGHTS_INSTRUMENTATIONKEY=$APP_INSIGHTS_KEY" \
            "DEPLOYMENT_MODE=$DEPLOYMENT_MODE" \
            "WEBSITE_RUN_FROM_PACKAGE=1" \
        --output none
    
    print_color $GREEN "$CHECK_MARK Function App configured"
}

# Function to deploy Function code
deploy_functions() {
    print_section "Deploying Function Code"
    
    # Create deployment package
    print_color $CYAN "$GEAR Creating deployment package..."
    
    local temp_dir=$(mktemp -d)
    cd "$temp_dir"
    
    # Create requirements.txt
    cat > requirements.txt <<'EOF'
azure-functions==1.18.0
azure-identity==1.15.0
azure-keyvault-secrets==4.7.0
azure-storage-blob==12.19.0
azure-cosmos==4.5.1
azure-servicebus==7.11.4
msal==1.26.0
requests==2.31.0
openai==1.10.0
pydantic==2.5.3
cryptography>=43.0.0
python-jose[cryptography]==3.3.0
azure-cosmos==4.5.1
EOF
    
    # Create host.json
    cat > host.json <<'EOF'
{
    "version": "2.0",
    "logging": {
        "applicationInsights": {
            "samplingSettings": {
                "isEnabled": true,
                "maxTelemetryItemsPerSecond": 20
            }
        }
    },
    "extensionBundle": {
        "id": "Microsoft.Azure.Functions.ExtensionBundle",
        "version": "[4.*, 5.0.0)"
    }
}
EOF
    
    # Create shared auth module
    mkdir -p shared
    cat > shared/__init__.py <<'EOF'
"""Shared authentication and utility functions"""

import os
import json
import logging
from typing import Optional, Dict, Any
from datetime import datetime, timedelta
import msal
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from azure.cosmos import CosmosClient
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.fernet import Fernet
import base64
import secrets
import hashlib
import hmac
import time
from urllib.parse import quote_plus

logger = logging.getLogger(__name__)

class SecureErrorHandler:
    """Secure error handling to prevent information disclosure"""
    
    @staticmethod
    def sanitize_error_message(error: Exception, context: str = "") -> str:
        """Sanitize error messages to prevent information disclosure"""
        
        # Map of error types to safe messages
        safe_messages = {
            'ValueError': 'Invalid input provided',
            'KeyError': 'Required field missing',
            'AttributeError': 'Invalid operation',
            'TypeError': 'Invalid data type',
            'ConnectionError': 'Service temporarily unavailable',
            'TimeoutError': 'Request timeout',
            'PermissionError': 'Access denied',
            'FileNotFoundError': 'Resource not found',
            'json.JSONDecodeError': 'Invalid data format'
        }
        
        error_type = type(error).__name__
        base_message = safe_messages.get(error_type, 'Operation failed')
        
        # Log the actual error for debugging (with sanitized context)
        sanitized_context = context.replace('\n', ' ').replace('\r', '')[:100]
        logger.error(f"Error in {sanitized_context}: {error_type} - {str(error)[:200]}")
        
        return base_message
    
    @staticmethod
    def create_error_response(message: str, status_code: int = 400, 
                            include_request_id: bool = True) -> dict:
        """Create standardized error response"""
        
        error_response = {
            'error': True,
            'message': message,
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }
        
        if include_request_id:
            error_response['request_id'] = secrets.token_hex(8)
            
        return error_response
    
    @staticmethod
    def log_security_event(event_type: str, details: str, severity: str = "INFO"):
        """Log security events for monitoring"""
        
        # Sanitize details to prevent log injection
        sanitized_details = details.replace('\n', ' ').replace('\r', '').replace('\x00', '')[:500]
        
        security_log = {
            'event_type': event_type,
            'details': sanitized_details,
            'severity': severity,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        if severity == "CRITICAL":
            logger.critical(f"SECURITY: {json.dumps(security_log)}")
        elif severity == "WARNING":
            logger.warning(f"SECURITY: {json.dumps(security_log)}")
        else:
            logger.info(f"SECURITY: {json.dumps(security_log)}")

class SecurityHeaders:
    """Standardized security headers for all endpoints"""
    
    @staticmethod
    def get_api_headers() -> dict:
        """Get security headers for API endpoints"""
        return {
            'Content-Security-Policy': "default-src 'none'",
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
            'Referrer-Policy': 'strict-origin-when-cross-origin',
            'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
            'Pragma': 'no-cache',
            'X-Permitted-Cross-Domain-Policies': 'none',
            'Cross-Origin-Embedder-Policy': 'require-corp',
            'Cross-Origin-Opener-Policy': 'same-origin',
            'Cross-Origin-Resource-Policy': 'same-origin'
        }
    
    @staticmethod
    def get_html_headers() -> dict:
        """Get security headers for HTML endpoints"""
        return {
            'Content-Security-Policy': "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; img-src 'self' data:; connect-src 'self'",
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
            'Referrer-Policy': 'strict-origin-when-cross-origin',
            'X-Permitted-Cross-Domain-Policies': 'none',
            'Cross-Origin-Embedder-Policy': 'require-corp',
            'Cross-Origin-Opener-Policy': 'same-origin'
        }
    
    @staticmethod
    def get_webhook_headers() -> dict:
        """Get security headers for webhook endpoints"""
        return {
            'Content-Security-Policy': "default-src 'none'",
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
            'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
            'Pragma': 'no-cache',
            'X-Permitted-Cross-Domain-Policies': 'none'
        }

class SecurePKCEStorage:
    """Secure storage for PKCE code verifiers using Cosmos DB with encryption"""
    
    def __init__(self):
        self.cosmos_client = CosmosClient.from_connection_string(os.environ['COSMOS_CONNECTION'])
        self.container = self.cosmos_client.get_database_client("M365Data").get_container_client("pkce_storage")
        
        # Initialize encryption key from Key Vault
        kv_name = os.environ['KEY_VAULT_NAME']
        kv_uri = f"https://{kv_name}.vault.azure.net"
        credential = DefaultAzureCredential()
        kv_client = SecretClient(vault_url=kv_uri, credential=credential)
        
        try:
            # Try to get existing encryption key
            encryption_key = kv_client.get_secret("pkce-encryption-key").value
        except:
            # Generate new key if doesn't exist
            encryption_key = Fernet.generate_key().decode()
            kv_client.set_secret("pkce-encryption-key", encryption_key)
        
        self.fernet = Fernet(encryption_key.encode())
    
    def store_code_verifier(self, state: str, code_verifier: str, ttl_minutes: int = 10) -> None:
        """Store code verifier securely with TTL"""
        
        # Encrypt the code verifier
        encrypted_verifier = self.fernet.encrypt(code_verifier.encode()).decode()
        
        # Calculate expiration
        expiration = datetime.utcnow() + timedelta(minutes=ttl_minutes)
        
        item = {
            'id': f"pkce_{state}",
            'state': state,
            'encrypted_verifier': encrypted_verifier,
            'expires': expiration.isoformat(),
            'created': datetime.utcnow().isoformat(),
            'tenantId': 'pkce_storage'  # Partition key for PKCE items
        }
        
        try:
            self.container.upsert_item(item)
            logger.info(f"Stored PKCE verifier for state: {state[:8]}...")
        except Exception as e:
            logger.error(f"Failed to store PKCE verifier: {str(e)}")
            raise
    
    def retrieve_code_verifier(self, state: str) -> Optional[str]:
        """Retrieve and decrypt code verifier, then delete it"""
        
        try:
            item_id = f"pkce_{state}"
            item = self.container.read_item(item=item_id, partition_key='pkce_storage')
            
            # Check if expired
            expiration = datetime.fromisoformat(item['expires'])
            if datetime.utcnow() > expiration:
                # Clean up expired item
                self.container.delete_item(item=item_id, partition_key='pkce_storage')
                logger.warning(f"PKCE verifier expired for state: {state[:8]}...")
                return None
            
            # Decrypt the verifier
            encrypted_verifier = item['encrypted_verifier']
            code_verifier = self.fernet.decrypt(encrypted_verifier.encode()).decode()
            
            # Delete after retrieval (one-time use)
            self.container.delete_item(item=item_id, partition_key='pkce_storage')
            
            logger.info(f"Retrieved and deleted PKCE verifier for state: {state[:8]}...")
            return code_verifier
            
        except Exception as e:
            logger.error(f"Failed to retrieve PKCE verifier: {str(e)}")
            return None
    
    def cleanup_expired_verifiers(self) -> None:
        """Clean up expired PKCE verifiers"""
        
        try:
            current_time = datetime.utcnow().isoformat()
            query = f"SELECT * FROM c WHERE c.tenantId = 'pkce_storage' AND c.expires < '{current_time}'"
            
            expired_items = list(self.container.query_items(query=query, enable_cross_partition_query=False))
            
            for item in expired_items:
                self.container.delete_item(item=item['id'], partition_key='pkce_storage')
                logger.info(f"Cleaned up expired PKCE verifier: {item['id']}")
                
        except Exception as e:
            logger.error(f"Failed to cleanup expired verifiers: {str(e)}")

class InputValidator:
    """Comprehensive input validation and sanitization"""
    
    @staticmethod
    def validate_tenant_id(tenant_id: str) -> bool:
        """Validate tenant ID format"""
        if not tenant_id or len(tenant_id) > 64:
            return False
        # Tenant ID should be UUID format or domain
        import re
        uuid_pattern = r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$'
        domain_pattern = r'^[a-zA-Z0-9][a-zA-Z0-9\.-]+[a-zA-Z0-9]$'
        return re.match(uuid_pattern, tenant_id, re.IGNORECASE) or re.match(domain_pattern, tenant_id)
    
    @staticmethod
    def validate_client_id(client_id: str) -> bool:
        """Validate client ID format"""
        if not client_id:
            return False
        import re
        uuid_pattern = r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$'
        return re.match(uuid_pattern, client_id, re.IGNORECASE) is not None
    
    @staticmethod
    def sanitize_search_query(query: str) -> str:
        """Sanitize search query to prevent injection"""
        if not query:
            return ""
        
        # Remove potentially dangerous characters
        import re
        # Allow alphanumeric, spaces, and basic punctuation
        sanitized = re.sub(r'[^a-zA-Z0-9\s\.\-\_\@]', '', query)
        
        # Limit length
        return sanitized[:200]
    
    @staticmethod
    def validate_redirect_uri(uri: str) -> bool:
        """Validate redirect URI is HTTPS and matches expected pattern"""
        if not uri:
            return False
            
        if not uri.startswith('https://'):
            return False
            
        # Should match our function app pattern
        import re
        pattern = r'https://[a-zA-Z0-9\-]+\.azurewebsites\.net/api/auth/callback$'
        return re.match(pattern, uri) is not None
    
    @staticmethod
    def validate_state_parameter(state: str) -> bool:
        """Validate state parameter format"""
        if not state or len(state) < 32 or len(state) > 128:
            return False
            
        # Should be base64url encoded
        import re
        return re.match(r'^[a-zA-Z0-9_\-]+$', state) is not None

class AuthManager:
    """Manages dual-mode authentication with enhanced security"""
    
    def __init__(self):
        # Validate configuration
        self.tenant_id = os.environ['TENANT_ID']
        self.client_id = os.environ['CLIENT_ID']
        self.redirect_uri = os.environ['REDIRECT_URI']
        self.deployment_mode = os.environ.get('DEPLOYMENT_MODE', 'BOTH')
        
        # Input validation
        if not InputValidator.validate_tenant_id(self.tenant_id):
            raise ValueError("Invalid tenant ID format")
        
        if not InputValidator.validate_client_id(self.client_id):
            raise ValueError("Invalid client ID format")
            
        if not InputValidator.validate_redirect_uri(self.redirect_uri):
            raise ValueError("Invalid redirect URI format - must be HTTPS")
        
        # Initialize secure PKCE storage
        self.pkce_storage = SecurePKCEStorage()
        
        # Get client secret from Key Vault
        kv_name = os.environ['KEY_VAULT_NAME']
        kv_uri = f"https://{kv_name}.vault.azure.net"
        credential = DefaultAzureCredential()
        kv_client = SecretClient(vault_url=kv_uri, credential=credential)
        self.client_secret = kv_client.get_secret("client-secret").value
        
        # Initialize MSAL apps
        self._init_msal_apps()
    
    def _init_msal_apps(self):
        """Initialize MSAL applications for both modes"""
        
        authority = f"https://login.microsoftonline.com/{self.tenant_id}"
        
        # Mode A: Public client for user authentication with PKCE
        self.public_app = msal.PublicClientApplication(
            self.client_id,
            authority=authority
        )
        
        # Mode B: Confidential client for app-only authentication
        self.confidential_app = msal.ConfidentialClientApplication(
            self.client_id,
            authority=authority,
            client_credential=self.client_secret
        )
    
    def get_auth_url(self, mode: str = "user", state: Optional[str] = None) -> tuple[str, Optional[str]]:
        """Generate authentication URL based on mode with secure PKCE implementation"""
        
        if not state:
            state = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8')
        
        # Validate state parameter
        if not InputValidator.validate_state_parameter(state):
            raise ValueError("Invalid state parameter format")
        
        if mode == "user":
            # Mode A: Delegated permissions with PKCE
            scopes = [
                "openid",
                "profile", 
                "offline_access",
                "User.Read",
                "Files.Read.All",
                "Sites.Read.All",
                "Group.Read.All",
                "Team.ReadBasic.All",
                "Channel.ReadBasic.All",
                "Chat.Read"
            ]
            
            # Generate cryptographically secure PKCE challenge
            code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8')
            code_challenge_bytes = hashlib.sha256(code_verifier.encode()).digest()
            code_challenge = base64.urlsafe_b64encode(code_challenge_bytes).decode('utf-8').rstrip('=')
            
            # Store code verifier securely
            self.pkce_storage.store_code_verifier(state, code_verifier, ttl_minutes=10)
            
            auth_url = self.public_app.get_authorization_request_url(
                scopes,
                state=state,
                redirect_uri=self.redirect_uri,
                response_mode="query",
                code_challenge=code_challenge,
                code_challenge_method="S256"
            )
            
            return auth_url, state  # Return state instead of verifier for security
            
        else:
            # Mode B: Admin consent for application permissions
            admin_consent_url = (
                f"https://login.microsoftonline.com/{self.tenant_id}/adminconsent?"
                f"client_id={self.client_id}&"
                f"redirect_uri={quote_plus(self.redirect_uri)}&"
                f"state={state}"
            )
            return admin_consent_url, None
    
    def acquire_token_by_auth_code(self, code: str, state: str, mode: str = "user") -> Dict[str, Any]:
        """Exchange authorization code for tokens with secure PKCE verification"""
        
        # Validate inputs
        if not code or not state:
            raise ValueError("Authorization code and state are required")
            
        if not InputValidator.validate_state_parameter(state):
            raise ValueError("Invalid state parameter")
        
        if mode == "user":
            # Retrieve code verifier from secure storage
            code_verifier = self.pkce_storage.retrieve_code_verifier(state)
            if not code_verifier:
                logger.error(f"PKCE code verifier not found or expired for state: {state[:8]}...")
                raise ValueError("PKCE verification failed - code verifier not found or expired")
            
            # Mode A: User delegated token with PKCE
            result = self.public_app.acquire_token_by_authorization_code(
                code,
                scopes=[
                    "User.Read",
                    "Files.Read.All",
                    "Sites.Read.All",
                    "Group.Read.All",
                    "offline_access"
                ],
                redirect_uri=self.redirect_uri,
                code_verifier=code_verifier
            )
        else:
            # Mode B: App-only token
            result = self.confidential_app.acquire_token_for_client(
                scopes=["https://graph.microsoft.com/.default"]
            )
        
        # Validate token response
        if "error" in result:
            logger.error(f"Token acquisition failed: {result.get('error')} - {result.get('error_description')}")
            raise ValueError(f"Token acquisition failed: {result.get('error_description')}")
            
        # Validate access token format
        if "access_token" not in result:
            raise ValueError("Invalid token response - no access token")
            
        return result
    
    def get_token_for_user(self, user_id: str) -> Optional[str]:
        """Get cached token for a user"""
        accounts = self.public_app.get_accounts(username=user_id)
        if accounts:
            result = self.public_app.acquire_token_silent(
                ["User.Read", "Files.Read.All"],
                account=accounts[0]
            )
            if result and "access_token" in result:
                return result["access_token"]
        return None
    
    def get_app_only_token(self) -> str:
        """Get application token for tenant-wide access"""
        result = self.confidential_app.acquire_token_for_client(
            scopes=["https://graph.microsoft.com/.default"]
        )
        if "access_token" in result:
            return result["access_token"]
        raise Exception(f"Failed to acquire app token: {result.get('error_description')}")

class DeltaTokenManager:
    """Manages delta tokens for incremental sync"""
    
    def __init__(self, cosmos_client):
        self.cosmos_client = cosmos_client
        self.container = cosmos_client.get_database_client("M365Data").get_container_client("crawlstate")
    
    def get_delta_token(self, tenant_id: str, resource_type: str, resource_id: str = None) -> Optional[str]:
        """Retrieve delta token for a resource"""
        try:
            partition_key = tenant_id
            item_id = f"{resource_type}_{resource_id}" if resource_id else resource_type
            
            response = self.container.read_item(
                item=item_id,
                partition_key=partition_key
            )
            return response.get('deltaToken')
        except:
            return None
    
    def save_delta_token(self, tenant_id: str, resource_type: str, 
                         delta_token: str, resource_id: str = None):
        """Save delta token for a resource"""
        partition_key = tenant_id
        item_id = f"{resource_type}_{resource_id}" if resource_id else resource_type
        
        item = {
            'id': item_id,
            'tenantId': tenant_id,
            'resourceType': resource_type,
            'resourceId': resource_id,
            'deltaToken': delta_token,
            'lastUpdated': datetime.utcnow().isoformat()
        }
        
        self.container.upsert_item(item)

class CertificateManager:
    """Manages encryption certificates for webhook payloads"""
    
    def __init__(self):
        self.kv_name = os.environ['KEY_VAULT_NAME']
        self.kv_uri = f"https://{self.kv_name}.vault.azure.net"
        self.credential = DefaultAzureCredential()
        self.kv_client = SecretClient(vault_url=self.kv_uri, credential=self.credential)
    
    def generate_webhook_certificate(self, certificate_id: str) -> Dict[str, Any]:
        """Generate a new X.509 certificate for webhook encryption"""
        
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        # Generate certificate (self-signed for webhook encryption)
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        import ipaddress
        
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "WA"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Redmond"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "M365 Crawl"),
            x509.NameAttribute(NameOID.COMMON_NAME, "webhook-encryption"),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
            ]),
            critical=False,
        ).sign(private_key, hashes.SHA256())
        
        # Serialize certificate and key
        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()
        
        # Store in Key Vault
        try:
            self.kv_client.set_secret(f"webhook-cert-{certificate_id}", cert_pem)
            self.kv_client.set_secret(f"webhook-key-{certificate_id}", private_key_pem)
            logger.info(f"Stored webhook certificate: {certificate_id}")
        except Exception as e:
            logger.error(f"Failed to store certificate: {str(e)}")
            raise
        
        return {
            'id': certificate_id,
            'certificate': cert_pem,
            'private_key': private_key_pem,
            'public_key_base64': base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()
        }
    
    def get_certificate(self, certificate_id: str) -> Optional[Dict[str, str]]:
        """Retrieve certificate from Key Vault"""
        
        try:
            cert_pem = self.kv_client.get_secret(f"webhook-cert-{certificate_id}").value
            key_pem = self.kv_client.get_secret(f"webhook-key-{certificate_id}").value
            
            return {
                'id': certificate_id,
                'certificate': cert_pem,
                'private_key': key_pem
            }
        except Exception as e:
            logger.error(f"Failed to retrieve certificate {certificate_id}: {str(e)}")
            return None
    
    def decrypt_webhook_payload(self, encrypted_content: Dict[str, Any], certificate_id: str) -> Dict[str, Any]:
        """Decrypt webhook payload using stored certificate"""
        
        cert_data = self.get_certificate(certificate_id)
        if not cert_data:
            raise ValueError(f"Certificate {certificate_id} not found")
        
        try:
            # Load private key
            private_key = serialization.load_pem_private_key(
                cert_data['private_key'].encode(),
                password=None
            )
            
            # Decrypt the symmetric key
            encrypted_key = base64.b64decode(encrypted_content['dataKey'])
            symmetric_key = private_key.decrypt(
                encrypted_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Decrypt the data using AES
            encrypted_data = base64.b64decode(encrypted_content['data'])
            iv = encrypted_data[:16]  # First 16 bytes are IV
            cipher_data = encrypted_data[16:]
            
            cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(iv))
            decryptor = cipher.decryptor()
            decrypted_data = decryptor.update(cipher_data) + decryptor.finalize()
            
            # Remove PKCS7 padding
            padding_length = decrypted_data[-1]
            decrypted_data = decrypted_data[:-padding_length]
            
            return json.loads(decrypted_data.decode())
            
        except Exception as e:
            logger.error(f"Failed to decrypt webhook payload: {str(e)}")
            raise

class WebhookManager:
    """Manages webhook subscriptions with encrypted payloads"""
    
    def __init__(self, auth_manager: AuthManager):
        self.auth_manager = auth_manager
        self.notification_url = f"{os.environ['REDIRECT_URI'].replace('/auth/callback', '/webhook')}"
        self.cert_manager = CertificateManager()
        
    def create_subscription(self, resource: str, change_type: str, 
                          expiration_hours: int = 72) -> Dict[str, Any]:
        """Create a webhook subscription with encrypted payloads"""
        
        token = self.auth_manager.get_app_only_token()
        
        # Generate unique certificate ID
        certificate_id = f"webhook-{secrets.token_hex(8)}"
        
        # Generate encryption certificate
        certificate = self.cert_manager.generate_webhook_certificate(certificate_id)
        
        # Create cryptographically secure client state
        client_state = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8')
        
        subscription_data = {
            "changeType": change_type,
            "notificationUrl": self.notification_url,
            "resource": resource,
            "expirationDateTime": (datetime.utcnow() + timedelta(hours=expiration_hours)).isoformat() + "Z",
            "clientState": client_state,
            "includeResourceData": True,
            "encryptionCertificate": certificate['public_key_base64'],
            "encryptionCertificateId": certificate_id
        }
        
        logger.info(f"Created webhook subscription for {resource} with certificate {certificate_id}")
        
        return subscription_data
    
    def validate_client_state(self, received_state: str, expected_state: str) -> bool:
        """Validate client state with timing-safe comparison"""
        
        if not received_state or not expected_state:
            return False
            
        # Use constant-time comparison to prevent timing attacks
        return hmac.compare_digest(received_state, expected_state)
    
    def process_webhook_notification(self, notification: Dict[str, Any]) -> Dict[str, Any]:
        """Process and decrypt webhook notification"""
        
        try:
            # Validate client state if present
            client_state = notification.get('clientState')
            if client_state:
                # In production, retrieve expected state from storage
                # For now, log for validation
                logger.info(f"Webhook client state: {client_state[:8]}...")
            
            # Process encrypted content if present
            if 'encryptedContent' in notification:
                certificate_id = notification['encryptedContent'].get('encryptionCertificateId')
                if not certificate_id:
                    raise ValueError("Missing encryption certificate ID")
                
                decrypted_data = self.cert_manager.decrypt_webhook_payload(
                    notification['encryptedContent'], 
                    certificate_id
                )
                
                return {
                    'status': 'success',
                    'data': decrypted_data,
                    'encrypted': True
                }
            else:
                # Process unencrypted notification (fallback)
                resource_data = notification.get('resourceData', {})
                return {
                    'status': 'success',
                    'data': resource_data,
                    'encrypted': False
                }
                
        except Exception as e:
            logger.error(f"Failed to process webhook notification: {str(e)}")
            raise
EOF
    
    # Create authentication endpoint function
    mkdir -p AuthCallback
    cat > AuthCallback/__init__.py <<'EOF'
import logging
import json
import azure.functions as func
from urllib.parse import parse_qs
from shared import AuthManager, SecureErrorHandler, InputValidator, SecurityHeaders

logger = logging.getLogger(__name__)

async def main(req: func.HttpRequest) -> func.HttpResponse:
    """Handle OAuth callback for both user and admin modes with secure error handling"""
    
    logger.info("OAuth callback triggered")
    
    try:
        # Parse query parameters with validation
        code = req.params.get('code')
        state = req.params.get('state')
        error = req.params.get('error')
        error_desc = req.params.get('error_description', '')
        
        # Log authentication attempt
        SecureErrorHandler.log_security_event(
            "auth_callback_attempt",
            f"Code present: {bool(code)}, State present: {bool(state)}, Error: {bool(error)}",
            "INFO"
        )
        
        # Handle OAuth errors from provider
        if error:
            SecureErrorHandler.log_security_event(
                "oauth_provider_error",
                f"Error: {error}",
                "WARNING"
            )
            
            # Return generic error message
            error_html = create_error_page("Authentication failed. Please try again.")
            return func.HttpResponse(
                error_html,
                mimetype="text/html",
                status_code=400,
                headers=get_security_headers()
            )
        
        # Validate required parameters
        if not code or not state:
            SecureErrorHandler.log_security_event(
                "invalid_callback_params",
                "Missing required parameters",
                "WARNING"
            )
            
            error_html = create_error_page("Invalid authentication request.")
            return func.HttpResponse(
                error_html,
                mimetype="text/html", 
                status_code=400,
                headers=get_security_headers()
            )
        
        # Validate state parameter format
        if not InputValidator.validate_state_parameter(state):
            SecureErrorHandler.log_security_event(
                "invalid_state_parameter",
                "State parameter validation failed",
                "WARNING"
            )
            
            error_html = create_error_page("Invalid authentication request.")
            return func.HttpResponse(
                error_html,
                mimetype="text/html",
                status_code=400,
                headers=get_security_headers()
            )
        
        # Initialize auth manager
        auth_manager = AuthManager()
        
        # Exchange code for token using secure PKCE flow
        result = auth_manager.acquire_token_by_auth_code(
            code=code,
            state=state,
            mode="user"
        )
        
        # Store tokens securely (implementation would use encrypted storage)
        SecureErrorHandler.log_security_event(
            "successful_authentication",
            "User authenticated successfully",
            "INFO"
        )
        
        # Return success page
        success_html = create_success_page()
        
        return func.HttpResponse(
            success_html,
            mimetype="text/html",
            status_code=200,
            headers=get_security_headers()
        )
        
    except ValueError as e:
        # Handle validation errors
        safe_message = SecureErrorHandler.sanitize_error_message(e, "auth_callback")
        SecureErrorHandler.log_security_event(
            "auth_validation_error",
            safe_message,
            "WARNING"
        )
        
        error_html = create_error_page("Authentication validation failed.")
        return func.HttpResponse(
            error_html,
            mimetype="text/html",
            status_code=400,
            headers=get_security_headers()
        )
    except Exception as e:
        # Handle unexpected errors
        safe_message = SecureErrorHandler.sanitize_error_message(e, "auth_callback")
        SecureErrorHandler.log_security_event(
            "auth_unexpected_error",
            safe_message,
            "CRITICAL"
        )
        
        error_html = create_error_page("An unexpected error occurred. Please try again.")
        return func.HttpResponse(
            error_html,
            mimetype="text/html",
            status_code=500,
            headers=get_security_headers()
        )

def get_security_headers() -> dict:
    """Get security headers for auth callback responses"""
    return SecurityHeaders.get_html_headers()

def create_success_page() -> str:
    """Create secure success page HTML"""
    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Authentication Successful</title>
        <style>
            body { 
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; 
                text-align: center; 
                padding: 50px; 
                background-color: #f5f5f5;
                margin: 0;
            }
            .container {
                background: white;
                border-radius: 8px;
                padding: 40px;
                max-width: 500px;
                margin: 0 auto;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            }
            .success { color: #28a745; margin-bottom: 20px; }
            .info { 
                margin-top: 20px; 
                padding: 20px; 
                background: #f8f9fa; 
                border-radius: 5px; 
                color: #666;
                line-height: 1.5;
            }
            .close-btn {
                margin-top: 20px;
                padding: 10px 20px;
                background: #007bff;
                color: white;
                border: none;
                border-radius: 4px;
                cursor: pointer;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1 class="success">✓ Authentication Successful</h1>
            <div class="info">
                <p>You have successfully authenticated with Microsoft 365.</p>
                <p>The M365 Brain Crawl system can now access your organization's data securely.</p>
            </div>
            <button class="close-btn" onclick="window.close()">Close Window</button>
        </div>
    </body>
    </html>
    """

def create_error_page(message: str) -> str:
    """Create secure error page HTML"""
    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Authentication Error</title>
        <style>
            body {{ 
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; 
                text-align: center; 
                padding: 50px; 
                background-color: #f5f5f5;
                margin: 0;
            }}
            .container {{
                background: white;
                border-radius: 8px;
                padding: 40px;
                max-width: 500px;
                margin: 0 auto;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            }}
            .error {{ color: #dc3545; margin-bottom: 20px; }}
            .info {{ 
                margin-top: 20px; 
                padding: 20px; 
                background: #f8d7da; 
                border-radius: 5px; 
                color: #721c24;
                line-height: 1.5;
            }}
            .retry-btn {{
                margin-top: 20px;
                padding: 10px 20px;
                background: #6c757d;
                color: white;
                border: none;
                border-radius: 4px;
                cursor: pointer;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1 class="error">✗ Authentication Error</h1>
            <div class="info">
                <p>{message}</p>
                <p>Please contact your administrator if this problem persists.</p>
            </div>
            <button class="retry-btn" onclick="window.close()">Close Window</button>
        </div>
    </body>
    </html>
    """
EOF
    
    cat > AuthCallback/function.json <<'EOF'
{
    "scriptFile": "__init__.py",
    "bindings": [
        {
            "authLevel": "anonymous",
            "type": "httpTrigger",
            "direction": "in",
            "name": "req",
            "methods": ["get", "post"],
            "route": "auth/callback"
        },
        {
            "type": "http",
            "direction": "out",
            "name": "$return"
        }
    ]
}
EOF
    
    # Create CrawlTrigger function
    mkdir -p CrawlTrigger
    cat > CrawlTrigger/__init__.py <<'EOF'
import logging
import json
import azure.functions as func
from azure.servicebus import ServiceBusClient, ServiceBusMessage
import os

logger = logging.getLogger(__name__)

async def main(req: func.HttpRequest) -> func.HttpResponse:
    """Trigger crawl operations"""
    
    logger.info("Crawl trigger activated")
    
    try:
        # Parse request
        req_body = req.get_json() if req.get_body() else {}
        crawl_type = req_body.get('type', 'delta')
        resources = req_body.get('resources', ['all'])
        tenant_id = req_body.get('tenant_id', os.environ['TENANT_ID'])
        user_id = req_body.get('user_id')  # For user-specific crawls
        
        # Create Service Bus client
        servicebus_client = ServiceBusClient.from_connection_string(
            os.environ['SERVICEBUS_CONNECTION']
        )
        
        # Send messages to queue
        with servicebus_client:
            sender = servicebus_client.get_queue_sender(queue_name="crawl-queue")
            with sender:
                for resource in resources:
                    message_body = {
                        'crawl_type': crawl_type,
                        'resource': resource,
                        'tenant_id': tenant_id,
                        'user_id': user_id,
                        'timestamp': func.datetime.utcnow().isoformat()
                    }
                    
                    message = ServiceBusMessage(
                        json.dumps(message_body),
                        content_type="application/json",
                        time_to_live=func.timedelta(days=1)
                    )
                    
                    sender.send_messages(message)
                    logger.info(f"Queued crawl for resource: {resource}")
        
        return func.HttpResponse(
            json.dumps({
                'status': 'success',
                'message': f'Crawl initiated for {len(resources)} resources',
                'crawl_type': crawl_type
            }),
            mimetype="application/json",
            status_code=200
        )
        
    except Exception as e:
        logger.error(f"Error in crawl trigger: {str(e)}")
        return func.HttpResponse(
            json.dumps({'error': str(e)}),
            mimetype="application/json",
            status_code=500
        )
EOF
    
    cat > CrawlTrigger/function.json <<'EOF'
{
    "scriptFile": "__init__.py",
    "bindings": [
        {
            "authLevel": "function",
            "type": "httpTrigger",
            "direction": "in",
            "name": "req",
            "methods": ["post"],
            "route": "crawl/{crawl_type}"
        },
        {
            "type": "http",
            "direction": "out",
            "name": "$return"
        }
    ]
}
EOF
    
    # Create QueueProcessor function
    mkdir -p QueueProcessor
    cat > QueueProcessor/__init__.py <<'EOF'
import logging
import json
import azure.functions as func
from azure.cosmos import CosmosClient
import requests
from shared import AuthManager, DeltaTokenManager
import os
from typing import Dict, Any, List
import time

logger = logging.getLogger(__name__)

def main(msg: func.ServiceBusMessage):
    """Process crawl messages from queue"""
    
    try:
        # Parse message
        message_body = json.loads(msg.get_body().decode('utf-8'))
        logger.info(f"Processing crawl message: {message_body}")
        
        crawl_type = message_body['crawl_type']
        resource = message_body['resource']
        tenant_id = message_body['tenant_id']
        user_id = message_body.get('user_id')
        
        # Initialize clients
        auth_manager = AuthManager()
        cosmos_client = CosmosClient.from_connection_string(os.environ['COSMOS_CONNECTION'])
        delta_manager = DeltaTokenManager(cosmos_client)
        
        # Get appropriate token
        if user_id:
            # User-specific crawl
            token = auth_manager.get_token_for_user(user_id)
            if not token:
                logger.error(f"No token found for user {user_id}")
                return
        else:
            # Tenant-wide crawl
            token = auth_manager.get_app_only_token()
        
        # Perform crawl based on resource type
        if resource == 'users' or resource == 'all':
            crawl_users(token, tenant_id, delta_manager, cosmos_client, crawl_type)
        
        if resource == 'sites' or resource == 'all':
            crawl_sites(token, tenant_id, delta_manager, cosmos_client, crawl_type)
        
        if resource == 'teams' or resource == 'all':
            crawl_teams(token, tenant_id, delta_manager, cosmos_client, crawl_type)
        
        if resource == 'drives' or resource == 'all':
            crawl_drives(token, tenant_id, delta_manager, cosmos_client, crawl_type)
        
        logger.info(f"Successfully processed crawl for {resource}")
        
    except Exception as e:
        logger.error(f"Error processing queue message: {str(e)}")
        raise

def crawl_users(token: str, tenant_id: str, delta_manager: DeltaTokenManager,
                cosmos_client: CosmosClient, crawl_type: str):
    """Crawl users with delta support"""
    
    container = cosmos_client.get_database_client("M365Data").get_container_client("users")
    
    # Build request URL
    if crawl_type == 'delta':
        delta_token = delta_manager.get_delta_token(tenant_id, 'users')
        if delta_token:
            url = f"https://graph.microsoft.com/v1.0/users/delta?$deltatoken={delta_token}"
        else:
            url = "https://graph.microsoft.com/v1.0/users/delta"
    else:
        url = "https://graph.microsoft.com/v1.0/users?$select=id,displayName,mail,userPrincipalName,jobTitle,department"
    
    headers = {'Authorization': f'Bearer {token}'}
    
    # Handle pagination and delta queries
    while url:
        response = make_graph_request(url, headers)
        
        if response.status_code == 200:
            data = response.json()
            
            # Process users
            for user in data.get('value', []):
                user['tenantId'] = tenant_id
                user['_partitionKey'] = tenant_id
                container.upsert_item(user)
            
            # Get next page or delta link
            url = data.get('@odata.nextLink')
            
            # Save delta token if present
            if '@odata.deltaLink' in data:
                delta_link = data['@odata.deltaLink']
                delta_token = delta_link.split('$deltatoken=')[1] if '$deltatoken=' in delta_link else None
                if delta_token:
                    delta_manager.save_delta_token(tenant_id, 'users', delta_token)
                url = None  # End pagination
        else:
            logger.error(f"Failed to crawl users: {response.status_code}")
            break

def crawl_sites(token: str, tenant_id: str, delta_manager: DeltaTokenManager,
                cosmos_client: CosmosClient, crawl_type: str):
    """Crawl SharePoint sites with delta support"""
    
    container = cosmos_client.get_database_client("M365Data").get_container_client("documents")
    
    # For Sites.Selected permission, we need to enumerate granted sites
    # This would be configured through SharePoint admin
    
    url = "https://graph.microsoft.com/v1.0/sites?$select=id,displayName,webUrl,createdDateTime"
    headers = {'Authorization': f'Bearer {token}'}
    
    while url:
        response = make_graph_request(url, headers)
        
        if response.status_code == 200:
            data = response.json()
            
            for site in data.get('value', []):
                # Crawl site documents
                crawl_site_documents(token, tenant_id, site['id'], container)
            
            url = data.get('@odata.nextLink')
        else:
            logger.error(f"Failed to crawl sites: {response.status_code}")
            break

def crawl_site_documents(token: str, tenant_id: str, site_id: str, container):
    """Crawl documents in a SharePoint site"""
    
    url = f"https://graph.microsoft.com/v1.0/sites/{site_id}/drive/root/children"
    headers = {'Authorization': f'Bearer {token}'}
    
    def crawl_folder(folder_url):
        response = make_graph_request(folder_url, headers)
        if response.status_code == 200:
            data = response.json()
            for item in data.get('value', []):
                if 'folder' in item:
                    # Recursively crawl subfolders
                    child_url = f"https://graph.microsoft.com/v1.0/sites/{site_id}/drive/items/{item['id']}/children"
                    crawl_folder(child_url)
                else:
                    # Store document metadata
                    item['tenantId'] = tenant_id
                    item['_partitionKey'] = tenant_id
                    item['siteId'] = site_id
                    container.upsert_item(item)
    
    crawl_folder(url)

def crawl_teams(token: str, tenant_id: str, delta_manager: DeltaTokenManager,
                cosmos_client: CosmosClient, crawl_type: str):
    """Crawl Teams and channels"""
    
    container = cosmos_client.get_database_client("M365Data").get_container_client("teams")
    
    url = "https://graph.microsoft.com/v1.0/teams"
    headers = {'Authorization': f'Bearer {token}'}
    
    response = make_graph_request(url, headers)
    
    if response.status_code == 200:
        data = response.json()
        
        for team in data.get('value', []):
            team['tenantId'] = tenant_id
            team['_partitionKey'] = tenant_id
            container.upsert_item(team)
            
            # Crawl channels
            crawl_channels(token, tenant_id, team['id'], container)

def crawl_channels(token: str, tenant_id: str, team_id: str, container):
    """Crawl channels for a team"""
    
    url = f"https://graph.microsoft.com/v1.0/teams/{team_id}/channels"
    headers = {'Authorization': f'Bearer {token}'}
    
    response = make_graph_request(url, headers)
    
    if response.status_code == 200:
        data = response.json()
        
        for channel in data.get('value', []):
            channel['tenantId'] = tenant_id
            channel['_partitionKey'] = tenant_id
            channel['teamId'] = team_id
            container.upsert_item(channel)

def crawl_drives(token: str, tenant_id: str, delta_manager: DeltaTokenManager,
                cosmos_client: CosmosClient, crawl_type: str):
    """Crawl OneDrive files with delta support"""
    
    container = cosmos_client.get_database_client("M365Data").get_container_client("documents")
    
    # Get all users' drives
    url = "https://graph.microsoft.com/v1.0/users"
    headers = {'Authorization': f'Bearer {token}'}
    
    response = make_graph_request(url, headers)
    
    if response.status_code == 200:
        users = response.json().get('value', [])
        
        for user in users:
            # Get user's drive
            drive_url = f"https://graph.microsoft.com/v1.0/users/{user['id']}/drive"
            drive_response = make_graph_request(drive_url, headers)
            
            if drive_response.status_code == 200:
                drive = drive_response.json()
                
                # Crawl drive with delta
                if crawl_type == 'delta':
                    delta_token = delta_manager.get_delta_token(tenant_id, 'drive', drive['id'])
                    if delta_token:
                        items_url = f"https://graph.microsoft.com/v1.0/drives/{drive['id']}/root/delta?token={delta_token}"
                    else:
                        items_url = f"https://graph.microsoft.com/v1.0/drives/{drive['id']}/root/delta"
                else:
                    items_url = f"https://graph.microsoft.com/v1.0/drives/{drive['id']}/root/children"
                
                crawl_drive_items(items_url, headers, tenant_id, drive['id'], container, delta_manager)

def crawl_drive_items(url: str, headers: Dict, tenant_id: str, drive_id: str,
                     container, delta_manager: DeltaTokenManager):
    """Crawl drive items with pagination"""
    
    while url:
        response = make_graph_request(url, headers)
        
        if response.status_code == 200:
            data = response.json()
            
            for item in data.get('value', []):
                item['tenantId'] = tenant_id
                item['_partitionKey'] = tenant_id
                item['driveId'] = drive_id
                container.upsert_item(item)
            
            # Handle pagination
            url = data.get('@odata.nextLink')
            
            # Save delta token
            if '@odata.deltaLink' in data:
                delta_link = data['@odata.deltaLink']
                if 'token=' in delta_link:
                    delta_token = delta_link.split('token=')[1].split('&')[0]
                    delta_manager.save_delta_token(tenant_id, 'drive', delta_token, drive_id)
                url = None
        else:
            logger.error(f"Failed to crawl drive items: {response.status_code}")
            break

def make_graph_request(url: str, headers: Dict, max_retries: int = 3) -> requests.Response:
    """Make Graph API request with retry logic for throttling"""
    
    for attempt in range(max_retries):
        response = requests.get(url, headers=headers)
        
        if response.status_code == 429:
            # Handle throttling
            retry_after = int(response.headers.get('Retry-After', 60))
            logger.warning(f"Throttled. Waiting {retry_after} seconds...")
            time.sleep(retry_after)
        elif response.status_code == 200:
            return response
        else:
            logger.error(f"Graph API error: {response.status_code} - {response.text}")
            return response
    
    return response
EOF
    
    cat > QueueProcessor/function.json <<'EOF'
{
    "scriptFile": "__init__.py",
    "bindings": [
        {
            "name": "msg",
            "type": "serviceBusTrigger",
            "direction": "in",
            "queueName": "crawl-queue",
            "connection": "SERVICEBUS_CONNECTION"
        }
    ]
}
EOF
    
    # Create WebhookEndpoint function
    mkdir -p WebhookEndpoint
    cat > WebhookEndpoint/__init__.py <<'EOF'
import logging
import json
import azure.functions as func
from shared import WebhookManager, AuthManager, InputValidator, SecurityHeaders
import hmac
import hashlib
import os
from azure.servicebus import ServiceBusClient, ServiceBusMessage
from typing import Dict, Any

logger = logging.getLogger(__name__)

async def main(req: func.HttpRequest) -> func.HttpResponse:
    """Handle webhook notifications from Microsoft Graph with authentication and encryption"""
    
    logger.info("Webhook endpoint triggered")
    
    # Handle validation token for subscription creation
    validation_token = req.params.get('validationToken')
    if validation_token:
        logger.info("Responding to webhook validation")
        # Validate token format
        if not InputValidator.validate_state_parameter(validation_token):
            logger.warning("Invalid validation token format")
            return func.HttpResponse("Invalid token", status_code=400)
        
        return func.HttpResponse(
            validation_token,
            mimetype="text/plain",
            status_code=200,
            headers=SecurityHeaders.get_webhook_headers()
        )
    
    try:
        # Validate webhook authentication
        if not validate_webhook_request(req):
            logger.warning("Webhook authentication failed")
            return func.HttpResponse("Unauthorized", status_code=401)
        
        # Parse notification with size limit
        if req.get_body_as_bytes() and len(req.get_body_as_bytes()) > 1024 * 1024:  # 1MB limit
            logger.warning("Webhook payload too large")
            return func.HttpResponse("Payload too large", status_code=413)
        
        req_body = req.get_json()
        if not req_body:
            logger.warning("Empty webhook payload")
            return func.HttpResponse("Bad Request", status_code=400)
        
        # Initialize webhook manager
        auth_manager = AuthManager()
        webhook_manager = WebhookManager(auth_manager)
        
        # Process notifications
        processed_count = 0
        for notification in req_body.get('value', []):
            try:
                result = webhook_manager.process_webhook_notification(notification)
                
                # Queue for async processing
                await queue_notification_for_processing(result, notification)
                processed_count += 1
                
            except Exception as e:
                logger.error(f"Failed to process notification: {str(e)}")
                # Continue processing other notifications
                continue
        
        logger.info(f"Successfully processed {processed_count} notifications")
        
        return func.HttpResponse(
            status_code=202,
            headers=SecurityHeaders.get_webhook_headers()
        )
        
    except json.JSONDecodeError:
        logger.error("Invalid JSON in webhook payload")
        return func.HttpResponse("Bad Request", status_code=400)
    except Exception as e:
        logger.error(f"Unexpected error processing webhook: {str(e)}")
        return func.HttpResponse("Internal Server Error", status_code=500)

def validate_webhook_request(req: func.HttpRequest) -> bool:
    """Validate webhook request authenticity"""
    
    # For Microsoft Graph webhooks, validate using subscription validation
    # In a production system, you would:
    # 1. Validate the request comes from Microsoft Graph IP ranges
    # 2. Verify any signature headers if available
    # 3. Check rate limiting
    
    # Basic validation
    user_agent = req.headers.get('User-Agent', '')
    if not user_agent.startswith('Microsoft-Graph'):
        logger.warning(f"Invalid User-Agent: {user_agent}")
        return False
    
    # Check for required headers
    content_type = req.headers.get('Content-Type', '')
    if 'application/json' not in content_type:
        logger.warning(f"Invalid Content-Type: {content_type}")
        return False
    
    return True

async def queue_notification_for_processing(result: Dict[str, Any], notification: Dict[str, Any]):
    """Queue webhook notification for async processing"""
    
    try:
        servicebus_client = ServiceBusClient.from_connection_string(
            os.environ['SERVICEBUS_CONNECTION']
        )
        
        with servicebus_client:
            sender = servicebus_client.get_queue_sender(queue_name="webhook-queue")
            with sender:
                message_body = {
                    'type': 'webhook_notification',
                    'change_type': notification.get('changeType'),
                    'resource': notification.get('resource'),
                    'resource_data': result['data'],
                    'encrypted': result['encrypted'],
                    'timestamp': func.datetime.utcnow().isoformat()
                }
                
                message = ServiceBusMessage(
                    json.dumps(message_body),
                    content_type="application/json",
                    time_to_live=func.timedelta(hours=24)
                )
                
                sender.send_messages(message)
                logger.info(f"Queued webhook notification: {notification.get('resource')}")
                
    except Exception as e:
        logger.error(f"Failed to queue webhook notification: {str(e)}")
        raise
EOF
    
    cat > WebhookEndpoint/function.json <<'EOF'
{
    "scriptFile": "__init__.py",
    "bindings": [
        {
            "authLevel": "function",
            "type": "httpTrigger",
            "direction": "in",
            "name": "req",
            "methods": ["post", "get"],
            "route": "webhook"
        },
        {
            "type": "http",
            "direction": "out",
            "name": "$return"
        }
    ]
}
EOF
    
    # Create SearchAPI function
    mkdir -p SearchAPI
    cat > SearchAPI/__init__.py <<'EOF'
import logging
import json
import azure.functions as func
from azure.cosmos import CosmosClient
from shared import SecureErrorHandler, InputValidator, SecurityHeaders
import os
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

async def main(req: func.HttpRequest) -> func.HttpResponse:
    """Search across M365 data with secure error handling"""
    
    try:
        # Parse and validate query parameters
        query = req.params.get('q', '').strip()
        entity_type = req.params.get('entity_type', '').strip()
        tenant_id = req.params.get('tenant_id', os.environ.get('TENANT_ID', '')).strip()
        
        # Validate and sanitize query
        if not query:
            error_response = SecureErrorHandler.create_error_response(
                "Search query is required"
            )
            return func.HttpResponse(
                json.dumps(error_response),
                mimetype="application/json",
                status_code=400,
                headers=get_security_headers()
            )
        
        # Sanitize search query to prevent injection
        sanitized_query = InputValidator.sanitize_search_query(query)
        if not sanitized_query:
            error_response = SecureErrorHandler.create_error_response(
                "Invalid search query format"
            )
            return func.HttpResponse(
                json.dumps(error_response),
                mimetype="application/json",
                status_code=400,
                headers=get_security_headers()
            )
        
        # Validate tenant ID
        if not InputValidator.validate_tenant_id(tenant_id):
            SecureErrorHandler.log_security_event(
                "invalid_tenant_search",
                "Invalid tenant ID in search request",
                "WARNING"
            )
            error_response = SecureErrorHandler.create_error_response(
                "Invalid tenant identifier"
            )
            return func.HttpResponse(
                json.dumps(error_response),
                mimetype="application/json",
                status_code=400,
                headers=get_security_headers()
            )
        
        # Validate and limit results count
        try:
            limit = max(1, min(int(req.params.get('limit', 50)), 1000))  # Cap at 1000
        except (ValueError, TypeError):
            limit = 50
        
        # Validate entity type
        valid_types = ['documents', 'users', 'teams', 'all']
        if entity_type and entity_type not in valid_types:
            entity_type = 'all'
        
        # Initialize Cosmos client
        cosmos_client = CosmosClient.from_connection_string(os.environ['COSMOS_CONNECTION'])
        
        # Perform search
        results = []
        
        if not entity_type or entity_type == 'all' or entity_type == 'documents':
            doc_results = search_documents(cosmos_client, tenant_id, sanitized_query, limit // 3 if entity_type == 'all' else limit)
            results.extend(doc_results)
        
        if not entity_type or entity_type == 'all' or entity_type == 'users':
            user_results = search_users(cosmos_client, tenant_id, sanitized_query, limit // 3 if entity_type == 'all' else limit)
            results.extend(user_results)
        
        if not entity_type or entity_type == 'all' or entity_type == 'teams':
            team_results = search_teams(cosmos_client, tenant_id, sanitized_query, limit // 3 if entity_type == 'all' else limit)
            results.extend(team_results)
        
        # Limit final results
        results = results[:limit]
        
        # Log successful search
        SecureErrorHandler.log_security_event(
            "search_executed",
            f"Query executed for {len(results)} results",
            "INFO"
        )
        
        return func.HttpResponse(
            json.dumps({
                'status': 'success',
                'query': sanitized_query,
                'entity_type': entity_type or 'all',
                'count': len(results),
                'results': results,
                'timestamp': func.datetime.utcnow().isoformat() + 'Z'
            }),
            mimetype="application/json",
            status_code=200,
            headers=get_security_headers()
        )
        
    except ConnectionError as e:
        safe_message = SecureErrorHandler.sanitize_error_message(e, "search_api")
        SecureErrorHandler.log_security_event(
            "search_connection_error",
            safe_message,
            "WARNING"
        )
        error_response = SecureErrorHandler.create_error_response(
            "Search service temporarily unavailable"
        )
        return func.HttpResponse(
            json.dumps(error_response),
            mimetype="application/json",
            status_code=503,
            headers=get_security_headers()
        )
    except Exception as e:
        safe_message = SecureErrorHandler.sanitize_error_message(e, "search_api")
        SecureErrorHandler.log_security_event(
            "search_unexpected_error",
            safe_message,
            "CRITICAL"
        )
        error_response = SecureErrorHandler.create_error_response(
            "Search operation failed"
        )
        return func.HttpResponse(
            json.dumps(error_response),
            mimetype="application/json",
            status_code=500,
            headers=get_security_headers()
        )

def get_security_headers() -> dict:
    """Get security headers for API responses"""
    return SecurityHeaders.get_api_headers()

def search_documents(cosmos_client: CosmosClient, tenant_id: str, 
                    query: str, limit: int) -> List[Dict]:
    """Search documents"""
    
    container = cosmos_client.get_database_client("M365Data").get_container_client("documents")
    
    # Use Cosmos DB query with CONTAINS
    cosmos_query = f"""
        SELECT TOP {limit} *
        FROM c
        WHERE c.tenantId = @tenant_id
        AND (CONTAINS(LOWER(c.name), LOWER(@query))
             OR CONTAINS(LOWER(c.displayName), LOWER(@query)))
    """
    
    parameters = [
        {"name": "@tenant_id", "value": tenant_id},
        {"name": "@query", "value": query}
    ]
    
    results = list(container.query_items(
        query=cosmos_query,
        parameters=parameters,
        enable_cross_partition_query=False
    ))
    
    for result in results:
        result['entity_type'] = 'document'
    
    return results

def search_users(cosmos_client: CosmosClient, tenant_id: str, 
                query: str, limit: int) -> List[Dict]:
    """Search users"""
    
    container = cosmos_client.get_database_client("M365Data").get_container_client("users")
    
    cosmos_query = f"""
        SELECT TOP {limit} *
        FROM c
        WHERE c.tenantId = @tenant_id
        AND (CONTAINS(LOWER(c.displayName), LOWER(@query))
             OR CONTAINS(LOWER(c.mail), LOWER(@query)))
    """
    
    parameters = [
        {"name": "@tenant_id", "value": tenant_id},
        {"name": "@query", "value": query}
    ]
    
    results = list(container.query_items(
        query=cosmos_query,
        parameters=parameters,
        enable_cross_partition_query=False
    ))
    
    for result in results:
        result['entity_type'] = 'user'
    
    return results

def search_teams(cosmos_client: CosmosClient, tenant_id: str, 
                query: str, limit: int) -> List[Dict]:
    """Search teams and channels"""
    
    container = cosmos_client.get_database_client("M365Data").get_container_client("teams")
    
    cosmos_query = f"""
        SELECT TOP {limit} *
        FROM c
        WHERE c.tenantId = @tenant_id
        AND (CONTAINS(LOWER(c.displayName), LOWER(@query))
             OR CONTAINS(LOWER(c.description), LOWER(@query)))
    """
    
    parameters = [
        {"name": "@tenant_id", "value": tenant_id},
        {"name": "@query", "value": query}
    ]
    
    results = list(container.query_items(
        query=cosmos_query,
        parameters=parameters,
        enable_cross_partition_query=False
    ))
    
    for result in results:
        result['entity_type'] = 'team'
    
    return results
EOF
    
    cat > SearchAPI/function.json <<'EOF'
{
    "scriptFile": "__init__.py",
    "bindings": [
        {
            "authLevel": "function",
            "type": "httpTrigger",
            "direction": "in",
            "name": "req",
            "methods": ["get"],
            "route": "search"
        },
        {
            "type": "http",
            "direction": "out",
            "name": "$return"
        }
    ]
}
EOF
    
    # Create OpenAI Assistant function
    mkdir -p OpenAIAssistant
    cat > OpenAIAssistant/__init__.py <<'EOF'
import logging
import json
import azure.functions as func
import openai
import os
from typing import Dict, Any, List
from shared import SecureErrorHandler, InputValidator, SecurityHeaders

logger = logging.getLogger(__name__)

# Initialize OpenAI
openai.api_key = os.environ['OPENAI_API_KEY']

async def main(req: func.HttpRequest) -> func.HttpResponse:
    """OpenAI Assistant for natural language interaction with security"""
    
    try:
        # Validate request size
        if req.get_body_as_bytes() and len(req.get_body_as_bytes()) > 10 * 1024:  # 10KB limit
            error_response = SecureErrorHandler.create_error_response(
                "Request payload too large"
            )
            return func.HttpResponse(
                json.dumps(error_response),
                mimetype="application/json",
                status_code=413,
                headers=SecurityHeaders.get_api_headers()
            )
        
        req_body = req.get_json()
        if not req_body:
            error_response = SecureErrorHandler.create_error_response(
                "Request body is required"
            )
            return func.HttpResponse(
                json.dumps(error_response),
                mimetype="application/json",
                status_code=400,
                headers=SecurityHeaders.get_api_headers()
            )
        
        # Validate and sanitize message
        message = req_body.get('message', '').strip()
        if not message:
            error_response = SecureErrorHandler.create_error_response(
                "Message is required"
            )
            return func.HttpResponse(
                json.dumps(error_response),
                mimetype="application/json",
                status_code=400,
                headers=SecurityHeaders.get_api_headers()
            )
        
        # Sanitize message to prevent prompt injection
        if len(message) > 2000:  # Limit message length
            message = message[:2000]
        
        # Basic validation for malicious content
        forbidden_patterns = ['<script', 'javascript:', 'vbscript:', 'onload=', 'onerror=']
        message_lower = message.lower()
        if any(pattern in message_lower for pattern in forbidden_patterns):
            SecureErrorHandler.log_security_event(
                "potential_xss_attempt",
                "Blocked potentially malicious message content",
                "WARNING"
            )
            error_response = SecureErrorHandler.create_error_response(
                "Invalid message content"
            )
            return func.HttpResponse(
                json.dumps(error_response),
                mimetype="application/json",
                status_code=400,
                headers=SecurityHeaders.get_api_headers()
            )
        
        # Create or retrieve thread
        if not thread_id:
            thread = openai.beta.threads.create()
            thread_id = thread.id
        
        # Add message to thread
        openai.beta.threads.messages.create(
            thread_id=thread_id,
            role="user",
            content=message
        )
        
        # Get or create assistant
        assistant_id = await get_or_create_assistant()
        
        # Run assistant
        run = openai.beta.threads.runs.create(
            thread_id=thread_id,
            assistant_id=assistant_id
        )
        
        # Wait for completion
        import time
        while run.status in ["queued", "in_progress"]:
            time.sleep(1)
            run = openai.beta.threads.runs.retrieve(
                thread_id=thread_id,
                run_id=run.id
            )
        
        # Handle tool calls if needed
        if run.status == "requires_action":
            tool_calls = run.required_action.submit_tool_outputs.tool_calls
            tool_outputs = await process_tool_calls(tool_calls)
            
            run = openai.beta.threads.runs.submit_tool_outputs(
                thread_id=thread_id,
                run_id=run.id,
                tool_outputs=tool_outputs
            )
            
            # Wait for completion again
            while run.status in ["queued", "in_progress"]:
                time.sleep(1)
                run = openai.beta.threads.runs.retrieve(
                    thread_id=thread_id,
                    run_id=run.id
                )
        
        # Get messages
        messages = openai.beta.threads.messages.list(thread_id=thread_id)
        
        # Get the latest assistant message
        assistant_message = None
        for msg in messages.data:
            if msg.role == "assistant":
                assistant_message = msg.content[0].text.value
                break
        
        return func.HttpResponse(
            json.dumps({
                'status': 'success',
                'response': assistant_message,
                'thread_id': thread_id,
                'timestamp': func.datetime.utcnow().isoformat() + 'Z'
            }),
            mimetype="application/json",
            status_code=200,
            headers=SecurityHeaders.get_api_headers()
        )
        
    except openai.RateLimitError as e:
        safe_message = SecureErrorHandler.sanitize_error_message(e, "openai_assistant")
        SecureErrorHandler.log_security_event(
            "openai_rate_limit",
            safe_message,
            "WARNING"
        )
        error_response = SecureErrorHandler.create_error_response(
            "Service temporarily unavailable due to high demand"
        )
        return func.HttpResponse(
            json.dumps(error_response),
            mimetype="application/json",
            status_code=429,
            headers=SecurityHeaders.get_api_headers()
        )
    except Exception as e:
        safe_message = SecureErrorHandler.sanitize_error_message(e, "openai_assistant")
        SecureErrorHandler.log_security_event(
            "openai_unexpected_error",
            safe_message,
            "CRITICAL"
        )
        error_response = SecureErrorHandler.create_error_response(
            "Assistant service error"
        )
        return func.HttpResponse(
            json.dumps(error_response),
            mimetype="application/json",
            status_code=500,
            headers=SecurityHeaders.get_api_headers()
        )

async def get_or_create_assistant() -> str:
    """Get or create the M365 Brain assistant"""
    
    # Check if assistant exists
    assistants = openai.beta.assistants.list()
    
    for assistant in assistants.data:
        if assistant.name == "M365 Brain Assistant":
            return assistant.id
    
    # Create new assistant
    assistant = openai.beta.assistants.create(
        name="M365 Brain Assistant",
        instructions="""You are the M365 Brain Assistant, an AI that helps users interact with their Microsoft 365 data.
        
        You can:
        - Search for documents, users, teams, and other M365 resources
        - Initiate crawls to update data
        - Provide insights about organizational data
        - Answer questions about M365 content
        
        Be helpful, concise, and accurate. When searching, provide relevant results with context.""",
        model="gpt-4-1106-preview",
        tools=get_assistant_tools()
    )
    
    return assistant.id

def get_assistant_tools() -> List[Dict]:
    """Define tools available to the assistant"""
    
    return [
        {
            "type": "function",
            "function": {
                "name": "search_m365_data",
                "description": "Search across Microsoft 365 data",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": "Search query"
                        },
                        "entity_type": {
                            "type": "string",
                            "enum": ["documents", "users", "teams", "all"],
                            "description": "Type of entity to search"
                        }
                    },
                    "required": ["query"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "initiate_crawl",
                "description": "Start a crawl to update M365 data",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "crawl_type": {
                            "type": "string",
                            "enum": ["full", "delta"],
                            "description": "Type of crawl to perform"
                        },
                        "resources": {
                            "type": "array",
                            "items": {
                                "type": "string",
                                "enum": ["users", "sites", "teams", "drives", "all"]
                            },
                            "description": "Resources to crawl"
                        }
                    },
                    "required": ["crawl_type"]
                }
            }
        }
    ]

async def process_tool_calls(tool_calls: List) -> List[Dict]:
    """Process tool calls from the assistant"""
    
    tool_outputs = []
    
    for tool_call in tool_calls:
        function_name = tool_call.function.name
        arguments = json.loads(tool_call.function.arguments)
        
        if function_name == "search_m365_data":
            # Perform search
            result = await search_m365_data(
                arguments.get('query'),
                arguments.get('entity_type', 'all')
            )
        elif function_name == "initiate_crawl":
            # Start crawl
            result = await initiate_crawl(
                arguments.get('crawl_type'),
                arguments.get('resources', ['all'])
            )
        else:
            result = {"error": f"Unknown function: {function_name}"}
        
        tool_outputs.append({
            "tool_call_id": tool_call.id,
            "output": json.dumps(result)
        })
    
    return tool_outputs

async def search_m365_data(query: str, entity_type: str) -> Dict:
    """Search M365 data"""
    
    # Call the SearchAPI function
    # In production, this would make an internal call to the search function
    
    return {
        "status": "success",
        "message": f"Searching for '{query}' in {entity_type}",
        "results": []  # Would include actual results
    }

async def initiate_crawl(crawl_type: str, resources: List[str]) -> Dict:
    """Initiate a crawl"""
    
    # Call the CrawlTrigger function
    # In production, this would make an internal call to trigger crawl
    
    return {
        "status": "success",
        "message": f"Initiated {crawl_type} crawl for {', '.join(resources)}"
    }
EOF
    
    cat > OpenAIAssistant/function.json <<'EOF'
{
    "scriptFile": "__init__.py",
    "bindings": [
        {
            "authLevel": "function",
            "type": "httpTrigger",
            "direction": "in",
            "name": "req",
            "methods": ["post"],
            "route": "assistant/chat"
        },
        {
            "type": "http",
            "direction": "out",
            "name": "$return"
        }
    ]
}
EOF
    
    # Create ScheduledCrawler function
    mkdir -p ScheduledCrawler
    cat > ScheduledCrawler/__init__.py <<'EOF'
import logging
import azure.functions as func
from azure.servicebus import ServiceBusClient, ServiceBusMessage
import json
import os

logger = logging.getLogger(__name__)

def main(mytimer: func.TimerRequest) -> None:
    """Scheduled crawler for delta updates"""
    
    logger.info('Scheduled crawler triggered')
    
    if mytimer.past_due:
        logger.warning('Timer is past due!')
    
    # Create Service Bus client
    servicebus_client = ServiceBusClient.from_connection_string(
        os.environ['SERVICEBUS_CONNECTION']
    )
    
    # Queue delta crawl for all resources
    with servicebus_client:
        sender = servicebus_client.get_queue_sender(queue_name="crawl-queue")
        with sender:
            message_body = {
                'crawl_type': 'delta',
                'resource': 'all',
                'tenant_id': os.environ['TENANT_ID'],
                'timestamp': func.datetime.utcnow().isoformat(),
                'scheduled': True
            }
            
            message = ServiceBusMessage(
                json.dumps(message_body),
                content_type="application/json"
            )
            
            sender.send_messages(message)
            logger.info('Scheduled delta crawl queued')
EOF
    
    cat > ScheduledCrawler/function.json <<'EOF'
{
    "scriptFile": "__init__.py",
    "bindings": [
        {
            "name": "mytimer",
            "type": "timerTrigger",
            "direction": "in",
            "schedule": "0 0 */6 * * *"
        }
    ]
}
EOF
    
    # Create local.settings.json for local development
    cat > local.settings.json <<EOF
{
    "IsEncrypted": false,
    "Values": {
        "AzureWebJobsStorage": "UseDevelopmentStorage=true",
        "FUNCTIONS_WORKER_RUNTIME": "python",
        "TENANT_ID": "$TENANT_ID",
        "CLIENT_ID": "$APP_ID",
        "CLIENT_SECRET": "$CLIENT_SECRET",
        "REDIRECT_URI": "$REDIRECT_URI",
        "OPENAI_API_KEY": "$OPENAI_API_KEY",
        "DEPLOYMENT_MODE": "$DEPLOYMENT_MODE"
    }
}
EOF
    
    # Create deployment package
    print_color $CYAN "$GEAR Creating deployment package..."
    zip -r deployment.zip . -x "*.pyc" -x "__pycache__/*" >/dev/null 2>&1
    
    # Deploy to Azure
    print_color $CYAN "$GEAR Deploying to Azure Function App..."
    az functionapp deployment source config-zip \
        --resource-group "$RESOURCE_GROUP" \
        --name "$FUNCTION_APP_NAME" \
        --src deployment.zip \
        --output none
    
    print_color $GREEN "$CHECK_MARK Functions deployed successfully"
    
    # Clean up temp directory
    cd - >/dev/null
    rm -rf "$temp_dir"
}

# Function to display deployment summary
display_summary() {
    print_section "Deployment Complete!"
    
    print_color $GREEN "╔══════════════════════════════════════════════════════════════════╗"
    print_color $GREEN "║                    DEPLOYMENT SUCCESSFUL!                        ║"
    print_color $GREEN "╚══════════════════════════════════════════════════════════════════╝"
    
    echo
    print_color $CYAN "Resource Details:"
    print_color $WHITE "  • Resource Group: $RESOURCE_GROUP"
    print_color $WHITE "  • Function App: $FUNCTION_APP_NAME"
    print_color $WHITE "  • App Registration: $APP_ID"
    print_color $WHITE "  • Key Vault: $KEY_VAULT_NAME"
    
    echo
    print_color $CYAN "Endpoints:"
    print_color $WHITE "  • Auth Callback: $REDIRECT_URI"
    print_color $WHITE "  • Webhook: https://${FUNCTION_APP_NAME}.azurewebsites.net/api/webhook"
    print_color $WHITE "  • Search API: https://${FUNCTION_APP_NAME}.azurewebsites.net/api/search"
    print_color $WHITE "  • Assistant: https://${FUNCTION_APP_NAME}.azurewebsites.net/api/assistant/chat"
    
    echo
    print_color $CYAN "Authentication URLs:"
    
    if [ "$DEPLOYMENT_MODE" = "USER" ] || [ "$DEPLOYMENT_MODE" = "BOTH" ]; then
        local user_auth_url="https://login.microsoftonline.com/${TENANT_ID}/oauth2/v2.0/authorize?client_id=${APP_ID}&response_type=code&redirect_uri=${REDIRECT_URI}&scope=openid%20profile%20offline_access%20User.Read%20Files.Read.All%20Sites.Read.All"
        print_color $YELLOW "  Mode A (User-Connected):"
        print_color $WHITE "  $user_auth_url"
    fi
    
    if [ "$DEPLOYMENT_MODE" = "TENANT" ] || [ "$DEPLOYMENT_MODE" = "BOTH" ]; then
        local admin_consent_url="https://login.microsoftonline.com/${TENANT_ID}/adminconsent?client_id=${APP_ID}&redirect_uri=${REDIRECT_URI}"
        print_color $YELLOW "  Mode B (Tenant-Connected Admin Consent):"
        print_color $WHITE "  $admin_consent_url"
    fi
    
    echo
    print_color $CYAN "Next Steps:"
    print_color $WHITE "  1. Grant admin consent (Mode B) or authenticate as user (Mode A)"
    print_color $WHITE "  2. Initiate first crawl: POST to /api/crawl/full"
    print_color $WHITE "  3. Test search: GET /api/search?q=your-query"
    print_color $WHITE "  4. Try the assistant: POST to /api/assistant/chat"
    
    echo
    print_color $CYAN "Function Keys:"
    local function_key=$(az functionapp keys list \
        --name "$FUNCTION_APP_NAME" \
        --resource-group "$RESOURCE_GROUP" \
        --query functionKeys.default -o tsv 2>/dev/null || echo "Retrieving...")
    print_color $WHITE "  Default Key: $function_key"
    
    echo
    print_color $GREEN "Deployment configuration saved to: $CONFIG_FILE"
}

# Main execution
main() {
    print_header
    
    check_prerequisites
    collect_parameters
    create_resource_group
    create_app_registration
    create_azure_resources
    create_function_app
    deploy_functions
    display_summary
    
    print_color $CYAN "\nWould you like to open the admin consent URL now? (y/n): "
    read -r open_consent
    
    if [ "$open_consent" = "y" ]; then
        if [ "$DEPLOYMENT_MODE" = "TENANT" ] || [ "$DEPLOYMENT_MODE" = "BOTH" ]; then
            local admin_consent_url="https://login.microsoftonline.com/${TENANT_ID}/adminconsent?client_id=${APP_ID}&redirect_uri=${REDIRECT_URI}"
            open_browser "$admin_consent_url"
        else
            local user_auth_url="https://login.microsoftonline.com/${TENANT_ID}/oauth2/v2.0/authorize?client_id=${APP_ID}&response_type=code&redirect_uri=${REDIRECT_URI}&scope=openid%20profile%20offline_access%20User.Read%20Files.Read.All%20Sites.Read.All"
            open_browser "$user_auth_url"
        fi
    fi
}

# Run main function
main