#!/bin/bash

#############################################################################
# M365 Big Brain Crawl - Complete Deployment Script
# Deploys a multi-tenant Microsoft 365 data crawler with OpenAI integration
# Run this script in Azure Cloud Shell for automatic deployment
#############################################################################

set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

#############################################################################
# CONFIGURATION SECTION
#############################################################################

# Generate unique deployment identifier
DEPLOYMENT_ID="m365brain$(date +%s)"
RESOURCE_PREFIX="m365brain"

# Azure Configuration
print_status "Configuring deployment parameters..."
SUBSCRIPTION_ID=$(az account show --query id -o tsv)
LOCATION=${AZURE_LOCATION:-"eastus"}
RESOURCE_GROUP="${RESOURCE_PREFIX}-rg"

# Service Names (using consistent naming)
STORAGE_ACCOUNT="${RESOURCE_PREFIX}stor$(date +%s | tail -c 5)"
COSMOS_ACCOUNT="${RESOURCE_PREFIX}-cosmos"
FUNCTION_APP="${RESOURCE_PREFIX}-func"
SERVICE_BUS="${RESOURCE_PREFIX}-sbus"
KEY_VAULT="${RESOURCE_PREFIX}-kv-$(date +%s | tail -c 5)"
APP_INSIGHTS="${RESOURCE_PREFIX}-insights"
APP_SERVICE_PLAN="${RESOURCE_PREFIX}-plan"

# Application Registration
APP_NAME="${RESOURCE_PREFIX}-app"
APP_DISPLAY_NAME="M365 Big Brain Crawler"

# OpenAI Configuration (will be set by user)
OPENAI_API_KEY=""
OPENAI_ENDPOINT="https://api.openai.com/v1"
OPENAI_MODEL="gpt-4-turbo-preview"

#############################################################################
# VALIDATE PREREQUISITES
#############################################################################

print_status "Validating prerequisites..."

# Check if running in Azure Cloud Shell
if [ -z "$AZURE_HTTP_USER_AGENT" ]; then
    print_warning "Not running in Azure Cloud Shell. Some features may not work correctly."
fi

# Check Azure CLI login
if ! az account show > /dev/null 2>&1; then
    print_error "Not logged into Azure. Please run 'az login' first."
    exit 1
fi

print_success "Prerequisites validated"

#############################################################################
# COLLECT REQUIRED INPUTS
#############################################################################

print_status "Collecting configuration inputs..."

# Tenant configuration
read -p "Enter your Azure AD Tenant ID: " TENANT_ID
if [ -z "$TENANT_ID" ]; then
    print_error "Tenant ID is required"
    exit 1
fi

# OpenAI Configuration
read -p "Enter your OpenAI API Key: " OPENAI_API_KEY
if [ -z "$OPENAI_API_KEY" ]; then
    print_error "OpenAI API Key is required"
    exit 1
fi

# Optional: Custom resource group name
read -p "Enter Resource Group name (default: ${RESOURCE_GROUP}): " CUSTOM_RG
if [ ! -z "$CUSTOM_RG" ]; then
    RESOURCE_GROUP="$CUSTOM_RG"
fi

# Optional: Azure region
read -p "Enter Azure region (default: ${LOCATION}): " CUSTOM_LOCATION
if [ ! -z "$CUSTOM_LOCATION" ]; then
    LOCATION="$CUSTOM_LOCATION"
fi

print_success "Configuration collected"

#############################################################################
# CREATE RESOURCE GROUP
#############################################################################

print_status "Creating resource group ${RESOURCE_GROUP}..."
az group create --name $RESOURCE_GROUP --location $LOCATION --output none
print_success "Resource group created"

#############################################################################
# CREATE APP REGISTRATION
#############################################################################

print_status "Creating Azure AD App Registration..."

# Create the app registration
APP_ID=$(az ad app create \
    --display-name "$APP_DISPLAY_NAME" \
    --sign-in-audience AzureADMultipleOrgs \
    --query appId -o tsv)

# Create service principal
az ad sp create --id $APP_ID --output none

# Create client secret
CLIENT_SECRET=$(az ad app credential reset \
    --id $APP_ID \
    --append \
    --query password -o tsv)

print_success "App Registration created with ID: $APP_ID"

# Configure API permissions
print_status "Configuring Microsoft Graph API permissions..."

# Microsoft Graph API ID
GRAPH_API_ID="00000003-0000-0000-c000-000000000000"

# Define required permissions
az ad app permission add --id $APP_ID --api $GRAPH_API_ID \
    --api-permissions \
    e1fe6dd8-ba31-4d61-89e7-88639da4683d=Scope \
    37f7f235-527c-4136-accd-4a02d197296e=Scope \
    14dad69e-099b-42c9-810b-d002981feec1=Scope \
    7427e0e9-2fba-42fe-b0c0-848c9e6a8182=Scope \
    ff91d191-99a0-4c8e-9c92-00ab3f362a16=Scope \
    5b567255-7703-4780-807c-7be8301ae99b=Role \
    7ab1d382-f21e-4acd-a863-ba3e13f7da61=Role \
    5df6fe86-1be0-44eb-b916-7bd443a71236=Role \
    9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30=Role \
    df021288-bdef-4463-88db-98f22de89214=Role \
    --output none

print_warning "Admin consent required for Graph permissions. Visit: https://portal.azure.com/#blade/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/CallAnAPI/appId/${APP_ID}"

#############################################################################
# CREATE STORAGE ACCOUNT
#############################################################################

print_status "Creating Storage Account..."
az storage account create \
    --name $STORAGE_ACCOUNT \
    --resource-group $RESOURCE_GROUP \
    --location $LOCATION \
    --sku Standard_LRS \
    --kind StorageV2 \
    --output none

STORAGE_CONNECTION=$(az storage account show-connection-string \
    --name $STORAGE_ACCOUNT \
    --resource-group $RESOURCE_GROUP \
    --query connectionString -o tsv)

# Create containers
az storage container create --name documents --connection-string "$STORAGE_CONNECTION" --output none
az storage container create --name crawl-state --connection-string "$STORAGE_CONNECTION" --output none
az storage container create --name webhooks --connection-string "$STORAGE_CONNECTION" --output none

print_success "Storage Account created"

#############################################################################
# CREATE COSMOS DB
#############################################################################

print_status "Creating Cosmos DB Account..."
az cosmosdb create \
    --name $COSMOS_ACCOUNT \
    --resource-group $RESOURCE_GROUP \
    --location $LOCATION \
    --default-consistency-level Session \
    --enable-free-tier false \
    --output none

# Create database and containers
az cosmosdb sql database create \
    --account-name $COSMOS_ACCOUNT \
    --resource-group $RESOURCE_GROUP \
    --name M365Data \
    --output none

# Create containers with partition keys
az cosmosdb sql container create \
    --account-name $COSMOS_ACCOUNT \
    --resource-group $RESOURCE_GROUP \
    --database-name M365Data \
    --name Documents \
    --partition-key-path /tenantId \
    --throughput 400 \
    --output none

az cosmosdb sql container create \
    --account-name $COSMOS_ACCOUNT \
    --resource-group $RESOURCE_GROUP \
    --database-name M365Data \
    --name Users \
    --partition-key-path /tenantId \
    --throughput 400 \
    --output none

az cosmosdb sql container create \
    --account-name $COSMOS_ACCOUNT \
    --resource-group $RESOURCE_GROUP \
    --database-name M365Data \
    --name Teams \
    --partition-key-path /tenantId \
    --throughput 400 \
    --output none

az cosmosdb sql container create \
    --account-name $COSMOS_ACCOUNT \
    --resource-group $RESOURCE_GROUP \
    --database-name M365Data \
    --name CrawlState \
    --partition-key-path /tenantId \
    --throughput 400 \
    --output none

COSMOS_CONNECTION=$(az cosmosdb keys list \
    --name $COSMOS_ACCOUNT \
    --resource-group $RESOURCE_GROUP \
    --type connection-strings \
    --query connectionStrings[0].connectionString -o tsv)

print_success "Cosmos DB created"

#############################################################################
# CREATE SERVICE BUS
#############################################################################

print_status "Creating Service Bus..."
az servicebus namespace create \
    --name $SERVICE_BUS \
    --resource-group $RESOURCE_GROUP \
    --location $LOCATION \
    --sku Standard \
    --output none

# Create queues
az servicebus queue create \
    --name crawl-queue \
    --namespace-name $SERVICE_BUS \
    --resource-group $RESOURCE_GROUP \
    --max-size 5120 \
    --default-message-time-to-live P14D \
    --output none

az servicebus queue create \
    --name process-queue \
    --namespace-name $SERVICE_BUS \
    --resource-group $RESOURCE_GROUP \
    --max-size 5120 \
    --default-message-time-to-live P14D \
    --output none

az servicebus queue create \
    --name webhook-queue \
    --namespace-name $SERVICE_BUS \
    --resource-group $RESOURCE_GROUP \
    --max-size 5120 \
    --default-message-time-to-live P14D \
    --output none

SERVICE_BUS_CONNECTION=$(az servicebus namespace authorization-rule keys list \
    --name RootManageSharedAccessKey \
    --namespace-name $SERVICE_BUS \
    --resource-group $RESOURCE_GROUP \
    --query primaryConnectionString -o tsv)

print_success "Service Bus created"

#############################################################################
# CREATE KEY VAULT
#############################################################################

print_status "Creating Key Vault..."
az keyvault create \
    --name $KEY_VAULT \
    --resource-group $RESOURCE_GROUP \
    --location $LOCATION \
    --output none

# Store secrets
az keyvault secret set --vault-name $KEY_VAULT --name "TenantId" --value "$TENANT_ID" --output none
az keyvault secret set --vault-name $KEY_VAULT --name "ClientId" --value "$APP_ID" --output none
az keyvault secret set --vault-name $KEY_VAULT --name "ClientSecret" --value "$CLIENT_SECRET" --output none
az keyvault secret set --vault-name $KEY_VAULT --name "OpenAIKey" --value "$OPENAI_API_KEY" --output none
az keyvault secret set --vault-name $KEY_VAULT --name "StorageConnection" --value "$STORAGE_CONNECTION" --output none
az keyvault secret set --vault-name $KEY_VAULT --name "CosmosConnection" --value "$COSMOS_CONNECTION" --output none
az keyvault secret set --vault-name $KEY_VAULT --name "ServiceBusConnection" --value "$SERVICE_BUS_CONNECTION" --output none

print_success "Key Vault created and secrets stored"

#############################################################################
# CREATE APPLICATION INSIGHTS
#############################################################################

print_status "Creating Application Insights..."
az monitor app-insights component create \
    --app $APP_INSIGHTS \
    --location $LOCATION \
    --resource-group $RESOURCE_GROUP \
    --application-type web \
    --output none

INSIGHTS_KEY=$(az monitor app-insights component show \
    --app $APP_INSIGHTS \
    --resource-group $RESOURCE_GROUP \
    --query instrumentationKey -o tsv)

print_success "Application Insights created"

#############################################################################
# CREATE FUNCTION APP
#############################################################################

print_status "Creating Function App..."

# Create App Service Plan
az appservice plan create \
    --name $APP_SERVICE_PLAN \
    --resource-group $RESOURCE_GROUP \
    --location $LOCATION \
    --sku EP1 \
    --is-linux \
    --output none

# Create Function App
az functionapp create \
    --name $FUNCTION_APP \
    --resource-group $RESOURCE_GROUP \
    --plan $APP_SERVICE_PLAN \
    --runtime python \
    --runtime-version 3.11 \
    --storage-account $STORAGE_ACCOUNT \
    --functions-version 4 \
    --output none

# Configure Function App settings
print_status "Configuring Function App settings..."
az functionapp config appsettings set \
    --name $FUNCTION_APP \
    --resource-group $RESOURCE_GROUP \
    --settings \
    "TENANT_ID=$TENANT_ID" \
    "CLIENT_ID=$APP_ID" \
    "CLIENT_SECRET=$CLIENT_SECRET" \
    "OPENAI_API_KEY=$OPENAI_API_KEY" \
    "OPENAI_ENDPOINT=$OPENAI_ENDPOINT" \
    "OPENAI_MODEL=$OPENAI_MODEL" \
    "STORAGE_CONNECTION=$STORAGE_CONNECTION" \
    "COSMOS_CONNECTION=$COSMOS_CONNECTION" \
    "SERVICE_BUS_CONNECTION=$SERVICE_BUS_CONNECTION" \
    "APPINSIGHTS_INSTRUMENTATIONKEY=$INSIGHTS_KEY" \
    "KEY_VAULT_NAME=$KEY_VAULT" \
    "WEBSITE_RUN_FROM_PACKAGE=1" \
    --output none

# Enable managed identity
az functionapp identity assign \
    --name $FUNCTION_APP \
    --resource-group $RESOURCE_GROUP \
    --output none

# Grant Key Vault access
FUNCTION_IDENTITY=$(az functionapp identity show \
    --name $FUNCTION_APP \
    --resource-group $RESOURCE_GROUP \
    --query principalId -o tsv)

az keyvault set-policy \
    --name $KEY_VAULT \
    --object-id $FUNCTION_IDENTITY \
    --secret-permissions get list \
    --output none

print_success "Function App created and configured"

#############################################################################
# DEPLOY FUNCTION CODE
#############################################################################

print_status "Deploying Function App code..."

# Create temporary directory for function code
TEMP_DIR=$(mktemp -d)
cd $TEMP_DIR

# Create requirements.txt
cat > requirements.txt << 'EOF'
azure-functions==1.18.0
azure-identity==1.15.0
azure-keyvault-secrets==4.7.0
azure-storage-blob==12.19.0
azure-cosmos==4.5.1
azure-servicebus==7.11.4
msal==1.26.0
requests==2.31.0
openai==1.12.0
python-dateutil==2.8.2
typing-extensions==4.9.0
EOF

# Create host.json
cat > host.json << 'EOF'
{
  "version": "2.0",
  "logging": {
    "applicationInsights": {
      "samplingSettings": {
        "isEnabled": true,
        "excludedTypes": "Request"
      }
    }
  },
  "extensionBundle": {
    "id": "Microsoft.Azure.Functions.ExtensionBundle",
    "version": "[4.*, 5.0.0)"
  },
  "functionTimeout": "00:10:00"
}
EOF

# Create function.json for HTTP triggers
mkdir -p CrawlTrigger
cat > CrawlTrigger/function.json << 'EOF'
{
  "scriptFile": "__init__.py",
  "bindings": [
    {
      "authLevel": "function",
      "type": "httpTrigger",
      "direction": "in",
      "name": "req",
      "methods": ["post", "get"],
      "route": "crawl/{action?}"
    },
    {
      "type": "http",
      "direction": "out",
      "name": "$return"
    }
  ]
}
EOF

# Create main crawler function
cat > CrawlTrigger/__init__.py << 'EOF'
import logging
import json
import os
import azure.functions as func
from datetime import datetime, timedelta
import requests
from msal import ConfidentialClientApplication
from azure.storage.blob import BlobServiceClient
from azure.cosmos import CosmosClient
from azure.servicebus import ServiceBusClient, ServiceBusMessage
from typing import Dict, List, Any, Optional

# Configuration
TENANT_ID = os.environ["TENANT_ID"]
CLIENT_ID = os.environ["CLIENT_ID"]
CLIENT_SECRET = os.environ["CLIENT_SECRET"]
STORAGE_CONNECTION = os.environ["STORAGE_CONNECTION"]
COSMOS_CONNECTION = os.environ["COSMOS_CONNECTION"]
SERVICE_BUS_CONNECTION = os.environ["SERVICE_BUS_CONNECTION"]

# Initialize clients
blob_client = BlobServiceClient.from_connection_string(STORAGE_CONNECTION)
cosmos_client = CosmosClient.from_connection_string(COSMOS_CONNECTION)
database = cosmos_client.get_database_client("M365Data")
servicebus_client = ServiceBusClient.from_connection_string(SERVICE_BUS_CONNECTION)

class GraphClient:
    """Microsoft Graph API client with authentication handling"""
    
    def __init__(self, tenant_id: str, client_id: str, client_secret: str):
        self.tenant_id = tenant_id
        self.authority = f"https://login.microsoftonline.com/{tenant_id}"
        self.scope = ["https://graph.microsoft.com/.default"]
        
        self.app = ConfidentialClientApplication(
            client_id,
            authority=self.authority,
            client_credential=client_secret
        )
        self.token = None
        self.token_expiry = None
    
    def get_token(self) -> str:
        """Get or refresh access token"""
        if self.token and self.token_expiry and datetime.utcnow() < self.token_expiry:
            return self.token
        
        result = self.app.acquire_token_silent(self.scope, account=None)
        if not result:
            result = self.app.acquire_token_for_client(scopes=self.scope)
        
        if "access_token" in result:
            self.token = result["access_token"]
            self.token_expiry = datetime.utcnow() + timedelta(seconds=result.get("expires_in", 3600))
            return self.token
        else:
            raise Exception(f"Failed to acquire token: {result.get('error_description')}")
    
    def make_request(self, url: str, params: Optional[Dict] = None) -> Dict:
        """Make authenticated request to Graph API"""
        headers = {
            "Authorization": f"Bearer {self.get_token()}",
            "Content-Type": "application/json"
        }
        
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        return response.json()
    
    def get_all_pages(self, url: str, params: Optional[Dict] = None) -> List[Dict]:
        """Get all pages of results from Graph API"""
        results = []
        next_link = url
        
        while next_link:
            if next_link == url:
                data = self.make_request(next_link, params)
            else:
                data = self.make_request(next_link)
            
            results.extend(data.get("value", []))
            next_link = data.get("@odata.nextLink")
        
        return results

class M365Crawler:
    """Main crawler for M365 data"""
    
    def __init__(self, graph_client: GraphClient):
        self.graph = graph_client
        self.documents_container = database.get_container_client("Documents")
        self.users_container = database.get_container_client("Users")
        self.teams_container = database.get_container_client("Teams")
        self.state_container = database.get_container_client("CrawlState")
    
    def crawl_users(self) -> List[Dict]:
        """Crawl all users in the tenant"""
        logging.info("Starting user crawl")
        users = self.graph.get_all_pages(
            "https://graph.microsoft.com/v1.0/users",
            params={"$select": "id,displayName,mail,userPrincipalName,jobTitle,department,officeLocation"}
        )
        
        for user in users:
            user["tenantId"] = self.tenant_id
            user["crawledAt"] = datetime.utcnow().isoformat()
            user["entityType"] = "user"
            
            self.users_container.upsert_item(user)
        
        logging.info(f"Crawled {len(users)} users")
        return users
    
    def crawl_groups(self) -> List[Dict]:
        """Crawl all groups in the tenant"""
        logging.info("Starting group crawl")
        groups = self.graph.get_all_pages(
            "https://graph.microsoft.com/v1.0/groups",
            params={"$select": "id,displayName,description,mail,groupTypes"}
        )
        
        for group in groups:
            group["tenantId"] = self.tenant_id
            group["crawledAt"] = datetime.utcnow().isoformat()
            group["entityType"] = "group"
            
            self.teams_container.upsert_item(group)
        
        logging.info(f"Crawled {len(groups)} groups")
        return groups
    
    def crawl_teams(self) -> List[Dict]:
        """Crawl all teams in the tenant"""
        logging.info("Starting teams crawl")
        teams = self.graph.get_all_pages(
            "https://graph.microsoft.com/v1.0/teams",
            params={"$select": "id,displayName,description,webUrl"}
        )
        
        for team in teams:
            team["tenantId"] = self.tenant_id
            team["crawledAt"] = datetime.utcnow().isoformat()
            team["entityType"] = "team"
            
            # Crawl channels for each team
            channels = self.graph.get_all_pages(
                f"https://graph.microsoft.com/v1.0/teams/{team['id']}/channels"
            )
            team["channels"] = channels
            
            self.teams_container.upsert_item(team)
            
            # Queue channel messages for processing
            with servicebus_client.get_queue_sender("crawl-queue") as sender:
                for channel in channels:
                    message_data = {
                        "type": "channel_messages",
                        "teamId": team["id"],
                        "channelId": channel["id"],
                        "tenantId": self.tenant_id
                    }
                    sender.send_messages(ServiceBusMessage(json.dumps(message_data)))
        
        logging.info(f"Crawled {len(teams)} teams")
        return teams
    
    def crawl_sharepoint_sites(self) -> List[Dict]:
        """Crawl SharePoint sites"""
        logging.info("Starting SharePoint sites crawl")
        sites = self.graph.get_all_pages(
            "https://graph.microsoft.com/v1.0/sites",
            params={"$select": "id,name,displayName,webUrl,createdDateTime"}
        )
        
        for site in sites:
            site["tenantId"] = self.tenant_id
            site["crawledAt"] = datetime.utcnow().isoformat()
            site["entityType"] = "sharepoint_site"
            
            self.documents_container.upsert_item(site)
            
            # Queue document libraries for processing
            with servicebus_client.get_queue_sender("crawl-queue") as sender:
                message_data = {
                    "type": "site_documents",
                    "siteId": site["id"],
                    "tenantId": self.tenant_id
                }
                sender.send_messages(ServiceBusMessage(json.dumps(message_data)))
        
        logging.info(f"Crawled {len(sites)} SharePoint sites")
        return sites
    
    def crawl_onedrive_users(self) -> None:
        """Queue OneDrive crawl for all users"""
        logging.info("Queueing OneDrive crawls")
        users = self.graph.get_all_pages(
            "https://graph.microsoft.com/v1.0/users",
            params={"$select": "id,userPrincipalName"}
        )
        
        with servicebus_client.get_queue_sender("crawl-queue") as sender:
            for user in users:
                message_data = {
                    "type": "onedrive",
                    "userId": user["id"],
                    "userPrincipalName": user["userPrincipalName"],
                    "tenantId": self.tenant_id
                }
                sender.send_messages(ServiceBusMessage(json.dumps(message_data)))
        
        logging.info(f"Queued OneDrive crawl for {len(users)} users")
    
    def save_crawl_state(self, crawl_type: str, status: str, details: Dict = None):
        """Save crawl state to Cosmos DB"""
        state = {
            "id": f"{crawl_type}_{datetime.utcnow().isoformat()}",
            "tenantId": self.tenant_id,
            "crawlType": crawl_type,
            "status": status,
            "timestamp": datetime.utcnow().isoformat(),
            "details": details or {}
        }
        
        self.state_container.upsert_item(state)

def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('M365 Crawler HTTP trigger processed a request.')
    
    try:
        # Initialize Graph client
        graph_client = GraphClient(TENANT_ID, CLIENT_ID, CLIENT_SECRET)
        crawler = M365Crawler(graph_client)
        
        # Get action from route
        action = req.route_params.get('action', 'status')
        
        if action == 'full':
            # Perform full crawl
            results = {
                "users": len(crawler.crawl_users()),
                "groups": len(crawler.crawl_groups()),
                "teams": len(crawler.crawl_teams()),
                "sites": len(crawler.crawl_sharepoint_sites())
            }
            
            # Queue detailed crawls
            crawler.crawl_onedrive_users()
            
            crawler.save_crawl_state("full_crawl", "completed", results)
            
            return func.HttpResponse(
                json.dumps({
                    "status": "success",
                    "message": "Full crawl initiated",
                    "results": results
                }),
                mimetype="application/json"
            )
        
        elif action == 'users':
            users = crawler.crawl_users()
            return func.HttpResponse(
                json.dumps({
                    "status": "success",
                    "count": len(users)
                }),
                mimetype="application/json"
            )
        
        elif action == 'teams':
            teams = crawler.crawl_teams()
            return func.HttpResponse(
                json.dumps({
                    "status": "success",
                    "count": len(teams)
                }),
                mimetype="application/json"
            )
        
        elif action == 'sharepoint':
            sites = crawler.crawl_sharepoint_sites()
            return func.HttpResponse(
                json.dumps({
                    "status": "success",
                    "count": len(sites)
                }),
                mimetype="application/json"
            )
        
        elif action == 'status':
            # Get recent crawl status
            query = "SELECT * FROM c WHERE c.tenantId = @tenantId ORDER BY c.timestamp DESC OFFSET 0 LIMIT 10"
            parameters = [{"name": "@tenantId", "value": TENANT_ID}]
            
            recent_crawls = list(crawler.state_container.query_items(
                query=query,
                parameters=parameters,
                enable_cross_partition_query=True
            ))
            
            return func.HttpResponse(
                json.dumps({
                    "status": "success",
                    "recent_crawls": recent_crawls
                }),
                mimetype="application/json"
            )
        
        else:
            return func.HttpResponse(
                json.dumps({
                    "status": "error",
                    "message": f"Unknown action: {action}"
                }),
                status_code=400,
                mimetype="application/json"
            )
    
    except Exception as e:
        logging.error(f"Error in crawler: {str(e)}")
        return func.HttpResponse(
            json.dumps({
                "status": "error",
                "message": str(e)
            }),
            status_code=500,
            mimetype="application/json"
        )
EOF

# Create Queue Processor Function
mkdir -p QueueProcessor
cat > QueueProcessor/function.json << 'EOF'
{
  "scriptFile": "__init__.py",
  "bindings": [
    {
      "name": "msg",
      "type": "serviceBusTrigger",
      "direction": "in",
      "queueName": "crawl-queue",
      "connection": "SERVICE_BUS_CONNECTION"
    }
  ]
}
EOF

cat > QueueProcessor/__init__.py << 'EOF'
import logging
import json
import os
import azure.functions as func
from datetime import datetime
import requests
from msal import ConfidentialClientApplication
from azure.storage.blob import BlobServiceClient
from azure.cosmos import CosmosClient
from typing import Dict, Any

# Configuration
TENANT_ID = os.environ["TENANT_ID"]
CLIENT_ID = os.environ["CLIENT_ID"]
CLIENT_SECRET = os.environ["CLIENT_SECRET"]
STORAGE_CONNECTION = os.environ["STORAGE_CONNECTION"]
COSMOS_CONNECTION = os.environ["COSMOS_CONNECTION"]

# Initialize clients
blob_service = BlobServiceClient.from_connection_string(STORAGE_CONNECTION)
cosmos_client = CosmosClient.from_connection_string(COSMOS_CONNECTION)
database = cosmos_client.get_database_client("M365Data")
documents_container = database.get_container_client("Documents")

class GraphClient:
    """Microsoft Graph API client"""
    
    def __init__(self, tenant_id: str, client_id: str, client_secret: str):
        self.tenant_id = tenant_id
        self.authority = f"https://login.microsoftonline.com/{tenant_id}"
        self.scope = ["https://graph.microsoft.com/.default"]
        
        self.app = ConfidentialClientApplication(
            client_id,
            authority=self.authority,
            client_credential=client_secret
        )
    
    def get_token(self) -> str:
        """Get access token"""
        result = self.app.acquire_token_for_client(scopes=self.scope)
        if "access_token" in result:
            return result["access_token"]
        raise Exception(f"Failed to acquire token: {result.get('error_description')}")
    
    def download_file(self, url: str) -> bytes:
        """Download file content from Graph API"""
        headers = {"Authorization": f"Bearer {self.get_token()}"}
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.content
    
    def get_json(self, url: str) -> Dict:
        """Get JSON data from Graph API"""
        headers = {"Authorization": f"Bearer {self.get_token()}"}
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()

def process_onedrive(graph: GraphClient, message_data: Dict) -> None:
    """Process OneDrive files for a user"""
    user_id = message_data["userId"]
    tenant_id = message_data["tenantId"]
    
    logging.info(f"Processing OneDrive for user {user_id}")
    
    try:
        # Get user's drive
        drive_url = f"https://graph.microsoft.com/v1.0/users/{user_id}/drive"
        drive = graph.get_json(drive_url)
        
        # Get root items
        items_url = f"https://graph.microsoft.com/v1.0/users/{user_id}/drive/root/children"
        items = graph.get_json(items_url).get("value", [])
        
        for item in items:
            # Store metadata in Cosmos DB
            doc = {
                "id": item["id"],
                "tenantId": tenant_id,
                "userId": user_id,
                "name": item["name"],
                "entityType": "onedrive_file",
                "webUrl": item.get("webUrl"),
                "createdDateTime": item.get("createdDateTime"),
                "modifiedDateTime": item.get("lastModifiedDateTime"),
                "size": item.get("size"),
                "crawledAt": datetime.utcnow().isoformat()
            }
            
            documents_container.upsert_item(doc)
            
            # Download and store file content if it's a document
            if item.get("file") and item["size"] < 10485760:  # 10MB limit
                try:
                    content_url = f"https://graph.microsoft.com/v1.0/users/{user_id}/drive/items/{item['id']}/content"
                    content = graph.download_file(content_url)
                    
                    # Store in blob storage
                    blob_name = f"onedrive/{tenant_id}/{user_id}/{item['id']}"
                    blob_container = blob_service.get_container_client("documents")
                    blob_container.upload_blob(name=blob_name, data=content, overwrite=True)
                    
                    doc["blobPath"] = blob_name
                    documents_container.upsert_item(doc)
                    
                except Exception as e:
                    logging.warning(f"Failed to download file {item['id']}: {str(e)}")
        
        logging.info(f"Processed {len(items)} OneDrive items for user {user_id}")
        
    except Exception as e:
        logging.error(f"Error processing OneDrive for user {user_id}: {str(e)}")

def process_site_documents(graph: GraphClient, message_data: Dict) -> None:
    """Process SharePoint site documents"""
    site_id = message_data["siteId"]
    tenant_id = message_data["tenantId"]
    
    logging.info(f"Processing documents for site {site_id}")
    
    try:
        # Get document libraries
        lists_url = f"https://graph.microsoft.com/v1.0/sites/{site_id}/lists"
        lists = graph.get_json(lists_url).get("value", [])
        
        doc_libraries = [l for l in lists if l.get("list", {}).get("template") == "documentLibrary"]
        
        for library in doc_libraries:
            # Get items in library
            items_url = f"https://graph.microsoft.com/v1.0/sites/{site_id}/lists/{library['id']}/items?expand=driveItem"
            items = graph.get_json(items_url).get("value", [])
            
            for item in items:
                if item.get("driveItem"):
                    drive_item = item["driveItem"]
                    
                    # Store metadata
                    doc = {
                        "id": drive_item["id"],
                        "tenantId": tenant_id,
                        "siteId": site_id,
                        "libraryId": library["id"],
                        "name": drive_item.get("name"),
                        "entityType": "sharepoint_document",
                        "webUrl": drive_item.get("webUrl"),
                        "createdDateTime": drive_item.get("createdDateTime"),
                        "modifiedDateTime": drive_item.get("lastModifiedDateTime"),
                        "size": drive_item.get("size"),
                        "crawledAt": datetime.utcnow().isoformat()
                    }
                    
                    documents_container.upsert_item(doc)
        
        logging.info(f"Processed documents for site {site_id}")
        
    except Exception as e:
        logging.error(f"Error processing site documents for {site_id}: {str(e)}")

def process_channel_messages(graph: GraphClient, message_data: Dict) -> None:
    """Process Teams channel messages"""
    team_id = message_data["teamId"]
    channel_id = message_data["channelId"]
    tenant_id = message_data["tenantId"]
    
    logging.info(f"Processing messages for channel {channel_id} in team {team_id}")
    
    try:
        # Get channel messages
        messages_url = f"https://graph.microsoft.com/v1.0/teams/{team_id}/channels/{channel_id}/messages"
        messages = graph.get_json(messages_url).get("value", [])
        
        for message in messages:
            # Store message
            doc = {
                "id": message["id"],
                "tenantId": tenant_id,
                "teamId": team_id,
                "channelId": channel_id,
                "entityType": "teams_message",
                "from": message.get("from", {}).get("user", {}).get("displayName"),
                "createdDateTime": message.get("createdDateTime"),
                "body": message.get("body", {}).get("content"),
                "importance": message.get("importance"),
                "crawledAt": datetime.utcnow().isoformat()
            }
            
            documents_container.upsert_item(doc)
            
            # Process replies
            if message.get("replies@odata.count", 0) > 0:
                replies_url = f"{messages_url}/{message['id']}/replies"
                replies = graph.get_json(replies_url).get("value", [])
                
                for reply in replies:
                    reply_doc = {
                        "id": reply["id"],
                        "tenantId": tenant_id,
                        "teamId": team_id,
                        "channelId": channel_id,
                        "parentMessageId": message["id"],
                        "entityType": "teams_reply",
                        "from": reply.get("from", {}).get("user", {}).get("displayName"),
                        "createdDateTime": reply.get("createdDateTime"),
                        "body": reply.get("body", {}).get("content"),
                        "crawledAt": datetime.utcnow().isoformat()
                    }
                    
                    documents_container.upsert_item(reply_doc)
        
        logging.info(f"Processed {len(messages)} messages for channel {channel_id}")
        
    except Exception as e:
        logging.error(f"Error processing channel messages: {str(e)}")

def main(msg: func.ServiceBusMessage):
    logging.info('Processing Service Bus queue message')
    
    try:
        # Parse message
        message_data = json.loads(msg.get_body().decode('utf-8'))
        message_type = message_data.get("type")
        
        # Initialize Graph client
        graph = GraphClient(TENANT_ID, CLIENT_ID, CLIENT_SECRET)
        
        # Route to appropriate processor
        if message_type == "onedrive":
            process_onedrive(graph, message_data)
        elif message_type == "site_documents":
            process_site_documents(graph, message_data)
        elif message_type == "channel_messages":
            process_channel_messages(graph, message_data)
        else:
            logging.warning(f"Unknown message type: {message_type}")
    
    except Exception as e:
        logging.error(f"Error processing message: {str(e)}")
        raise
EOF

# Create Timer Trigger for scheduled crawls
mkdir -p ScheduledCrawler
cat > ScheduledCrawler/function.json << 'EOF'
{
  "scriptFile": "__init__.py",
  "bindings": [
    {
      "name": "timer",
      "type": "timerTrigger",
      "direction": "in",
      "schedule": "0 0 */6 * * *"
    }
  ]
}
EOF

cat > ScheduledCrawler/__init__.py << 'EOF'
import logging
import os
import azure.functions as func
import requests
from datetime import datetime

FUNCTION_APP_URL = f"https://{os.environ.get('WEBSITE_HOSTNAME', 'localhost')}"
FUNCTION_KEY = os.environ.get("FUNCTION_KEY", "")

def main(timer: func.TimerRequest) -> None:
    logging.info('Scheduled crawler triggered at %s', datetime.utcnow())
    
    if timer.past_due:
        logging.info('The timer is past due!')
    
    try:
        # Trigger full crawl
        url = f"{FUNCTION_APP_URL}/api/crawl/full"
        headers = {"x-functions-key": FUNCTION_KEY} if FUNCTION_KEY else {}
        
        response = requests.post(url, headers=headers)
        response.raise_for_status()
        
        logging.info(f"Crawl initiated successfully: {response.json()}")
        
    except Exception as e:
        logging.error(f"Failed to initiate scheduled crawl: {str(e)}")
EOF

# Create OpenAI Integration Function
mkdir -p OpenAIAssistant
cat > OpenAIAssistant/function.json << 'EOF'
{
  "scriptFile": "__init__.py",
  "bindings": [
    {
      "authLevel": "function",
      "type": "httpTrigger",
      "direction": "in",
      "name": "req",
      "methods": ["post"],
      "route": "assistant/{action}"
    },
    {
      "type": "http",
      "direction": "out",
      "name": "$return"
    }
  ]
}
EOF

cat > OpenAIAssistant/__init__.py << 'EOF'
import logging
import json
import os
import azure.functions as func
from openai import OpenAI
from azure.cosmos import CosmosClient
from typing import Dict, List, Any
import hashlib

# Configuration
OPENAI_API_KEY = os.environ["OPENAI_API_KEY"]
COSMOS_CONNECTION = os.environ["COSMOS_CONNECTION"]

# Initialize clients
openai_client = OpenAI(api_key=OPENAI_API_KEY)
cosmos_client = CosmosClient.from_connection_string(COSMOS_CONNECTION)
database = cosmos_client.get_database_client("M365Data")

class M365Assistant:
    """OpenAI Assistant for M365 data operations"""
    
    def __init__(self):
        self.client = openai_client
        self.assistant_id = self.get_or_create_assistant()
    
    def get_or_create_assistant(self) -> str:
        """Get existing or create new assistant"""
        # Check if assistant already exists (would need to store ID somewhere)
        # For now, create a new one
        
        assistant = self.client.beta.assistants.create(
            name="M365 Big Brain Assistant",
            instructions="""You are an intelligent assistant for Microsoft 365 data operations.
            You can search, analyze, and provide insights on SharePoint documents, OneDrive files,
            Teams messages, users, and groups. You can also help with eDiscovery, compliance monitoring,
            and knowledge management tasks. Always provide accurate, relevant responses based on the
            actual data available in the system.""",
            model="gpt-4-turbo-preview",
            tools=[
                {
                    "type": "function",
                    "function": {
                        "name": "search_documents",
                        "description": "Search for documents across SharePoint and OneDrive",
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "query": {"type": "string", "description": "Search query"},
                                "entity_type": {"type": "string", "description": "Type of entity to search"},
                                "limit": {"type": "integer", "description": "Maximum results"}
                            },
                            "required": ["query"]
                        }
                    }
                },
                {
                    "type": "function",
                    "function": {
                        "name": "search_messages",
                        "description": "Search Teams messages and conversations",
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "query": {"type": "string", "description": "Search query"},
                                "team_id": {"type": "string", "description": "Optional team ID"},
                                "limit": {"type": "integer", "description": "Maximum results"}
                            },
                            "required": ["query"]
                        }
                    }
                },
                {
                    "type": "function",
                    "function": {
                        "name": "get_user_info",
                        "description": "Get information about a user",
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "user_email": {"type": "string", "description": "User email or UPN"}
                            },
                            "required": ["user_email"]
                        }
                    }
                },
                {
                    "type": "function",
                    "function": {
                        "name": "analyze_compliance",
                        "description": "Analyze data for compliance issues",
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "policy_type": {"type": "string", "description": "Type of compliance policy"},
                                "date_range": {"type": "string", "description": "Date range for analysis"}
                            },
                            "required": ["policy_type"]
                        }
                    }
                }
            ]
        )
        
        return assistant.id
    
    def search_documents(self, query: str, entity_type: str = None, limit: int = 10) -> List[Dict]:
        """Search documents in Cosmos DB"""
        container = database.get_container_client("Documents")
        
        # Simple text search (in production, use Azure Cognitive Search)
        cosmos_query = f"SELECT TOP {limit} * FROM c WHERE CONTAINS(LOWER(c.name), LOWER(@query))"
        if entity_type:
            cosmos_query += " AND c.entityType = @entity_type"
        
        parameters = [{"name": "@query", "value": query}]
        if entity_type:
            parameters.append({"name": "@entity_type", "value": entity_type})
        
        results = list(container.query_items(
            query=cosmos_query,
            parameters=parameters,
            enable_cross_partition_query=True
        ))
        
        return results
    
    def search_messages(self, query: str, team_id: str = None, limit: int = 10) -> List[Dict]:
        """Search Teams messages"""
        container = database.get_container_client("Documents")
        
        cosmos_query = f"""SELECT TOP {limit} * FROM c 
                          WHERE c.entityType IN ('teams_message', 'teams_reply')
                          AND CONTAINS(LOWER(c.body), LOWER(@query))"""
        
        if team_id:
            cosmos_query += " AND c.teamId = @team_id"
        
        parameters = [{"name": "@query", "value": query}]
        if team_id:
            parameters.append({"name": "@team_id", "value": team_id})
        
        results = list(container.query_items(
            query=cosmos_query,
            parameters=parameters,
            enable_cross_partition_query=True
        ))
        
        return results
    
    def get_user_info(self, user_email: str) -> Dict:
        """Get user information"""
        container = database.get_container_client("Users")
        
        query = "SELECT * FROM c WHERE c.mail = @email OR c.userPrincipalName = @email"
        parameters = [{"name": "@email", "value": user_email}]
        
        results = list(container.query_items(
            query=query,
            parameters=parameters,
            enable_cross_partition_query=True
        ))
        
        return results[0] if results else None
    
    def process_message(self, user_message: str, thread_id: str = None) -> str:
        """Process user message with assistant"""
        # Create or retrieve thread
        if not thread_id:
            thread = self.client.beta.threads.create()
            thread_id = thread.id
        
        # Add message to thread
        self.client.beta.threads.messages.create(
            thread_id=thread_id,
            role="user",
            content=user_message
        )
        
        # Run assistant
        run = self.client.beta.threads.runs.create(
            thread_id=thread_id,
            assistant_id=self.assistant_id
        )
        
        # Wait for completion and handle function calls
        while run.status in ["queued", "in_progress", "requires_action"]:
            run = self.client.beta.threads.runs.retrieve(
                thread_id=thread_id,
                run_id=run.id
            )
            
            if run.status == "requires_action":
                # Handle function calls
                tool_calls = run.required_action.submit_tool_outputs.tool_calls
                tool_outputs = []
                
                for tool_call in tool_calls:
                    function_name = tool_call.function.name
                    arguments = json.loads(tool_call.function.arguments)
                    
                    # Execute function
                    if function_name == "search_documents":
                        result = self.search_documents(**arguments)
                    elif function_name == "search_messages":
                        result = self.search_messages(**arguments)
                    elif function_name == "get_user_info":
                        result = self.get_user_info(**arguments)
                    else:
                        result = {"error": f"Unknown function: {function_name}"}
                    
                    tool_outputs.append({
                        "tool_call_id": tool_call.id,
                        "output": json.dumps(result)
                    })
                
                # Submit outputs
                run = self.client.beta.threads.runs.submit_tool_outputs(
                    thread_id=thread_id,
                    run_id=run.id,
                    tool_outputs=tool_outputs
                )
        
        # Get response
        messages = self.client.beta.threads.messages.list(thread_id=thread_id)
        return messages.data[0].content[0].text.value, thread_id

def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('OpenAI Assistant endpoint called')
    
    try:
        action = req.route_params.get('action')
        req_body = req.get_json()
        
        assistant = M365Assistant()
        
        if action == 'chat':
            message = req_body.get('message')
            thread_id = req_body.get('thread_id')
            
            if not message:
                return func.HttpResponse(
                    json.dumps({"error": "Message is required"}),
                    status_code=400,
                    mimetype="application/json"
                )
            
            response, thread_id = assistant.process_message(message, thread_id)
            
            return func.HttpResponse(
                json.dumps({
                    "response": response,
                    "thread_id": thread_id
                }),
                mimetype="application/json"
            )
        
        elif action == 'search':
            query = req_body.get('query')
            search_type = req_body.get('type', 'documents')
            
            if search_type == 'documents':
                results = assistant.search_documents(query)
            elif search_type == 'messages':
                results = assistant.search_messages(query)
            else:
                results = []
            
            return func.HttpResponse(
                json.dumps({
                    "results": results,
                    "count": len(results)
                }),
                mimetype="application/json"
            )
        
        else:
            return func.HttpResponse(
                json.dumps({"error": f"Unknown action: {action}"}),
                status_code=400,
                mimetype="application/json"
            )
    
    except Exception as e:
        logging.error(f"Error in OpenAI Assistant: {str(e)}")
        return func.HttpResponse(
            json.dumps({"error": str(e)}),
            status_code=500,
            mimetype="application/json"
        )
EOF

# Create Search API Function
mkdir -p SearchAPI
cat > SearchAPI/function.json << 'EOF'
{
  "scriptFile": "__init__.py",
  "bindings": [
    {
      "authLevel": "function",
      "type": "httpTrigger",
      "direction": "in",
      "name": "req",
      "methods": ["get", "post"],
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

cat > SearchAPI/__init__.py << 'EOF'
import logging
import json
import os
import azure.functions as func
from azure.cosmos import CosmosClient
from typing import Dict, List, Any
from datetime import datetime, timedelta

COSMOS_CONNECTION = os.environ["COSMOS_CONNECTION"]

cosmos_client = CosmosClient.from_connection_string(COSMOS_CONNECTION)
database = cosmos_client.get_database_client("M365Data")

def search_all(query: str, filters: Dict = None, limit: int = 50) -> Dict:
    """Search across all data types"""
    results = {
        "documents": [],
        "messages": [],
        "users": [],
        "teams": []
    }
    
    # Search documents
    doc_container = database.get_container_client("Documents")
    doc_query = f"SELECT TOP {limit} * FROM c WHERE CONTAINS(LOWER(c.name), LOWER(@query))"
    
    if filters and filters.get("entity_type"):
        doc_query += " AND c.entityType = @entity_type"
    
    if filters and filters.get("date_from"):
        doc_query += " AND c.modifiedDateTime >= @date_from"
    
    parameters = [{"name": "@query", "value": query}]
    if filters:
        if filters.get("entity_type"):
            parameters.append({"name": "@entity_type", "value": filters["entity_type"]})
        if filters.get("date_from"):
            parameters.append({"name": "@date_from", "value": filters["date_from"]})
    
    results["documents"] = list(doc_container.query_items(
        query=doc_query,
        parameters=parameters,
        enable_cross_partition_query=True
    ))
    
    # Search messages
    msg_query = f"""SELECT TOP {limit} * FROM c 
                    WHERE c.entityType IN ('teams_message', 'teams_reply')
                    AND CONTAINS(LOWER(c.body), LOWER(@query))"""
    
    results["messages"] = list(doc_container.query_items(
        query=msg_query,
        parameters=[{"name": "@query", "value": query}],
        enable_cross_partition_query=True
    ))
    
    # Search users
    user_container = database.get_container_client("Users")
    user_query = f"""SELECT TOP {limit} * FROM c 
                     WHERE CONTAINS(LOWER(c.displayName), LOWER(@query))
                     OR CONTAINS(LOWER(c.mail), LOWER(@query))"""
    
    results["users"] = list(user_container.query_items(
        query=user_query,
        parameters=[{"name": "@query", "value": query}],
        enable_cross_partition_query=True
    ))
    
    # Search teams
    teams_container = database.get_container_client("Teams")
    teams_query = f"""SELECT TOP {limit} * FROM c 
                      WHERE CONTAINS(LOWER(c.displayName), LOWER(@query))
                      OR CONTAINS(LOWER(c.description), LOWER(@query))"""
    
    results["teams"] = list(teams_container.query_items(
        query=teams_query,
        parameters=[{"name": "@query", "value": query}],
        enable_cross_partition_query=True
    ))
    
    return results

def get_analytics() -> Dict:
    """Get system analytics"""
    analytics = {}
    
    # Get document counts by type
    doc_container = database.get_container_client("Documents")
    count_query = "SELECT c.entityType, COUNT(1) as count FROM c GROUP BY c.entityType"
    
    doc_counts = list(doc_container.query_items(
        query=count_query,
        enable_cross_partition_query=True
    ))
    
    analytics["document_counts"] = {item["entityType"]: item["count"] for item in doc_counts}
    
    # Get user count
    user_container = database.get_container_client("Users")
    user_count = list(user_container.query_items(
        query="SELECT VALUE COUNT(1) FROM c",
        enable_cross_partition_query=True
    ))[0]
    
    analytics["total_users"] = user_count
    
    # Get teams count
    teams_container = database.get_container_client("Teams")
    teams_count = list(teams_container.query_items(
        query="SELECT VALUE COUNT(1) FROM c WHERE c.entityType = 'team'",
        enable_cross_partition_query=True
    ))[0]
    
    analytics["total_teams"] = teams_count
    
    # Get recent crawl status
    state_container = database.get_container_client("CrawlState")
    recent_crawls = list(state_container.query_items(
        query="SELECT TOP 5 * FROM c ORDER BY c.timestamp DESC",
        enable_cross_partition_query=True
    ))
    
    analytics["recent_crawls"] = recent_crawls
    
    return analytics

def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Search API endpoint called')
    
    try:
        # Get search parameters
        query = req.params.get('q') or req.get_json().get('query') if req.get_body() else None
        search_type = req.params.get('type') or req.get_json().get('type') if req.get_body() else 'all'
        
        if search_type == 'analytics':
            # Return analytics
            analytics = get_analytics()
            return func.HttpResponse(
                json.dumps(analytics),
                mimetype="application/json"
            )
        
        if not query:
            return func.HttpResponse(
                json.dumps({"error": "Query parameter 'q' is required"}),
                status_code=400,
                mimetype="application/json"
            )
        
        # Parse filters
        filters = {}
        if req.params.get('entity_type'):
            filters['entity_type'] = req.params.get('entity_type')
        if req.params.get('date_from'):
            filters['date_from'] = req.params.get('date_from')
        
        # Perform search
        results = search_all(query, filters)
        
        # Calculate total results
        total = sum(len(v) for v in results.values())
        
        response = {
            "query": query,
            "total_results": total,
            "results": results,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        return func.HttpResponse(
            json.dumps(response),
            mimetype="application/json"
        )
    
    except Exception as e:
        logging.error(f"Error in search: {str(e)}")
        return func.HttpResponse(
            json.dumps({"error": str(e)}),
            status_code=500,
            mimetype="application/json"
        )
EOF

# Create local.settings.json for local development
cat > local.settings.json << EOF
{
  "IsEncrypted": false,
  "Values": {
    "AzureWebJobsStorage": "$STORAGE_CONNECTION",
    "FUNCTIONS_WORKER_RUNTIME": "python",
    "TENANT_ID": "$TENANT_ID",
    "CLIENT_ID": "$APP_ID",
    "CLIENT_SECRET": "$CLIENT_SECRET",
    "OPENAI_API_KEY": "$OPENAI_API_KEY",
    "OPENAI_ENDPOINT": "$OPENAI_ENDPOINT",
    "OPENAI_MODEL": "$OPENAI_MODEL",
    "STORAGE_CONNECTION": "$STORAGE_CONNECTION",
    "COSMOS_CONNECTION": "$COSMOS_CONNECTION",
    "SERVICE_BUS_CONNECTION": "$SERVICE_BUS_CONNECTION",
    "KEY_VAULT_NAME": "$KEY_VAULT"
  }
}
EOF

# Create deployment package
print_status "Creating deployment package..."
zip -r functionapp.zip . -x "*.git*" > /dev/null

# Deploy to Azure
print_status "Deploying to Azure Functions..."
az functionapp deployment source config-zip \
    --resource-group $RESOURCE_GROUP \
    --name $FUNCTION_APP \
    --src functionapp.zip \
    --output none

# Get function keys
FUNCTION_KEY=$(az functionapp function keys list \
    --name $FUNCTION_APP \
    --resource-group $RESOURCE_GROUP \
    --function-name CrawlTrigger \
    --query default -o tsv 2>/dev/null || echo "")

# Store function key in Key Vault
if [ ! -z "$FUNCTION_KEY" ]; then
    az keyvault secret set --vault-name $KEY_VAULT --name "FunctionKey" --value "$FUNCTION_KEY" --output none
fi

# Clean up temp directory
cd /
rm -rf $TEMP_DIR

print_success "Function App deployed successfully"

#############################################################################
# CREATE WEBHOOK SUBSCRIPTIONS
#############################################################################

print_status "Setting up Graph webhooks..."

# This would need to be done after the function app is running
# Creating a helper script for webhook setup
cat > setup-webhooks.sh << 'WEBHOOK_SCRIPT'
#!/bin/bash

# Function to create webhook subscription
create_subscription() {
    local RESOURCE=$1
    local CHANGE_TYPE=$2
    local NOTIFICATION_URL=$3
    
    curl -X POST https://graph.microsoft.com/v1.0/subscriptions \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d "{
            \"changeType\": \"$CHANGE_TYPE\",
            \"notificationUrl\": \"$NOTIFICATION_URL\",
            \"resource\": \"$RESOURCE\",
            \"expirationDateTime\": \"$(date -u -d '+30 days' '+%Y-%m-%dT%H:%M:%S.0000000Z')\",
            \"clientState\": \"SecretClientState\"
        }"
}

echo "Webhook setup script created. Run this after function app is deployed and accessible."
WEBHOOK_SCRIPT

chmod +x setup-webhooks.sh

#############################################################################
# OUTPUT DEPLOYMENT INFORMATION
#############################################################################

print_success "Deployment completed successfully!"

echo ""
echo "═══════════════════════════════════════════════════════════════════════"
echo "                    M365 BIG BRAIN CRAWL DEPLOYMENT SUMMARY"
echo "═══════════════════════════════════════════════════════════════════════"
echo ""
echo "Resource Group:        $RESOURCE_GROUP"
echo "Function App:          $FUNCTION_APP"
echo "Storage Account:       $STORAGE_ACCOUNT"
echo "Cosmos DB:            $COSMOS_ACCOUNT"
echo "Service Bus:          $SERVICE_BUS"
echo "Key Vault:            $KEY_VAULT"
echo "Application Insights:  $APP_INSIGHTS"
echo ""
echo "App Registration ID:   $APP_ID"
echo "Tenant ID:            $TENANT_ID"
echo ""
echo "Function App URL:      https://${FUNCTION_APP}.azurewebsites.net"
echo ""
echo "═══════════════════════════════════════════════════════════════════════"
echo "                              API ENDPOINTS"
echo "═══════════════════════════════════════════════════════════════════════"
echo ""
echo "Crawl Operations:"
echo "  Full Crawl:     POST https://${FUNCTION_APP}.azurewebsites.net/api/crawl/full"
echo "  Users:          POST https://${FUNCTION_APP}.azurewebsites.net/api/crawl/users"
echo "  Teams:          POST https://${FUNCTION_APP}.azurewebsites.net/api/crawl/teams"
echo "  SharePoint:     POST https://${FUNCTION_APP}.azurewebsites.net/api/crawl/sharepoint"
echo "  Status:         GET  https://${FUNCTION_APP}.azurewebsites.net/api/crawl/status"
echo ""
echo "Search & Analytics:"
echo "  Search:         GET  https://${FUNCTION_APP}.azurewebsites.net/api/search?q=<query>"
echo "  Analytics:      GET  https://${FUNCTION_APP}.azurewebsites.net/api/search?type=analytics"
echo ""
echo "OpenAI Assistant:"
echo "  Chat:           POST https://${FUNCTION_APP}.azurewebsites.net/api/assistant/chat"
echo "  Search:         POST https://${FUNCTION_APP}.azurewebsites.net/api/assistant/search"
echo ""
if [ ! -z "$FUNCTION_KEY" ]; then
    echo "Function Key:     $FUNCTION_KEY"
    echo ""
    echo "Include in requests as header: x-functions-key: $FUNCTION_KEY"
else
    echo "Note: Function keys will be available after initial deployment completes."
fi
echo ""
echo "═══════════════════════════════════════════════════════════════════════"
echo "                            NEXT STEPS"
echo "═══════════════════════════════════════════════════════════════════════"
echo ""
echo "1. Grant admin consent for Graph API permissions:"
echo "   https://portal.azure.com/#blade/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/CallAnAPI/appId/${APP_ID}"
echo ""
echo "2. Test the deployment:"
echo "   curl -X POST https://${FUNCTION_APP}.azurewebsites.net/api/crawl/status \\"
echo "        -H 'x-functions-key: <function-key>'"
echo ""
echo "3. Initiate first crawl:"
echo "   curl -X POST https://${FUNCTION_APP}.azurewebsites.net/api/crawl/full \\"
echo "        -H 'x-functions-key: <function-key>'"
echo ""
echo "4. Test OpenAI Assistant:"
echo "   curl -X POST https://${FUNCTION_APP}.azurewebsites.net/api/assistant/chat \\"
echo "        -H 'Content-Type: application/json' \\"
echo "        -H 'x-functions-key: <function-key>' \\"
echo "        -d '{\"message\": \"Show me recent Teams messages about projects\"}'"
echo ""
echo "5. Monitor in Azure Portal:"
echo "   https://portal.azure.com/#@${TENANT_ID}/resource/subscriptions/${SUBSCRIPTION_ID}/resourceGroups/${RESOURCE_GROUP}/overview"
echo ""
echo "═══════════════════════════════════════════════════════════════════════"

# Save deployment info to file
cat > deployment-info.json << EOF
{
  "deployment_id": "$DEPLOYMENT_ID",
  "timestamp": "$(date -u '+%Y-%m-%dT%H:%M:%S.000Z')",
  "subscription_id": "$SUBSCRIPTION_ID",
  "resource_group": "$RESOURCE_GROUP",
  "location": "$LOCATION",
  "services": {
    "function_app": "$FUNCTION_APP",
    "storage_account": "$STORAGE_ACCOUNT",
    "cosmos_db": "$COSMOS_ACCOUNT",
    "service_bus": "$SERVICE_BUS",
    "key_vault": "$KEY_VAULT",
    "app_insights": "$APP_INSIGHTS"
  },
  "app_registration": {
    "app_id": "$APP_ID",
    "tenant_id": "$TENANT_ID"
  },
  "endpoints": {
    "base_url": "https://${FUNCTION_APP}.azurewebsites.net",
    "crawl_full": "https://${FUNCTION_APP}.azurewebsites.net/api/crawl/full",
    "crawl_status": "https://${FUNCTION_APP}.azurewebsites.net/api/crawl/status",
    "search": "https://${FUNCTION_APP}.azurewebsites.net/api/search",
    "assistant": "https://${FUNCTION_APP}.azurewebsites.net/api/assistant/chat"
  }
}
EOF

print_success "Deployment information saved to deployment-info.json"
print_success "Setup complete! Your M365 Big Brain Crawl system is ready."