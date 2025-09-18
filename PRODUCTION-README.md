# M365 Big Brain Crawl - Production Implementation Guide

## Complete Multi-Tenant Microsoft 365 Data Crawler with Dual-Mode Authentication

### Overview

M365 Big Brain Crawl is a production-ready, enterprise-grade Microsoft 365 data crawler that provides comprehensive data synchronization, intelligent processing, and natural language interaction capabilities. This implementation supports both user-delegated and tenant-wide access modes, making it suitable for various deployment scenarios.

### Key Features

#### Dual Authentication Modes

1. **Mode A: User-Connected (Delegated Permissions)**
   - No admin consent required (where policy allows)
   - OAuth 2.0 Authorization Code Flow with PKCE
   - Per-user data access
   - Suitable for individual users or small teams

2. **Mode B: Tenant-Connected (Application Permissions)**
   - Admin consent required
   - Sites.Selected for granular SharePoint access
   - Organization-wide data access
   - Suitable for enterprise deployments

#### Core Capabilities

- **Delta Synchronization**: Seed once, then delta forever for efficient updates
- **Webhook Subscriptions**: Real-time change notifications with encrypted payloads
- **Queue-Based Processing**: Scalable architecture using Azure Service Bus
- **Multi-Tenant Isolation**: Complete data partitioning per tenant/user
- **OpenAI Integration**: Natural language interface for data interaction
- **Comprehensive Search**: Full-text search across all M365 data types
- **Security First**: Azure Key Vault integration, managed identities, certificate-based auth

### Architecture

```
┌────────────────────────────────────────────────────────────────────┐
│                        Microsoft 365 Tenant                         │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐│
│  │SharePoint│ │ OneDrive │ │  Teams   │ │  Users   │ │  Groups  ││
│  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘│
└───────┼────────────┼────────────┼────────────┼────────────┼───────┘
        │            │            │            │            │
        └────────────┴────────────┴────────────┴────────────┘
                              │
                    ┌─────────┴──────────┐
                    │   Graph API v1.0    │
                    │  ┌──────────────┐  │
                    │  │ Delta Queries│  │
                    │  └──────────────┘  │
                    │  ┌──────────────┐  │
                    │  │   Webhooks   │  │
                    │  └──────────────┘  │
                    └─────────┬──────────┘
                              │
        ┌─────────────────────┴─────────────────────┐
        │          Azure Functions App               │
        │  ┌────────────────────────────────────┐   │
        │  │     Authentication Layer           │   │
        │  │  ┌──────────┐  ┌──────────────┐  │   │
        │  │  │  Mode A  │  │    Mode B     │  │   │
        │  │  │   User   │  │    Tenant     │  │   │
        │  │  │   PKCE   │  │  Sites.Sel    │  │   │
        │  │  └──────────┘  └──────────────┘  │   │
        │  └────────────────────────────────────┘   │
        │                                            │
        │  ┌────────────────────────────────────┐   │
        │  │      Processing Functions          │   │
        │  │  ┌──────────┐  ┌──────────────┐  │   │
        │  │  │  Crawl   │  │    Queue     │  │   │
        │  │  │ Trigger  │  │  Processor   │  │   │
        │  │  └──────────┘  └──────────────┘  │   │
        │  │  ┌──────────┐  ┌──────────────┐  │   │
        │  │  │ Webhook  │  │  Scheduled   │  │   │
        │  │  │ Handler  │  │   Crawler    │  │   │
        │  │  └──────────┘  └──────────────┘  │   │
        │  └────────────────────────────────────┘   │
        │                                            │
        │  ┌────────────────────────────────────┐   │
        │  │         API Functions              │   │
        │  │  ┌──────────┐  ┌──────────────┐  │   │
        │  │  │  Search  │  │   OpenAI     │  │   │
        │  │  │   API    │  │  Assistant   │  │   │
        │  │  └──────────┘  └──────────────┘  │   │
        │  └────────────────────────────────────┘   │
        └────────────────────────────────────────────┘
                              │
        ┌─────────────────────┴─────────────────────┐
        │            Data & Queue Layer              │
        │  ┌──────────┐  ┌──────────────────────┐  │
        │  │ Cosmos DB│  │   Service Bus        │  │
        │  │Partitioned│ │  ┌──────────────┐   │  │
        │  │by Tenant │  │  │ crawl-queue  │   │  │
        │  └──────────┘  │  ├──────────────┤   │  │
        │                │  │webhook-queue │   │  │
        │  ┌──────────┐  │  ├──────────────┤   │  │
        │  │Key Vault │  │  │ delta-queue  │   │  │
        │  └──────────┘  │  └──────────────┘   │  │
        │                └──────────────────────┘  │
        │  ┌────────────────────────────────────┐  │
        │  │      Blob Storage                  │  │
        │  │  ┌──────────┐  ┌──────────────┐  │  │
        │  │  │Documents │  │ Delta Tokens │  │  │
        │  │  └──────────┘  └──────────────┘  │  │
        │  └────────────────────────────────────┘  │
        └────────────────────────────────────────────┘
```

### Deployment Guide

#### Prerequisites

1. **Azure Subscription** with appropriate permissions
2. **Azure AD Tenant ID**
3. **OpenAI API Key**
4. **Azure Cloud Shell** or Azure CLI installed locally
5. **Python 3.11+** (for local development)
6. **Podman** (optional, for containerized deployment)

#### Quick Deployment

```bash
# 1. Clone or download the deployment script
curl -O https://raw.githubusercontent.com/your-repo/M365Crawl/main/m365-brain-production.sh

# 2. Make it executable
chmod +x m365-brain-production.sh

# 3. Run the deployment
./m365-brain-production.sh
```

The script will:
- Check prerequisites and install missing components
- Collect deployment parameters
- Create Azure resources (Resource Group, Storage, Cosmos DB, Service Bus, Key Vault)
- Configure app registration with proper permissions
- Deploy Function App with all endpoints
- Display connection URLs and next steps

#### Manual Deployment Steps

##### 1. Create App Registration

```bash
# Create app with redirect URI
az ad app create \
    --display-name "M365BrainCrawl" \
    --sign-in-audience AzureADMyOrg \
    --web-redirect-uris "https://YOUR-FUNCTION-APP.azurewebsites.net/api/auth/callback"

# Note the Application ID
APP_ID=$(az ad app list --display-name "M365BrainCrawl" --query "[0].appId" -o tsv)

# Create service principal
az ad sp create --id $APP_ID

# Create client secret
CLIENT_SECRET=$(az ad app credential reset --id $APP_ID --years 2 --query password -o tsv)
```

##### 2. Configure Permissions

For Mode A (Delegated):
```bash
# Add delegated permissions
az ad app permission add --id $APP_ID \
    --api 00000003-0000-0000-c000-000000000000 \
    --api-permissions \
    e1fe6dd8-ba31-4d61-89e7-88639da4683d=Scope \  # User.Read
    01d4889c-1287-42c6-ac1f-5d1e02578ef6=Scope \  # Files.Read.All
    205e70e5-aba6-4c52-a976-6d2d46c48043=Scope \  # Sites.Read.All
    5f8c59db-677d-491f-a6b8-5f174b11ec1d=Scope \  # Group.Read.All
    660b7406-55f1-41ca-a0ed-0b035e182f3e=Scope \  # Team.ReadBasic.All
    9d8982ae-4365-4f57-95e9-d6032a4c0b87=Scope \  # Channel.ReadBasic.All
    f501c180-9344-439a-bca0-6cbf209fd270=Scope    # Chat.Read
```

For Mode B (Application):
```bash
# Add application permissions
az ad app permission add --id $APP_ID \
    --api 00000003-0000-0000-c000-000000000000 \
    --api-permissions \
    883ea226-0bf2-4a8f-9f9d-92c9162a727d=Role \  # Sites.Selected
    df021288-bdef-4463-88db-98f22de89214=Role \  # User.Read.All
    5f8c59db-677d-491f-a6b8-5f174b11ec1d=Role    # Group.Read.All

# Grant admin consent
az ad app permission admin-consent --id $APP_ID
```

##### 3. Create Azure Resources

```bash
# Resource Group
az group create --name m365-brain-rg --location eastus

# Storage Account
az storage account create \
    --name m365brainstorage \
    --resource-group m365-brain-rg \
    --location eastus \
    --sku Standard_LRS

# Cosmos DB
az cosmosdb create \
    --name m365brain-cosmos \
    --resource-group m365-brain-rg \
    --locations eastus=0

# Create database and containers
az cosmosdb sql database create \
    --account-name m365brain-cosmos \
    --resource-group m365-brain-rg \
    --name M365Data

for container in documents users teams crawlstate webhooks; do
    az cosmosdb sql container create \
        --account-name m365brain-cosmos \
        --resource-group m365-brain-rg \
        --database-name M365Data \
        --name $container \
        --partition-key-path /tenantId \
        --throughput 400
done

# Service Bus
az servicebus namespace create \
    --name m365brain-sb \
    --resource-group m365-brain-rg \
    --location eastus \
    --sku Standard

# Create queues
for queue in crawl-queue webhook-queue delta-queue; do
    az servicebus queue create \
        --name $queue \
        --namespace-name m365brain-sb \
        --resource-group m365-brain-rg
done

# Key Vault
az keyvault create \
    --name m365brainvault \
    --resource-group m365-brain-rg \
    --location eastus
```

##### 4. Deploy Function App

```bash
# Create Function App
az functionapp create \
    --name m365crawl7277 \
    --resource-group m365-brain-rg \
    --consumption-plan-location eastus \
    --runtime python \
    --runtime-version 3.11 \
    --functions-version 4 \
    --storage-account m365brainstorage

# Deploy code
func azure functionapp publish m365crawl7277 --python
```

### Configuration

#### Environment Variables

Configure these in your Function App settings:

| Variable | Description | Required |
|----------|-------------|----------|
| `TENANT_ID` | Azure AD Tenant ID | Yes |
| `CLIENT_ID` | App Registration Client ID | Yes |
| `CLIENT_SECRET` | App Registration Secret (use Key Vault reference) | Yes |
| `REDIRECT_URI` | OAuth callback URL (must match exactly) | Yes |
| `OPENAI_API_KEY` | OpenAI API Key (use Key Vault reference) | Yes |
| `STORAGE_CONNECTION` | Azure Storage connection string | Yes |
| `COSMOS_CONNECTION` | Cosmos DB connection string | Yes |
| `SERVICEBUS_CONNECTION` | Service Bus connection string | Yes |
| `KEY_VAULT_NAME` | Key Vault name for secrets | Yes |
| `APPINSIGHTS_INSTRUMENTATIONKEY` | Application Insights key | Yes |
| `DEPLOYMENT_MODE` | USER, TENANT, or BOTH | Yes |

#### Permission Profiles

##### Mode A: User-Connected Permissions
- `openid` - OpenID Connect authentication
- `profile` - User profile access
- `offline_access` - Refresh token support
- `User.Read` - Read user profile
- `Files.Read.All` - Read all files user can access
- `Sites.Read.All` - Read all SharePoint sites
- `Group.Read.All` - Read all groups
- `Team.ReadBasic.All` - Read Teams basic info
- `Channel.ReadBasic.All` - Read channels basic info
- `Chat.Read` - Read user's chat messages

##### Mode B: Tenant-Connected Permissions
- `Sites.Selected` - Granular SharePoint site access (preferred)
- `User.Read.All` - Read all users
- `Group.Read.All` - Read all groups
- `Files.Read.All` - Read all files (if Sites.Selected not sufficient)

### API Endpoints

#### Authentication

##### Get Authentication URL
```bash
# Mode A: User authentication
GET /api/auth/url?mode=user

# Mode B: Admin consent
GET /api/auth/url?mode=admin
```

##### OAuth Callback
```bash
# Handles both modes
GET /api/auth/callback?code=AUTH_CODE&state=STATE
```

##### Logout
```bash
POST /api/auth/logout
```

#### Crawl Operations

##### Full Crawl
```bash
POST /api/crawl/full
Content-Type: application/json
x-functions-key: YOUR_KEY

{
    "resources": ["users", "sites", "teams", "drives"],
    "tenant_id": "optional-tenant-id",
    "user_id": "optional-user-id"
}
```

##### Delta Crawl
```bash
POST /api/crawl/delta
Content-Type: application/json
x-functions-key: YOUR_KEY

{
    "resources": ["all"],
    "tenant_id": "optional-tenant-id"
}
```

##### Crawl Status
```bash
GET /api/crawl/status
x-functions-key: YOUR_KEY
```

#### Search

##### Universal Search
```bash
GET /api/search?q=project%20plan&limit=50
x-functions-key: YOUR_KEY
```

##### Filtered Search
```bash
GET /api/search?q=budget&entity_type=documents&tenant_id=TENANT_ID
x-functions-key: YOUR_KEY
```

#### Webhook

##### Webhook Endpoint
```bash
POST /api/webhook

# Validation request
{
    "validationToken": "TOKEN_TO_ECHO"
}

# Change notification
{
    "value": [{
        "clientState": "CLIENT_STATE",
        "resource": "/users/USER_ID",
        "changeType": "updated",
        "encryptedContent": {
            "data": "ENCRYPTED_DATA",
            "dataKey": "ENCRYPTED_KEY"
        }
    }]
}
```

#### OpenAI Assistant

##### Chat with Assistant
```bash
POST /api/assistant/chat
Content-Type: application/json
x-functions-key: YOUR_KEY

{
    "message": "Find all documents related to Q4 planning",
    "thread_id": "optional-thread-id"
}
```

### Security Best Practices

#### 1. Secrets Management
- Store all secrets in Azure Key Vault
- Use managed identities for Key Vault access
- Rotate secrets regularly
- Never commit secrets to source control

#### 2. Network Security
- Enable VNet integration for Function App
- Use private endpoints for Cosmos DB and Storage
- Implement IP restrictions where appropriate
- Enable HTTPS only

#### 3. Data Protection
- Enable encryption at rest for all storage
- Use TLS 1.2+ for all communications
- Implement proper data retention policies
- Regular security audits

#### 4. Access Control
- Use least-privilege permissions
- Implement conditional access policies
- Regular access reviews
- Multi-factor authentication for admins

### Monitoring and Troubleshooting

#### Application Insights Queries

##### Check crawl performance
```kusto
traces
| where message contains "crawl"
| summarize count() by bin(timestamp, 5m)
| render timechart
```

##### Monitor API response times
```kusto
requests
| where name contains "api"
| summarize avg(duration), percentile(duration, 95) by name
| order by avg_duration desc
```

##### Track errors
```kusto
exceptions
| where timestamp > ago(1h)
| summarize count() by problemId, outerMessage
| order by count_ desc
```

#### Common Issues and Solutions

##### 1. Authentication Failures

**Issue**: "AADSTS50011: The reply URL specified in the request does not match"

**Solution**: Ensure redirect URI matches exactly:
```bash
# Check app registration
az ad app show --id $APP_ID --query "web.redirectUris"

# Update if needed
az ad app update --id $APP_ID \
    --web-redirect-uris "https://YOUR-EXACT-URL.azurewebsites.net/api/auth/callback"
```

##### 2. Throttling (429 Errors)

**Issue**: "429 Too Many Requests"

**Solution**: The system implements automatic retry with exponential backoff. To adjust:
```python
# In QueueProcessor function
MAX_RETRIES = 5
BASE_DELAY = 2  # seconds
MAX_DELAY = 300  # 5 minutes
```

##### 3. Delta Token Expiration

**Issue**: "Delta token is expired"

**Solution**: System automatically falls back to full sync:
```python
if "token is expired" in error_message:
    # Clear delta token
    delta_manager.clear_token(tenant_id, resource_type)
    # Retry with full sync
    perform_full_sync(resource)
```

##### 4. Webhook Subscription Expiration

**Issue**: Webhooks stop receiving notifications

**Solution**: Subscriptions auto-renew 24 hours before expiration:
```python
# In ScheduledCrawler
if subscription.expires_in_hours < 24:
    renew_subscription(subscription.id)
```

### Performance Optimization

#### 1. Cosmos DB Optimization
- Use autoscale for RU allocation
- Optimize partition key usage (tenant_id)
- Implement proper indexing policies
- Use point reads where possible

#### 2. Queue Processing
- Adjust batch size based on workload
- Implement priority queues for critical updates
- Use dead letter queues for failed messages
- Monitor queue depth and adjust workers

#### 3. Function App Scaling
- Use Premium plan for predictable performance
- Configure scale-out rules appropriately
- Implement circuit breakers for external calls
- Use async/await patterns throughout

### Testing

#### Run Test Suite
```bash
# Install test dependencies
pip install pytest pytest-cov pytest-asyncio

# Run all tests
python test_m365_brain.py

# Run specific test category
python -m pytest test_m365_brain.py::TestAuthenticationModes -v

# Run with coverage
python -m pytest test_m365_brain.py --cov=. --cov-report=html
```

#### Integration Testing
```bash
# Test authentication flow
curl -X GET "https://YOUR-APP.azurewebsites.net/api/auth/url?mode=user"

# Test search
curl -X GET "https://YOUR-APP.azurewebsites.net/api/search?q=test" \
    -H "x-functions-key: YOUR_KEY"

# Test crawl trigger
curl -X POST "https://YOUR-APP.azurewebsites.net/api/crawl/delta" \
    -H "x-functions-key: YOUR_KEY" \
    -H "Content-Type: application/json" \
    -d '{"resources": ["users"]}'
```

### Maintenance

#### Regular Tasks

1. **Daily**
   - Monitor Application Insights dashboard
   - Check queue depths
   - Review error logs

2. **Weekly**
   - Review crawl completion rates
   - Check delta token validity
   - Monitor storage usage

3. **Monthly**
   - Rotate secrets
   - Review access logs
   - Update dependencies
   - Performance review

4. **Quarterly**
   - Security audit
   - Disaster recovery test
   - Capacity planning review

### Disaster Recovery

#### Backup Strategy
```bash
# Backup Cosmos DB
az cosmosdb sql container restore \
    --account-name m365brain-cosmos \
    --database-name M365Data \
    --name documents \
    --resource-group m365-brain-rg

# Export Key Vault secrets
az keyvault secret list --vault-name m365brainvault \
    --query "[].{name:name, value:value}" -o json > secrets-backup.json
```

#### Recovery Procedures
1. Restore Cosmos DB from point-in-time backup
2. Recreate Function App from deployment package
3. Restore Key Vault secrets
4. Reconfigure app settings
5. Verify webhook subscriptions
6. Run full crawl to resync data

### Support

For issues or questions:
1. Check Application Insights for detailed error messages
2. Review Function App logs in Azure Portal
3. Consult the troubleshooting section above
4. File an issue with detailed logs and configuration

### License

This implementation is provided as-is for enterprise Microsoft 365 integration.

---

**Version**: 3.0.0  
**Last Updated**: 2024  
**Status**: Production Ready