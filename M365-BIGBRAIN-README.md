# M365 Big Brain Crawl - Enterprise Microsoft 365 Data Intelligence Platform

## Overview

M365 Big Brain Crawl is a production-ready, multi-tenant Microsoft 365 data crawler with OpenAI integration that provides comprehensive data crawling, intelligent processing, and plain language interaction capabilities for enterprise environments.

## Features

### Core Capabilities
- **Multi-tenant M365 Data Crawling**: Complete crawling of SharePoint, OneDrive, Teams (chats + channels), users, groups, and teams
- **Continuous Synchronization**: Delta queries and webhook subscriptions for real-time data updates
- **OpenAI Intelligence**: Integrated OpenAI Assistant for natural language queries and intelligent data operations
- **Enterprise Search**: Comprehensive search across all M365 data types with advanced filtering
- **Compliance & eDiscovery**: Built-in support for compliance monitoring and eDiscovery workflows
- **Knowledge Management**: Centralized knowledge base from all M365 sources

### Technical Features
- **Serverless Architecture**: Azure Functions for infinite scalability
- **Queue-Based Processing**: Service Bus for reliable async processing
- **Secure Secrets Management**: Azure Key Vault integration
- **Production Monitoring**: Application Insights for comprehensive telemetry
- **Multi-tier Storage**: Cosmos DB for metadata, Blob Storage for documents
- **Incremental Updates**: Delta query support for efficient data synchronization

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Microsoft 365                            │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐          │
│  │SharePoint│ │ OneDrive │ │  Teams   │ │  Users   │          │
│  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘          │
└───────┼────────────┼────────────┼────────────┼─────────────────┘
        │            │            │            │
        └────────────┴────────────┴────────────┘
                           │
                    Graph API / Webhooks
                           │
        ┌──────────────────┴──────────────────┐
        │        Azure Functions App           │
        │  ┌─────────────────────────────┐    │
        │  │    Crawler Functions        │    │
        │  │  - CrawlTrigger            │    │
        │  │  - QueueProcessor          │    │
        │  │  - ScheduledCrawler        │    │
        │  └─────────────┬───────────────┘    │
        │                │                     │
        │  ┌─────────────┴───────────────┐    │
        │  │    API Functions            │    │
        │  │  - SearchAPI               │    │
        │  │  - OpenAIAssistant         │    │
        │  └─────────────────────────────┘    │
        └──────────────────────────────────────┘
                           │
        ┌──────────────────┴──────────────────┐
        │           Data Layer                 │
        │  ┌──────────┐  ┌──────────────┐    │
        │  │Cosmos DB │  │ Blob Storage │    │
        │  └──────────┘  └──────────────┘    │
        │  ┌──────────┐  ┌──────────────┐    │
        │  │Key Vault │  │ Service Bus  │    │
        │  └──────────┘  └──────────────┘    │
        └──────────────────────────────────────┘
                           │
                    ┌──────┴──────┐
                    │  OpenAI API  │
                    └──────────────┘
```

## Prerequisites

- Azure Subscription with appropriate permissions
- Azure AD Tenant ID
- OpenAI API Key
- Azure Cloud Shell or Azure CLI installed locally

## Quick Start Deployment

### 1. Run Deployment Script

```bash
# Download the deployment script
curl -O https://raw.githubusercontent.com/your-repo/m365-brain/main/m365-brain-deploy.sh

# Make it executable
chmod +x m365-brain-deploy.sh

# Run deployment
./m365-brain-deploy.sh
```

### 2. Provide Required Information

The script will prompt for:
- Azure AD Tenant ID
- OpenAI API Key
- Resource Group name (optional)
- Azure region (optional)

### 3. Grant Admin Consent

After deployment, visit the provided URL to grant admin consent for Microsoft Graph permissions.

## API Endpoints

### Crawl Operations

#### Initiate Full Crawl
```bash
curl -X POST https://<function-app>.azurewebsites.net/api/crawl/full \
  -H 'x-functions-key: <your-key>'
```

#### Crawl Specific Resources
```bash
# Users
curl -X POST https://<function-app>.azurewebsites.net/api/crawl/users \
  -H 'x-functions-key: <your-key>'

# Teams
curl -X POST https://<function-app>.azurewebsites.net/api/crawl/teams \
  -H 'x-functions-key: <your-key>'

# SharePoint
curl -X POST https://<function-app>.azurewebsites.net/api/crawl/sharepoint \
  -H 'x-functions-key: <your-key>'
```

#### Check Crawl Status
```bash
curl -X GET https://<function-app>.azurewebsites.net/api/crawl/status \
  -H 'x-functions-key: <your-key>'
```

### Search Operations

#### Universal Search
```bash
curl -X GET "https://<function-app>.azurewebsites.net/api/search?q=project%20plan" \
  -H 'x-functions-key: <your-key>'
```

#### Filtered Search
```bash
curl -X GET "https://<function-app>.azurewebsites.net/api/search?q=budget&entity_type=sharepoint_document&date_from=2024-01-01" \
  -H 'x-functions-key: <your-key>'
```

#### Get Analytics
```bash
curl -X GET "https://<function-app>.azurewebsites.net/api/search?type=analytics" \
  -H 'x-functions-key: <your-key>'
```

### OpenAI Assistant

#### Chat with Assistant
```bash
curl -X POST https://<function-app>.azurewebsites.net/api/assistant/chat \
  -H 'Content-Type: application/json' \
  -H 'x-functions-key: <your-key>' \
  -d '{
    "message": "Find all documents related to Q4 planning"
  }'
```

#### Continue Conversation
```bash
curl -X POST https://<function-app>.azurewebsites.net/api/assistant/chat \
  -H 'Content-Type: application/json' \
  -H 'x-functions-key: <your-key>' \
  -d '{
    "message": "Show me the most recent ones",
    "thread_id": "<previous-thread-id>"
  }'
```

## Configuration

### Environment Variables

All configuration is managed through Azure Function App settings:

| Variable | Description |
|----------|-------------|
| `TENANT_ID` | Azure AD Tenant ID |
| `CLIENT_ID` | App Registration Client ID |
| `CLIENT_SECRET` | App Registration Secret |
| `OPENAI_API_KEY` | OpenAI API Key |
| `STORAGE_CONNECTION` | Azure Storage Connection String |
| `COSMOS_CONNECTION` | Cosmos DB Connection String |
| `SERVICE_BUS_CONNECTION` | Service Bus Connection String |
| `KEY_VAULT_NAME` | Key Vault Name |

### Microsoft Graph Permissions

Required API permissions (configured automatically):

**Delegated Permissions:**
- User.Read
- Files.Read.All
- Sites.Read.All
- Group.Read.All
- Team.ReadBasic.All

**Application Permissions:**
- User.Read.All
- Files.Read.All
- Sites.Read.All
- Group.Read.All
- TeamSettings.Read.All

## Data Storage

### Cosmos DB Containers

1. **Documents**: SharePoint/OneDrive files and metadata
2. **Users**: User directory information
3. **Teams**: Teams, groups, and channels
4. **CrawlState**: Crawl history and delta tokens

### Blob Storage Containers

1. **documents**: File content storage
2. **crawl-state**: Delta query tokens
3. **webhooks**: Webhook subscription data

## Monitoring

### Application Insights

Monitor your deployment through Application Insights:

- **Live Metrics**: Real-time performance monitoring
- **Failures**: Track and diagnose errors
- **Performance**: Response times and dependencies
- **Usage**: API call patterns and volumes

### Key Metrics

- Crawl completion rates
- API response times
- Queue processing delays
- Storage utilization
- OpenAI API usage

## Security Considerations

1. **Secrets Management**: All secrets stored in Azure Key Vault
2. **Network Security**: Function App can be configured with VNet integration
3. **Authentication**: Function-level authentication with keys
4. **Data Encryption**: At-rest and in-transit encryption
5. **Compliance**: Supports compliance monitoring workflows

## Scaling Considerations

### Performance Optimization

1. **Function App Plan**: Uses Elastic Premium (EP1) for auto-scaling
2. **Cosmos DB RUs**: Start with 400 RUs per container, scale as needed
3. **Service Bus**: Standard tier supports up to 80MB/s throughput
4. **Batch Processing**: Queue-based architecture for parallel processing

### Cost Optimization

1. **Cosmos DB**: Use autoscale for cost efficiency
2. **Storage**: Implement lifecycle policies for old data
3. **Functions**: Monitor execution counts and optimize triggers
4. **OpenAI**: Implement caching for repeated queries

## Troubleshooting

### Common Issues

#### 1. Authentication Failures
```bash
# Check app registration permissions
az ad app permission list --id <app-id>

# Verify admin consent
az ad app permission admin-consent --id <app-id>
```

#### 2. Crawl Failures
```bash
# Check function logs
az functionapp log tail --name <function-app> --resource-group <rg>

# Verify Graph API access
curl -H "Authorization: Bearer <token>" \
  https://graph.microsoft.com/v1.0/users
```

#### 3. Search Not Returning Results
```bash
# Verify Cosmos DB data
az cosmosdb sql container list --account-name <cosmos-account> \
  --database-name M365Data --resource-group <rg>
```

### Debug Commands

```bash
# View function app logs
func azure functionapp logstream <function-app>

# Check Service Bus queue depth
az servicebus queue show --name crawl-queue \
  --namespace-name <namespace> --resource-group <rg> \
  --query messageCount

# Monitor Cosmos DB metrics
az monitor metrics list --resource <cosmos-resource-id> \
  --metric "TotalRequests" --interval PT1H
```

## Advanced Usage

### Custom Crawl Schedules

Modify the timer trigger in `ScheduledCrawler/function.json`:

```json
{
  "schedule": "0 0 */6 * * *"  // Every 6 hours
}
```

Common cron expressions:
- `0 */30 * * * *` - Every 30 minutes
- `0 0 * * * *` - Every hour
- `0 0 0 * * *` - Daily at midnight
- `0 0 0 * * 1-5` - Weekdays at midnight

### Extending the OpenAI Assistant

Add custom tools to the assistant in `OpenAIAssistant/__init__.py`:

```python
{
    "type": "function",
    "function": {
        "name": "your_custom_function",
        "description": "Description of your function",
        "parameters": {
            "type": "object",
            "properties": {
                "param1": {"type": "string", "description": "Parameter description"}
            },
            "required": ["param1"]
        }
    }
}
```

### Adding New Data Sources

1. Create new crawler function in `CrawlTrigger/__init__.py`
2. Add queue processor in `QueueProcessor/__init__.py`
3. Update Cosmos DB containers if needed
4. Extend search functionality in `SearchAPI/__init__.py`

## Support and Contribution

### Reporting Issues

1. Check existing issues in the repository
2. Provide deployment logs and error messages
3. Include Azure region and subscription type
4. Specify Graph API permissions granted

### Contributing

1. Fork the repository
2. Create a feature branch
3. Test deployment in your environment
4. Submit pull request with documentation

## License

This project is provided as-is for enterprise Microsoft 365 integration.

## Acknowledgments

- Microsoft Graph API Team
- Azure Functions Team
- OpenAI Platform Team
- Azure Cosmos DB Team

---

**Note**: This system processes sensitive organizational data. Ensure proper security reviews and compliance checks before production deployment.