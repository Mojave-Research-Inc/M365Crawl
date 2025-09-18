# M365 Big Brain Crawl - Enterprise M365 Data Intelligence Platform

## Overview

M365 Big Brain Crawl is a comprehensive, production-ready platform for crawling, indexing, and intelligently analyzing Microsoft 365 data using OpenAI's Assistant API. The system provides continuous synchronization, real-time change tracking, and natural language interaction with your entire M365 ecosystem.

## Key Features

### Core Capabilities
- **Multi-Tenant Support**: Handle multiple M365 tenants with isolated data storage
- **Comprehensive Data Coverage**: SharePoint, OneDrive, Teams (channels & chats), Users, Groups
- **Incremental Sync**: Delta queries for efficient updates
- **Real-Time Updates**: Webhook subscriptions for instant change notifications
- **AI-Powered Analysis**: OpenAI Assistant integration for intelligent queries
- **Enterprise Scale**: Queue-based architecture for handling large datasets
- **Automated Sync**: Scheduled functions for continuous data freshness

### Technical Architecture
- **Azure Functions**: Serverless compute for all processing
- **Azure Storage**: Blob storage for documents with hierarchical organization
- **Cosmos DB**: NoSQL database for indexing and fast queries
- **Service Bus**: Message queuing for reliable large-scale processing
- **Key Vault**: Secure secret management
- **Application Insights**: Complete monitoring and diagnostics

## Deployment

### Prerequisites
1. Azure subscription with appropriate permissions
2. Azure CLI installed and configured
3. OpenAI API access (for Assistant features)
4. Microsoft 365 tenant with admin access
5. Azure AD app registration for Graph API

### Quick Start

```bash
# Clone or download the deployment script
wget https://raw.githubusercontent.com/your-repo/m365-brain-deploy.sh

# Make executable
chmod +x m365-brain-deploy.sh

# Set required environment variables
export OPENAI_API_KEY="your-openai-api-key"
export GRAPH_CLIENT_ID="your-graph-app-id"
export GRAPH_CLIENT_SECRET="your-graph-app-secret"
export GRAPH_TENANT_ID="your-tenant-id"

# Run deployment
./m365-brain-deploy.sh
```

The script will:
1. Create all Azure resources
2. Configure storage, database, and messaging
3. Deploy function code
4. Set up monitoring
5. Configure security

### Azure AD App Setup

1. Register a new application in Azure AD:
```bash
az ad app create --display-name "M365 Brain Crawler" \
  --available-to-other-tenants false
```

2. Grant required Graph API permissions:
   - User.Read.All
   - Group.Read.All
   - Sites.Read.All
   - Files.Read.All
   - TeamSettings.Read.All
   - Channel.ReadBasic.All
   - ChannelMessage.Read.All

3. Create client secret:
```bash
az ad app credential reset --id <app-id>
```

### OpenAI Assistant Configuration

After deployment, set up the OpenAI Assistant:

```bash
# Run the setup script
python3 setup_assistant.py

# Update Function App with Assistant ID
az functionapp config appsettings set \
  --name <function-app-name> \
  --resource-group <resource-group> \
  --settings "OPENAI_ASSISTANT_ID=<assistant-id>"
```

## API Endpoints

### Assistant Chat
```bash
POST /api/assistant/chat
{
  "message": "Find all documents about Q4 sales",
  "tenant_id": "your-tenant-id",
  "thread_id": "optional-thread-id"
}
```

### Full Crawl
```bash
POST /api/crawl/full
{
  "tenant_id": "your-tenant-id",
  "resources": ["users", "groups", "sites", "teams"]
}
```

### Delta Sync
```bash
POST /api/crawl/delta
{
  "tenant_id": "your-tenant-id",
  "resources": ["users", "groups", "documents", "messages"]
}
```

### Search
```bash
GET /api/search?q=sales+report&tenant_id=your-tenant-id&limit=50
```

### Analytics
```bash
GET /api/analytics?tenant_id=your-tenant-id&report_type=summary
```

## Usage Examples

### Initial Setup and First Crawl

```bash
# Trigger initial full crawl
curl -X POST https://<function-app>.azurewebsites.net/api/crawl/full \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "your-tenant-id",
    "resources": ["users", "groups", "sites", "teams"]
  }'
```

### Chat with Your M365 Data

```python
import requests

# Start a conversation
response = requests.post(
    "https://<function-app>.azurewebsites.net/api/assistant/chat",
    json={
        "message": "What are the most active Teams channels this month?",
        "tenant_id": "your-tenant-id"
    }
)

thread_id = response.json()["thread_id"]
print(response.json()["response"])

# Continue conversation
response = requests.post(
    "https://<function-app>.azurewebsites.net/api/assistant/chat",
    json={
        "message": "Show me the top contributors",
        "tenant_id": "your-tenant-id",
        "thread_id": thread_id
    }
)
```

### Search Across All Content

```python
# Search for specific content
response = requests.get(
    "https://<function-app>.azurewebsites.net/api/search",
    params={
        "q": "project roadmap",
        "tenant_id": "your-tenant-id",
        "limit": 20
    }
)

for result in response.json()["results"]:
    print(f"{result['displayName']} - {result['webUrl']}")
```

### Generate Analytics Reports

```python
# Get usage analytics
response = requests.get(
    "https://<function-app>.azurewebsites.net/api/analytics",
    params={
        "tenant_id": "your-tenant-id",
        "report_type": "collaboration"
    }
)

analytics = response.json()["analytics"]
print(f"Total Users: {analytics['total_users']}")
print(f"Total Documents: {analytics['total_documents']}")
print(f"Recent Activity: {analytics['documents_modified_last_week']}")
```

## Architecture Details

### Data Flow

1. **Crawling Phase**
   - Graph API calls retrieve M365 data
   - Delta tokens track incremental changes
   - Data stored in blob storage
   - Metadata indexed in Cosmos DB

2. **Processing Pipeline**
   - Service Bus queues distribute work
   - Queue triggers process items asynchronously
   - Large datasets handled in batches
   - Automatic retry on failures

3. **AI Integration**
   - OpenAI Assistant processes queries
   - Function calling enables data operations
   - Context maintained across conversations
   - Tools provide specialized capabilities

### Storage Structure

```
Blob Storage:
/crawl-data/
  /<tenant-id>/
    /users/
      /<user-id>.json
    /groups/
      /<group-id>.json
    /documents/
      /<document-id>.json
    /teams/
      /<team-id>.json

Cosmos DB:
- Database: M365Data
  - Container: users (partitioned by tenantId)
  - Container: groups (partitioned by tenantId)
  - Container: documents (partitioned by tenantId)
  - Container: teams (partitioned by tenantId)
  - Container: channels (partitioned by tenantId)
  - Container: metadata (partitioned by tenantId)
  - Container: crawl-status (partitioned by tenantId)
```

### Security Model

- **Managed Identities**: Functions use system-assigned identities
- **Key Vault Integration**: All secrets stored securely
- **Network Isolation**: Private endpoints available
- **Data Encryption**: At-rest and in-transit encryption
- **RBAC**: Role-based access control for all resources
- **Audit Logging**: Complete audit trail in App Insights

## Monitoring and Operations

### Health Checks

```bash
# Check function app health
az functionapp show --name <function-app> \
  --resource-group <resource-group> \
  --query state

# View recent errors
az monitor app-insights query \
  --app <app-insights> \
  --analytics-query "exceptions | take 10"
```

### Performance Metrics

Monitor these key metrics in Application Insights:
- Function execution duration
- Queue depth and processing time
- API response times
- Graph API throttling
- Storage operations/sec
- Cosmos DB RU consumption

### Troubleshooting

Common issues and solutions:

1. **Graph API Throttling**
   - Implement exponential backoff
   - Use batch requests where possible
   - Monitor rate limits in App Insights

2. **Large Dataset Processing**
   - Increase queue batch size
   - Scale function app instances
   - Optimize Cosmos DB throughput

3. **Delta Token Expiration**
   - Automatic fallback to full sync
   - Token refresh in scheduled functions
   - Alert on repeated failures

## Advanced Features

### Custom Webhook Subscriptions

```python
# Create subscription for specific resources
subscription = {
    "changeType": "created,updated",
    "notificationUrl": "https://<function-app>.azurewebsites.net/api/webhooks/changes",
    "resource": "/users",
    "expirationDateTime": "2024-12-31T23:59:59Z"
}
```

### Batch Processing

```python
# Queue multiple items for processing
items = [
    {"type": "site_documents", "site_id": "site1"},
    {"type": "site_documents", "site_id": "site2"},
    {"type": "team_channels", "team_id": "team1"}
]

for item in items:
    queue_client.send_message(json.dumps(item))
```

### Custom Analytics Queries

```sql
-- Cosmos DB query for collaboration insights
SELECT 
    c.tenantId,
    COUNT(1) as document_count,
    AVG(c.size) as avg_size
FROM c
WHERE c.modifiedDateTime > '2024-01-01'
GROUP BY c.tenantId
```

## Cost Optimization

### Recommendations

1. **Function App**
   - Use Consumption plan for variable workloads
   - Premium plan for consistent high volume
   - Enable auto-scaling based on queue depth

2. **Storage**
   - Lifecycle policies for old data
   - Cool/Archive tiers for historical data
   - Compression for large documents

3. **Cosmos DB**
   - Autoscale for variable workloads
   - Reserved capacity for predictable usage
   - Optimize partition keys for query patterns

4. **Service Bus**
   - Basic tier sufficient for most scenarios
   - Standard tier for advanced features
   - Monitor dead letter queues

## Compliance and Governance

### Data Retention

Configure retention policies:
```bash
# Set blob lifecycle policy
az storage account management-policy create \
  --account-name <storage-account> \
  --policy @retention-policy.json
```

### Audit Logging

All operations logged to Application Insights:
- User queries and responses
- Crawl operations and results
- Data access patterns
- System errors and warnings

### Privacy Considerations

- Implement data minimization
- Use selective field crawling
- Apply retention policies
- Enable audit logging
- Regular permission reviews

## Roadmap

### Planned Features

- **Enhanced AI Capabilities**
  - Custom fine-tuned models
  - Multi-modal analysis
  - Predictive insights

- **Extended Data Sources**
  - Exchange email support
  - Yammer integration
  - Power Platform data

- **Advanced Analytics**
  - Real-time dashboards
  - Trend analysis
  - Anomaly detection

- **Enterprise Features**
  - Multi-geo support
  - Advanced RBAC
  - Custom compliance policies

## Support and Contributing

### Getting Help

1. Check documentation and FAQs
2. Review Application Insights logs
3. Search existing issues
4. Create detailed bug reports

### Contributing

We welcome contributions! Areas of interest:
- Additional data connectors
- Analytics improvements
- Performance optimizations
- Documentation enhancements

## License

This project is provided as-is for educational and development purposes. Ensure compliance with your organization's policies and Microsoft's terms of service when accessing M365 data.

## Acknowledgments

Built with:
- Azure Functions for serverless compute
- Microsoft Graph API for M365 access
- OpenAI for intelligent analysis
- Azure services for enterprise scale

---

**Version**: 1.0.0  
**Last Updated**: January 2025  
**Status**: Production Ready