# M365 Big Brain Crawl / M365Cawl7277

## Purpose

The **M365 Big Brain Crawl** app is a **multi-tenant Microsoft 365 data crawler and integration layer**. Its role is to securely connect to one or more Microsoft 365 tenants, obtain admin consent, and then continuously **crawl, index, and refresh content** across the tenant’s collaboration tools: SharePoint, OneDrive, Teams (chats + channels), and directory objects (users, groups, teams). It then uses OpenAI Assistants or Agents API (whichever is best) to run from the Azure / Entra App space.

By doing this, the app builds a **complete, searchable, and analyzable dataset** from Microsoft Graph that can power advanced use cases such as eDiscovery, compliance monitoring, knowledge management, AI assistants, and cross-tenant data insights.

---

## How the App Works

1. **App Registration (Entra ID)**  
   - Registered as **M365 Big Brain Crawl** in Entra ID, multitenant.  
   - Uses **application permissions** with admin consent.  

2. **Admin Consent & Redirect Flow**  
   - Tenant admins open an **Admin Consent URL**.  
   - After sign-in and approval, Azure AD redirects to the Function App callback (`/api/auth/callback`).  
   - A **service principal** is created in their tenant.

3. **Azure Function App Backend**  
   - Deployed as **M365Cawl7277**.  
   - Endpoints:  
     - `/api/health`  
     - `/api/test`  
     - `/api/admin-consent-url`  
     - `/api/auth/callback`  
     - `/api/crawl`

4. **Crawling Microsoft 365 Data**  
   - Calls Microsoft Graph APIs with app-only tokens.  
   - Crawls: SharePoint, OneDrive, Teams, Users, Groups.  
   - Stores **delta tokens** to sync only changes.

5. **Keeping Data Fresh**  
   - Uses **delta queries** (`/delta` endpoints).  
   - Supports **change notifications** (webhooks) for real-time updates.

---

## Why This App Is Valuable

- **Multi-tenant**: Single app can access many tenants.  
- **Centralized index**: Enables search and analytics.  
- **Agent-ready**: Exposes crawl/search to AI agents.  
- **Secure**: Admin-consented, auditable access.  

---

## Example Use Cases

- **eDiscovery** across tenants.  
- **AI-powered Knowledge Base**.  
- **Compliance Monitoring** (real-time).  
- **Migration & Audit**.  
- **Multi-org Insights**.

---

## Current Status

- ✅ Function App deployed and live at `https://m365cawl7277.azurewebsites.net`  
- ✅ Redirect URI registered  
- ✅ Admin consent flow working  
- ✅ Client secret configured  
- ⏳ Next: add Graph permissions, onboard tenants, run real crawl

---

## Latest Deployment Output

- ✅ Function App published successfully (remote build + ZipDeploy)
- 🌐 Function App URL: `https://m365cawl7277.azurewebsites.net`
- 🔁 Redirect URI: `https://m365cawl7277.azurewebsites.net/api/auth/callback`
- 🔗 Admin consent URL:
  `https://login.microsoftonline.com/organizations/v2.0/adminconsent?client_id=2df32d0f-2683-437d-bd70-bd78d1d0c212&scope=https%3A%2F%2Fgraph.microsoft.com%2F.default&redirect_uri=https%3A%2F%2Fm365cawl7277.azurewebsites.net%2Fapi%2Fauth%2Fcallback&state=xyz123`

Endpoints (live):
- Health Check: `https://m365cawl7277.azurewebsites.net/api/health`
- Test Endpoint: `https://m365cawl7277.azurewebsites.net/api/test`
- Admin Consent URL Generator: `https://m365cawl7277.azurewebsites.net/api/admin-consent-url`
- Auth Callback: `https://m365cawl7277.azurewebsites.net/api/auth/callback`
- Crawl: `https://m365cawl7277.azurewebsites.net/api/crawl`

Note:
- Linux Consumption plan remote build container memory limit: 1.5 GB. See [service limits](https://docs.microsoft.com/en-us/azure/azure-functions/functions-scale#service-limits).

Quick test commands:
```bash
# Health check
curl https://m365cawl7277.azurewebsites.net/api/health

# Test endpoint
curl https://m365cawl7277.azurewebsites.net/api/test

# Get admin consent URL
curl https://m365cawl7277.azurewebsites.net/api/admin-consent-url

# Simulate successful auth callback (for smoke testing only)
curl 'https://m365cawl7277.azurewebsites.net/api/auth/callback?admin_consent=True&tenant=test-tenant&state=xyz123'

# Trigger crawl (replace with real tenant GUID when ready)
curl -X POST https://m365cawl7277.azurewebsites.net/api/crawl \
  -H 'Content-Type: application/json' \
  -d '{"tenant_id":"your-tenant-id"}'
```

Troubleshooting hints observed during deploy:
- If the admin-consent-url endpoint returns an error, verify app settings and logs, then fall back to constructing the URL as shown above.
- Oryx build summary log may be unavailable in remote builds (`/tmp/oryx-build.log` empty). Rely on deployment output and Function App logs in Application Insights.

---

## Next Steps

1. **Configure Graph Permissions** (Entra → App registrations → M365 Big Brain Crawl → API permissions):  
   - Sites.Read.All (or Sites.Selected for least privilege)  
   - Chat.Read.All  
   - ChannelMessage.Read.All  
   - User.Read.All  
   - Group.Read.All  
   - Team.ReadBasic.All  
   - Grant admin consent.  

2. **Test Endpoints**  
   ```bash
   curl https://m365cawl7277.azurewebsites.net/api/health
   curl https://m365cawl7277.azurewebsites.net/api/test
   curl https://m365cawl7277.azurewebsites.net/api/admin-consent-url
   ```

3. **Onboard Tenants**  
   - Share the Admin Consent URL:  
     ```
     https://login.microsoftonline.com/organizations/v2.0/adminconsent?client_id=2df32d0f-2683-437d-bd70-bd78d1d0c212&scope=https%3A%2F%2Fgraph.microsoft.com%2F.default&redirect_uri=https%3A%2F%2Fm365cawl7277.azurewebsites.net%2Fapi%2Fauth%2Fcallback&state=xyz123
     ```
   - Tenant admin approves → service principal created.

4. **Run a Crawl**  
   ```bash
   curl -X POST https://m365cawl7277.azurewebsites.net/api/crawl      -H 'Content-Type: application/json'      -d '{"tenant_id":"7cc4e405-4887-4f0d-bcb6-ac22faea810d"}'
   ```

5. **Secure Secrets**  
   - Store `CLIENT_SECRET` in Key Vault.  
   - Prefer Managed Identity for production.

---

## Alignment with Microsoft Guidance

- ✅ Uses **Microsoft Graph** only (Azure AD Graph is retired).  
- ✅ Supports **Sites.Selected** for least-privilege site-level grants.  
- ✅ Supports **delta + change notifications** for efficiency.  

---

## Quick Checklist

- [ ] Add Microsoft Graph API permissions.  
- [ ] Grant admin consent.  
- [ ] Onboard first tenant via Admin Consent URL.  
- [ ] Verify crawl with `/api/crawl`.  
- [ ] Add delta + webhook subscriptions.  
- [ ] Secure secrets in Key Vault.  
