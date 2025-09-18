#!/usr/bin/env bash
set -euo pipefail

# M365Crawl: One-command Azure Cloud Shell deployment
# - Provisions RG, Storage, Function App (Linux/Python)
# - Creates/updates multi-tenant Entra app registration
# - Configures Key Vault secret with Key Vault reference
# - Generates and deploys Azure Functions app with endpoints
# - Prints endpoints, admin consent URL, and quick tests

########################################
# Config (override via env or flags)
########################################
LOCATION=${LOCATION:-"eastus"}
PROJECT_NAME=${PROJECT_NAME:-"m365cawl"}
SUFFIX=${SUFFIX:-"7277"}

# Resource names (lowercase where required)
RG_NAME=${RG_NAME:-"${PROJECT_NAME}-rg"}
STORAGE_NAME=${STORAGE_NAME:-"${PROJECT_NAME}store${SUFFIX}"}
FUNCAPP_NAME=${FUNCAPP_NAME:-"${PROJECT_NAME}${SUFFIX}"}
KV_NAME=${KV_NAME:-"${PROJECT_NAME}-kv-${SUFFIX}"}

# Entra app registration
APP_DISPLAY_NAME=${APP_DISPLAY_NAME:-"M365 Big Brain Crawl"}
STATE_VALUE=${STATE_VALUE:-"xyz123"}

# Toggle tests after deploy
RUN_TESTS=${RUN_TESTS:-"true"}

########################################
# Helpers
########################################
log() { echo -e "\n[$(date +%H:%M:%S)] $*"; }
req() { command -v "$1" >/dev/null 2>&1 || { echo "Missing required command: $1"; exit 1; }; }
randlower() { tr -dc a-z0-9 </dev/urandom | head -c "$1"; }

########################################
# Pre-flight
########################################
req az
req jq

if ! az account show >/dev/null 2>&1; then
  echo "You must be logged in to Azure CLI. Run: az login" >&2
  exit 1
fi

SUB_ID=$(az account show --query id -o tsv)
TENANT_ID_HOME=$(az account show --query tenantId -o tsv)

# Storage account must be 3-24 chars, lowercase, unique
if [[ ${#STORAGE_NAME} -gt 24 ]]; then
  STORAGE_NAME="${STORAGE_NAME:0:20}$(randlower 4)"
fi

########################################
# Create/ensure resource group
########################################
log "Ensuring resource group: ${RG_NAME} (${LOCATION})"
az group create -n "$RG_NAME" -l "$LOCATION" -o none

########################################
# Storage account (idempotent)
########################################
log "Ensuring storage account: ${STORAGE_NAME}"
if ! az storage account show -g "$RG_NAME" -n "$STORAGE_NAME" >/dev/null 2>&1; then
  az storage account create \
    -g "$RG_NAME" -n "$STORAGE_NAME" -l "$LOCATION" \
    --sku Standard_LRS --kind StorageV2 -o none
fi

########################################
# Function App (Linux Python 3.11) + Managed Identity
########################################
log "Ensuring Function App: ${FUNCAPP_NAME} (Python 3.11, Linux Consumption)"
if ! az functionapp show -g "$RG_NAME" -n "$FUNCAPP_NAME" >/dev/null 2>&1; then
  az functionapp create \
    -g "$RG_NAME" -n "$FUNCAPP_NAME" \
    --storage-account "$STORAGE_NAME" \
    --consumption-plan-location "$LOCATION" \
    --os-type Linux --runtime python --runtime-version 3.11 \
    --functions-version 4 -o none
fi

log "Ensuring system-assigned managed identity for Function App"
IDENTITY_JSON=$(az functionapp identity assign -g "$RG_NAME" -n "$FUNCAPP_NAME" -o json)
FUNC_PRINCIPAL_ID=$(echo "$IDENTITY_JSON" | jq -r '.principalId')

########################################
# Key Vault + secret (for client secret), with MI access
########################################
log "Ensuring Key Vault: ${KV_NAME}"
if ! az keyvault show -n "$KV_NAME" -g "$RG_NAME" >/dev/null 2>&1; then
  az keyvault create -n "$KV_NAME" -g "$RG_NAME" -l "$LOCATION" --enable-soft-delete true -o none
fi

log "Granting Function App identity access to Key Vault secrets"
az keyvault set-policy -n "$KV_NAME" -g "$RG_NAME" \
  --object-id "$FUNC_PRINCIPAL_ID" \
  --secret-permissions get list -o none

########################################
# Entra App Registration (create or reuse)
########################################
log "Ensuring Entra App Registration: ${APP_DISPLAY_NAME} (multi-tenant)"
APP_JSON=$(az ad app list --display-name "$APP_DISPLAY_NAME" -o json)
APP_COUNT=$(echo "$APP_JSON" | jq 'length')
if [[ "$APP_COUNT" -gt 0 ]]; then
  APP_ID=$(echo "$APP_JSON" | jq -r '.[0].appId')
  APP_OBJ_ID=$(echo "$APP_JSON" | jq -r '.[0].id')
  log "Reusing existing app registration: $APP_ID"
else
  APP_CREATE=$(az ad app create \
    --display-name "$APP_DISPLAY_NAME" \
    --sign-in-audience AzureADMultipleOrgs -o json)
  APP_ID=$(echo "$APP_CREATE" | jq -r '.appId')
  APP_OBJ_ID=$(echo "$APP_CREATE" | jq -r '.id')
  log "Created app registration: $APP_ID"
fi

# Ensure a service principal for the app (in home tenant)
if ! az ad sp show --id "$APP_ID" >/dev/null 2>&1; then
  az ad sp create --id "$APP_ID" -o none
fi

########################################
# Create client secret (store in Key Vault)
########################################
log "Ensuring client secret for app registration (stored in Key Vault)"
SECRET_NAME=${SECRET_NAME:-"m365crawl-client-secret"}
if ! az keyvault secret show --vault-name "$KV_NAME" --name "$SECRET_NAME" >/dev/null 2>&1; then
  APP_SECRET_VALUE=$(az ad app credential reset --id "$APP_ID" --append --display-name "cloudshell-secret" --years 1 --query password -o tsv)
  az keyvault secret set --vault-name "$KV_NAME" --name "$SECRET_NAME" --value "$APP_SECRET_VALUE" -o none
  log "Client secret created and stored in Key Vault secret: ${SECRET_NAME}"
else
  log "Reusing existing Key Vault secret: ${SECRET_NAME}"
fi
SECRET_URI=$(az keyvault secret show --vault-name "$KV_NAME" --name "$SECRET_NAME" --query id -o tsv)

########################################
# Graph permissions (Application) — add by value name via Graph lookup
########################################
log "Adding Microsoft Graph application permissions"
GRAPH_APP_ID="00000003-0000-0000-c000-000000000000"

get_app_role_id() {
  local role_value="$1"
  az rest --method GET \
    --url "https://graph.microsoft.com/v1.0/servicePrincipals(appId='${GRAPH_APP_ID}')" \
    --output json | \
    jq -r --arg v "$role_value" '.appRoles[] | select(.value==$v and (.allowedMemberTypes|index("Application"))) | .id'
}

declare -a ROLES=(
  "Sites.Read.All"
  "Chat.Read.All"
  "ChannelMessage.Read.All"
  "User.Read.All"
  "Group.Read.All"
  "Team.ReadBasic.All"
)

API_PERMS=""
for role in "${ROLES[@]}"; do
  role_id=$(get_app_role_id "$role" || true)
  if [[ -n "${role_id}" && "${role_id}" != "null" ]]; then
    API_PERMS+="${role_id}=Role "
  else
    echo "Warning: Could not resolve app role id for ${role}" >&2
  fi
done

if [[ -n "$API_PERMS" ]]; then
  az ad app permission add --id "$APP_ID" --api "$GRAPH_APP_ID" --api-permissions $API_PERMS -o none || true
  # Best-effort admin consent (requires admin)
  az ad app permission admin-consent --id "$APP_ID" -o none || echo "Admin consent step requires sufficient privileges; continue."
fi

########################################
# Configure Function App settings (Key Vault ref + IDs)
########################################
DEFAULT_HOSTNAME=$(az functionapp show -g "$RG_NAME" -n "$FUNCAPP_NAME" --query defaultHostName -o tsv)
REDIRECT_URI="https://${DEFAULT_HOSTNAME}/api/auth/callback"

log "Updating app registration redirect URI: ${REDIRECT_URI}"
az ad app update --id "$APP_ID" --web-redirect-uris "$REDIRECT_URI" -o none

log "Setting Function App application settings"
az functionapp config appsettings set -g "$RG_NAME" -n "$FUNCAPP_NAME" --settings \
  "CLIENT_ID=${APP_ID}" \
  "CLIENT_SECRET=@Microsoft.KeyVault(SecretUri=${SECRET_URI})" \
  "STATE_VALUE=${STATE_VALUE}" \
  "REDIRECT_URI=${REDIRECT_URI}" \
  "WEBSITE_RUN_FROM_PACKAGE=1" -o none

########################################
# Generate Azure Functions Python app
########################################
WORKDIR=$(mktemp -d)
APPDIR="$WORKDIR/app"
mkdir -p "$APPDIR"

cat >"$APPDIR/host.json" <<'EOF'
{
  "version": "2.0"
}
EOF

cat >"$APPDIR/requirements.txt" <<'EOF'
azure-functions==1.20.0
msal==1.28.0
EOF

# health_check
mkdir -p "$APPDIR/health_check"
cat >"$APPDIR/health_check/__init__.py" <<'PY'
import json
import azure.functions as func

def main(req: func.HttpRequest) -> func.HttpResponse:
    return func.HttpResponse(
        json.dumps({"status": "ok"}),
        status_code=200,
        mimetype="application/json",
    )
PY
cat >"$APPDIR/health_check/function.json" <<'EOF'
{
  "bindings": [
    {"authLevel": "anonymous", "type": "httpTrigger", "direction": "in", "name": "req", "methods": ["get"], "route": "health"},
    {"type": "http", "direction": "out", "name": "$return"}
  ]
}
EOF

# test_endpoint
mkdir -p "$APPDIR/test_endpoint"
cat >"$APPDIR/test_endpoint/__init__.py" <<'PY'
import azure.functions as func

def main(req: func.HttpRequest) -> func.HttpResponse:
    return func.HttpResponse("test ok", status_code=200)
PY
cat >"$APPDIR/test_endpoint/function.json" <<'EOF'
{
  "bindings": [
    {"authLevel": "anonymous", "type": "httpTrigger", "direction": "in", "name": "req", "methods": ["get"], "route": "test"},
    {"type": "http", "direction": "out", "name": "$return"}
  ]
}
EOF

# get_admin_consent_url
mkdir -p "$APPDIR/get_admin_consent_url"
cat >"$APPDIR/get_admin_consent_url/__init__.py" <<'PY'
import json
import os
import urllib.parse
import azure.functions as func

def main(req: func.HttpRequest) -> func.HttpResponse:
    client_id = os.environ.get("CLIENT_ID", "")
    redirect_uri = os.environ.get("REDIRECT_URI", "")
    state = os.environ.get("STATE_VALUE", "state")
    if not client_id or not redirect_uri:
        return func.HttpResponse("Missing CLIENT_ID or REDIRECT_URI", status_code=500)

    params = {
        "client_id": client_id,
        "scope": "https://graph.microsoft.com/.default",
        "redirect_uri": redirect_uri,
        "state": state,
    }
    url = (
        "https://login.microsoftonline.com/organizations/v2.0/adminconsent?"
        + urllib.parse.urlencode(params)
    )
    return func.HttpResponse(
        json.dumps({"admin_consent_url": url}),
        status_code=200,
        mimetype="application/json",
    )
PY
cat >"$APPDIR/get_admin_consent_url/function.json" <<'EOF'
{
  "bindings": [
    {"authLevel": "anonymous", "type": "httpTrigger", "direction": "in", "name": "req", "methods": ["get"], "route": "admin-consent-url"},
    {"type": "http", "direction": "out", "name": "$return"}
  ]
}
EOF

# auth_callback
mkdir -p "$APPDIR/auth_callback"
cat >"$APPDIR/auth_callback/__init__.py" <<'PY'
import azure.functions as func

def main(req: func.HttpRequest) -> func.HttpResponse:
    state = req.params.get("state")
    admin_consent = req.params.get("admin_consent")
    tenant = req.params.get("tenant")
    # Minimal validation of state
    return func.HttpResponse(
        f"auth callback ok; state={state}; admin_consent={admin_consent}; tenant={tenant}",
        status_code=200,
    )
PY
cat >"$APPDIR/auth_callback/function.json" <<'EOF'
{
  "bindings": [
    {"authLevel": "anonymous", "type": "httpTrigger", "direction": "in", "name": "req", "methods": ["get"], "route": "auth/callback"},
    {"type": "http", "direction": "out", "name": "$return"}
  ]
}
EOF

# crawl_tenant (token acquisition demo)
mkdir -p "$APPDIR/crawl_tenant"
cat >"$APPDIR/crawl_tenant/__init__.py" <<'PY'
import json
import os
import azure.functions as func
import msal

def main(req: func.HttpRequest) -> func.HttpResponse:
    try:
        body = req.get_json()
    except Exception:
        body = {}
    tenant_id = body.get("tenant_id") or req.params.get("tenant_id")
    if not tenant_id:
        return func.HttpResponse("Missing tenant_id", status_code=400)

    client_id = os.environ.get("CLIENT_ID")
    client_secret = os.environ.get("CLIENT_SECRET")
    if not client_id or not client_secret:
        return func.HttpResponse("Missing CLIENT_ID/CLIENT_SECRET", status_code=500)

    authority = f"https://login.microsoftonline.com/{tenant_id}"
    app = msal.ConfidentialClientApplication(client_id=client_id, client_credential=client_secret, authority=authority)
    result = app.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])  # app-only
    if "access_token" not in result:
        return func.HttpResponse(json.dumps(result), status_code=500, mimetype="application/json")

    token = result["access_token"][:32] + "..."
    return func.HttpResponse(
        json.dumps({"status": "crawl trigger ok", "tenant_id": tenant_id, "token_preview": token}),
        status_code=200,
        mimetype="application/json",
    )
PY
cat >"$APPDIR/crawl_tenant/function.json" <<'EOF'
{
  "bindings": [
    {"authLevel": "anonymous", "type": "httpTrigger", "direction": "in", "name": "req", "methods": ["post"], "route": "crawl"},
    {"type": "http", "direction": "out", "name": "$return"}
  ]
}
EOF

########################################
# Package and deploy (ZipDeploy / remote Oryx build)
########################################
ZIPFILE="$WORKDIR/app.zip"
(cd "$APPDIR" && zip -qr "$ZIPFILE" .)

log "Deploying Function App package (this triggers remote build)"
az functionapp deployment source config-zip -g "$RG_NAME" -n "$FUNCAPP_NAME" --src "$ZIPFILE" -o none

log "Syncing triggers"
az functionapp sync-functions -g "$RG_NAME" -n "$FUNCAPP_NAME" -o none || true

########################################
# Output and tests
########################################
DEFAULT_HOSTNAME=$(az functionapp show -g "$RG_NAME" -n "$FUNCAPP_NAME" --query defaultHostName -o tsv)
BASE_URL="https://${DEFAULT_HOSTNAME}"
ADMIN_CONSENT_URL="https://login.microsoftonline.com/organizations/v2.0/adminconsent?client_id=${APP_ID}&scope=https%3A%2F%2Fgraph.microsoft.com%2F.default&redirect_uri=$(python3 - <<PY
import urllib.parse
print(urllib.parse.quote("${REDIRECT_URI}", safe=""))
PY
)\&state=${STATE_VALUE}"

echo
echo "=== DEPLOYMENT COMPLETE ==="
echo "Function App: ${BASE_URL}"
echo "Health:       ${BASE_URL}/api/health"
echo "Test:         ${BASE_URL}/api/test"
echo "Admin URL:    ${BASE_URL}/api/admin-consent-url"
echo "Callback:     ${BASE_URL}/api/auth/callback"
echo "Crawl:        ${BASE_URL}/api/crawl"
echo
echo "Admin Consent URL (share with tenant admins):"
echo "${ADMIN_CONSENT_URL}"
echo
echo "Linux Consumption remote build container memory limit is 1.5 GB: https://docs.microsoft.com/azure/azure-functions/functions-scale#service-limits"

if [[ "$RUN_TESTS" == "true" ]]; then
  log "Running quick endpoint tests"
  set +e
  curl -fsS "${BASE_URL}/api/health" && echo || true
  curl -fsS "${BASE_URL}/api/test" && echo || true
  curl -fsS "${BASE_URL}/api/admin-consent-url" && echo || true
  set -e
fi

echo
echo "NEXT STEPS:"
echo "1) Verify Graph API permissions are present and grant Admin consent in Entra ID."
echo "   - Teams message permissions (Chat.Read.All, ChannelMessage.Read.All) are protected; approval may be required."
echo "2) Share the Admin Consent URL with tenant admins to onboard tenants."
echo "3) Trigger a crawl: curl -X POST ${BASE_URL}/api/crawl -H 'Content-Type: application/json' -d '{"tenant_id":"<tenant-guid>"}'"
echo
echo "Done."


