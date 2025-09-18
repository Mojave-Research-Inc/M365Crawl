#!/bin/bash

#############################################################################
# M365 Brain Crawl - Complete Deployment & Multi-Tenant Management Script
# Enhanced with inventory checking, resource reuse, and OAuth automation
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
SCRIPT_VERSION="2.0.0"
DEPLOYMENT_NAME="m365-brain-crawl"
CONFIG_FILE=".m365-brain-config.json"
TENANT_CONFIG_FILE=".m365-tenants.json"

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
    print_color $CYAN "║          M365 Brain Crawl Deployment System v${SCRIPT_VERSION}           ║"
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

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to open URL in browser
open_browser() {
    local url=$1
    if command_exists xdg-open; then
        xdg-open "$url" 2>/dev/null &
    elif command_exists open; then
        open "$url" 2>/dev/null &
    elif command_exists start; then
        start "$url" 2>/dev/null &
    else
        print_color $YELLOW "$WARNING Could not automatically open browser. Please visit:"
        print_color $WHITE "  $url"
    fi
}

# Function to check prerequisites
check_prerequisites() {
    print_section "Checking Prerequisites"
    
    local all_good=true
    
    # Check Azure CLI
    if command_exists az; then
        local az_version=$(az --version 2>/dev/null | head -n1 | cut -d' ' -f2)
        print_color $GREEN "$CHECK_MARK Azure CLI installed (version $az_version)"
    else
        print_color $RED "$CROSS_MARK Azure CLI not installed"
        all_good=false
    fi
    
    # Check jq
    if command_exists jq; then
        print_color $GREEN "$CHECK_MARK jq installed"
    else
        print_color $RED "$CROSS_MARK jq not installed (required for JSON processing)"
        all_good=false
    fi
    
    # Check Azure login status
    if az account show >/dev/null 2>&1; then
        local account_name=$(az account show --query name -o tsv)
        print_color $GREEN "$CHECK_MARK Logged into Azure ($account_name)"
    else
        print_color $RED "$CROSS_MARK Not logged into Azure"
        all_good=false
    fi
    
    if [ "$all_good" = false ]; then
        print_color $RED "\n$CROSS_MARK Prerequisites check failed. Please install missing components."
        exit 1
    fi
    
    print_color $GREEN "\n$CHECK_MARK All prerequisites met!"
}

# Function to load existing configuration
load_configuration() {
    if [ -f "$CONFIG_FILE" ]; then
        print_color $CYAN "$INFO Loading existing configuration from $CONFIG_FILE"
        source <(jq -r 'to_entries[] | "export \(.key)=\"\(.value)\""' "$CONFIG_FILE")
        return 0
    fi
    return 1
}

# Function to save configuration
save_configuration() {
    local config_json=$(cat <<EOF
{
    "RESOURCE_GROUP": "$RESOURCE_GROUP",
    "LOCATION": "$LOCATION",
    "STORAGE_ACCOUNT": "$STORAGE_ACCOUNT",
    "COSMOS_ACCOUNT": "$COSMOS_ACCOUNT",
    "FUNCTION_APP": "$FUNCTION_APP",
    "APP_SERVICE_PLAN": "$APP_SERVICE_PLAN",
    "KEY_VAULT": "$KEY_VAULT",
    "APP_INSIGHTS": "$APP_INSIGHTS",
    "APP_ID": "$APP_ID",
    "TENANT_ID": "$TENANT_ID",
    "DEPLOYMENT_DATE": "$(date -Iseconds)"
}
EOF
)
    echo "$config_json" | jq '.' > "$CONFIG_FILE"
    print_color $GREEN "$CHECK_MARK Configuration saved to $CONFIG_FILE"
}

# Function to perform inventory check
inventory_check() {
    print_section "Deployment Inventory Check"
    
    local inventory_status=""
    
    # Initialize variables
    EXISTING_RESOURCES=""
    MISSING_RESOURCES=""
    
    # Check Resource Group
    print_color $CYAN "$GEAR Checking Resource Group: $RESOURCE_GROUP"
    if az group show -n "$RESOURCE_GROUP" >/dev/null 2>&1; then
        print_color $GREEN "  $CHECK_MARK Resource Group exists"
        EXISTING_RESOURCES="${EXISTING_RESOURCES}resource_group,"
    else
        print_color $YELLOW "  $INFO Resource Group does not exist (will be created)"
        MISSING_RESOURCES="${MISSING_RESOURCES}resource_group,"
    fi
    
    # Check Storage Account
    print_color $CYAN "$GEAR Checking Storage Account: $STORAGE_ACCOUNT"
    if az storage account show -n "$STORAGE_ACCOUNT" -g "$RESOURCE_GROUP" >/dev/null 2>&1; then
        print_color $GREEN "  $CHECK_MARK Storage Account exists"
        EXISTING_RESOURCES="${EXISTING_RESOURCES}storage,"
    else
        print_color $YELLOW "  $INFO Storage Account does not exist (will be created)"
        MISSING_RESOURCES="${MISSING_RESOURCES}storage,"
    fi
    
    # Check Cosmos DB
    print_color $CYAN "$GEAR Checking Cosmos DB: $COSMOS_ACCOUNT"
    if az cosmosdb show -n "$COSMOS_ACCOUNT" -g "$RESOURCE_GROUP" >/dev/null 2>&1; then
        print_color $GREEN "  $CHECK_MARK Cosmos DB exists"
        EXISTING_RESOURCES="${EXISTING_RESOURCES}cosmos,"
        
        # Check databases and containers
        if az cosmosdb sql database show -a "$COSMOS_ACCOUNT" -n "m365brain" -g "$RESOURCE_GROUP" >/dev/null 2>&1; then
            print_color $GREEN "    $CHECK_MARK Database 'm365brain' exists"
        else
            print_color $YELLOW "    $INFO Database 'm365brain' will be created"
        fi
    else
        print_color $YELLOW "  $INFO Cosmos DB does not exist (will be created)"
        MISSING_RESOURCES="${MISSING_RESOURCES}cosmos,"
    fi
    
    # Check Function App
    print_color $CYAN "$GEAR Checking Function App: $FUNCTION_APP"
    if az functionapp show -n "$FUNCTION_APP" -g "$RESOURCE_GROUP" >/dev/null 2>&1; then
        print_color $GREEN "  $CHECK_MARK Function App exists"
        EXISTING_RESOURCES="${EXISTING_RESOURCES}function,"
        
        # Check functions
        local functions=$(az functionapp function list -n "$FUNCTION_APP" -g "$RESOURCE_GROUP" --query "[].name" -o tsv 2>/dev/null)
        if [ -n "$functions" ]; then
            print_color $GREEN "    $CHECK_MARK Functions deployed:"
            echo "$functions" | while read -r func; do
                print_color $GREEN "      • $func"
            done
        else
            print_color $YELLOW "    $INFO No functions deployed yet"
        fi
    else
        print_color $YELLOW "  $INFO Function App does not exist (will be created)"
        MISSING_RESOURCES="${MISSING_RESOURCES}function,"
    fi
    
    # Check Key Vault
    print_color $CYAN "$GEAR Checking Key Vault: $KEY_VAULT"
    if az keyvault show -n "$KEY_VAULT" >/dev/null 2>&1; then
        print_color $GREEN "  $CHECK_MARK Key Vault exists"
        EXISTING_RESOURCES="${EXISTING_RESOURCES}keyvault,"
        
        # Check for secrets
        local secret_count=$(az keyvault secret list --vault-name "$KEY_VAULT" --query "length(@)" -o tsv 2>/dev/null || echo "0")
        print_color $GREEN "    $INFO $secret_count secrets stored"
    else
        print_color $YELLOW "  $INFO Key Vault does not exist (will be created)"
        MISSING_RESOURCES="${MISSING_RESOURCES}keyvault,"
    fi
    
    # Check App Registration
    if [ -n "$APP_ID" ]; then
        print_color $CYAN "$GEAR Checking App Registration: $APP_ID"
        if az ad app show --id "$APP_ID" >/dev/null 2>&1; then
            print_color $GREEN "  $CHECK_MARK App Registration exists"
            EXISTING_RESOURCES="${EXISTING_RESOURCES}app_registration,"
            
            # Check API permissions
            local permissions=$(az ad app permission list --id "$APP_ID" --query "[].resourceAppId" -o tsv 2>/dev/null | sort -u)
            if [ -n "$permissions" ]; then
                print_color $GREEN "    $CHECK_MARK Graph API permissions configured"
            fi
        else
            print_color $YELLOW "  $WARNING App Registration ID not found (will create new)"
            APP_ID=""
        fi
    else
        print_color $YELLOW "  $INFO No App Registration configured yet"
        MISSING_RESOURCES="${MISSING_RESOURCES}app_registration,"
    fi
    
    # Summary
    echo
    print_color $WHITE "═══════════════════════════════════════════════════════════════════"
    
    if [ -n "$EXISTING_RESOURCES" ]; then
        print_color $GREEN "Existing Resources:"
        echo "$EXISTING_RESOURCES" | tr ',' '\n' | grep -v '^$' | while read -r res; do
            print_color $GREEN "  • ${res//_/ }"
        done
    fi
    
    if [ -n "$MISSING_RESOURCES" ]; then
        print_color $YELLOW "\nResources to Create:"
        echo "$MISSING_RESOURCES" | tr ',' '\n' | grep -v '^$' | while read -r res; do
            print_color $YELLOW "  • ${res//_/ }"
        done
    fi
    
    print_color $WHITE "═══════════════════════════════════════════════════════════════════"
}

# Function to create or update resources
deploy_resources() {
    print_section "Deploying M365 Brain Crawl Resources"
    
    # Create Resource Group if needed
    if [[ "$MISSING_RESOURCES" == *"resource_group"* ]]; then
        print_color $CYAN "$GEAR Creating Resource Group..."
        az group create -n "$RESOURCE_GROUP" -l "$LOCATION" --output none
        print_color $GREEN "$CHECK_MARK Resource Group created"
    fi
    
    # Create Storage Account if needed
    if [[ "$MISSING_RESOURCES" == *"storage"* ]]; then
        print_color $CYAN "$GEAR Creating Storage Account..."
        az storage account create \
            -n "$STORAGE_ACCOUNT" \
            -g "$RESOURCE_GROUP" \
            -l "$LOCATION" \
            --sku Standard_LRS \
            --output none
        print_color $GREEN "$CHECK_MARK Storage Account created"
    fi
    
    # Create Cosmos DB if needed
    if [[ "$MISSING_RESOURCES" == *"cosmos"* ]]; then
        print_color $CYAN "$GEAR Creating Cosmos DB Account (this may take several minutes)..."
        az cosmosdb create \
            -n "$COSMOS_ACCOUNT" \
            -g "$RESOURCE_GROUP" \
            --default-consistency-level Session \
            --location "$LOCATION" \
            --output none
        print_color $GREEN "$CHECK_MARK Cosmos DB Account created"
    fi
    
    # Create database and containers
    print_color $CYAN "$GEAR Setting up Cosmos DB databases and containers..."
    
    # Create database
    az cosmosdb sql database create \
        -a "$COSMOS_ACCOUNT" \
        -g "$RESOURCE_GROUP" \
        -n "m365brain" \
        --output none 2>/dev/null || true
    
    # Create containers
    containers=("users" "documents" "emails" "meetings" "tasks" "crawl-status")
    for container in "${containers[@]}"; do
        az cosmosdb sql container create \
            -a "$COSMOS_ACCOUNT" \
            -g "$RESOURCE_GROUP" \
            -d "m365brain" \
            -n "$container" \
            -p "/id" \
            --throughput 400 \
            --output none 2>/dev/null || true
        print_color $GREEN "  $CHECK_MARK Container '$container' ready"
    done
    
    # Create Key Vault if needed
    if [[ "$MISSING_RESOURCES" == *"keyvault"* ]]; then
        print_color $CYAN "$GEAR Creating Key Vault..."
        az keyvault create \
            -n "$KEY_VAULT" \
            -g "$RESOURCE_GROUP" \
            -l "$LOCATION" \
            --output none
        print_color $GREEN "$CHECK_MARK Key Vault created"
    fi
    
    # Create App Service Plan if needed
    if [[ "$MISSING_RESOURCES" == *"function"* ]]; then
        print_color $CYAN "$GEAR Creating App Service Plan..."
        az appservice plan create \
            -n "$APP_SERVICE_PLAN" \
            -g "$RESOURCE_GROUP" \
            -l "$LOCATION" \
            --sku B1 \
            --is-linux \
            --output none
        print_color $GREEN "$CHECK_MARK App Service Plan created"
        
        # Create Function App
        print_color $CYAN "$GEAR Creating Function App..."
        az functionapp create \
            -n "$FUNCTION_APP" \
            -g "$RESOURCE_GROUP" \
            --plan "$APP_SERVICE_PLAN" \
            --runtime python \
            --runtime-version 3.9 \
            --storage-account "$STORAGE_ACCOUNT" \
            --output none
        print_color $GREEN "$CHECK_MARK Function App created"
    fi
    
    # Create or update App Registration
    if [[ "$MISSING_RESOURCES" == *"app_registration"* ]] || [ -z "$APP_ID" ]; then
        print_color $CYAN "$GEAR Creating App Registration..."
        
        APP_ID=$(az ad app create \
            --display-name "M365 Brain Crawl" \
            --sign-in-audience AzureADMultipleOrgs \
            --query appId -o tsv)
        
        print_color $GREEN "$CHECK_MARK App Registration created: $APP_ID"
        
        # Add Graph API permissions
        print_color $CYAN "$GEAR Configuring Graph API permissions..."
        
        # Microsoft Graph API ID
        GRAPH_API_ID="00000003-0000-0000-c000-000000000000"
        
        # Required permissions
        permissions=(
            "User.Read.All"
            "Files.Read.All"
            "Mail.Read"
            "Calendars.Read"
            "Tasks.ReadWrite"
            "Sites.Read.All"
            "Group.Read.All"
            "Directory.Read.All"
        )
        
        for perm in "${permissions[@]}"; do
            # Get permission ID
            perm_id=$(az ad sp show --id $GRAPH_API_ID --query "appRoles[?value=='$perm'].id" -o tsv 2>/dev/null || \
                     az ad sp show --id $GRAPH_API_ID --query "oauth2PermissionScopes[?value=='$perm'].id" -o tsv 2>/dev/null)
            
            if [ -n "$perm_id" ]; then
                az ad app permission add --id "$APP_ID" --api $GRAPH_API_ID --api-permissions "${perm_id}=Scope" 2>/dev/null || true
                print_color $GREEN "  $CHECK_MARK Added permission: $perm"
            fi
        done
        
        # Create service principal
        az ad sp create --id "$APP_ID" --output none 2>/dev/null || true
        
        # Get tenant ID
        TENANT_ID=$(az account show --query tenantId -o tsv)
        
        save_configuration
    fi
    
    print_color $GREEN "\n$CHECK_MARK All resources deployed successfully!"
}

# Function to load tenant configuration
load_tenants() {
    if [ -f "$TENANT_CONFIG_FILE" ]; then
        CONFIGURED_TENANTS=$(jq -r 'keys[]' "$TENANT_CONFIG_FILE" 2>/dev/null || echo "")
        return 0
    fi
    echo "{}" > "$TENANT_CONFIG_FILE"
    CONFIGURED_TENANTS=""
    return 1
}

# Function to save tenant configuration
save_tenant() {
    local tenant_id=$1
    local tenant_name=$2
    local status=$3
    
    local temp_file=$(mktemp)
    jq --arg tid "$tenant_id" \
       --arg name "$tenant_name" \
       --arg status "$status" \
       --arg date "$(date -Iseconds)" \
       '.[$tid] = {name: $name, status: $status, configured_date: $date}' \
       "$TENANT_CONFIG_FILE" > "$temp_file"
    mv "$temp_file" "$TENANT_CONFIG_FILE"
}

# Function to display tenant menu
tenant_menu() {
    print_section "Multi-Tenant Configuration"
    
    load_tenants
    
    while true; do
        echo
        print_color $CYAN "Current Tenant Configuration:"
        print_color $CYAN "════════════════════════════════════════════════════════════════"
        
        if [ -n "$CONFIGURED_TENANTS" ]; then
            echo "$CONFIGURED_TENANTS" | while read -r tenant_id; do
                local tenant_info=$(jq -r ".\"$tenant_id\"" "$TENANT_CONFIG_FILE")
                local name=$(echo "$tenant_info" | jq -r '.name')
                local status=$(echo "$tenant_info" | jq -r '.status')
                
                if [ "$status" = "active" ]; then
                    print_color $GREEN "  $CHECK_MARK $name (ID: $tenant_id)"
                else
                    print_color $YELLOW "  $WARNING $name (ID: $tenant_id) - Pending consent"
                fi
            done
        else
            print_color $YELLOW "  No tenants configured yet"
        fi
        
        print_color $CYAN "════════════════════════════════════════════════════════════════"
        echo
        print_color $WHITE "Options:"
        print_color $WHITE "  1) Add new tenant"
        print_color $WHITE "  2) Re-send consent URL for pending tenant"
        print_color $WHITE "  3) Remove tenant"
        print_color $WHITE "  4) Test tenant connection"
        print_color $WHITE "  5) Back to main menu"
        echo
        read -p "Select option (1-5): " choice
        
        case $choice in
            1)
                add_tenant
                ;;
            2)
                resend_consent
                ;;
            3)
                remove_tenant
                ;;
            4)
                test_tenant
                ;;
            5)
                break
                ;;
            *)
                print_color $RED "Invalid option"
                ;;
        esac
    done
}

# Function to add a new tenant
add_tenant() {
    print_section "Add New Tenant"
    
    print_color $CYAN "Enter tenant information:"
    read -p "Tenant Name (e.g., 'Contoso Corporation'): " tenant_name
    read -p "Tenant ID or Domain (e.g., 'contoso.onmicrosoft.com'): " tenant_domain
    
    # Resolve tenant ID if domain was provided
    if [[ "$tenant_domain" == *"."* ]]; then
        print_color $CYAN "$GEAR Resolving tenant ID..."
        tenant_id=$(curl -s "https://login.microsoftonline.com/$tenant_domain/.well-known/openid-configuration" | jq -r '.token_endpoint' | cut -d'/' -f4)
        
        if [ "$tenant_id" = "null" ] || [ -z "$tenant_id" ]; then
            print_color $RED "$CROSS_MARK Could not resolve tenant ID for domain: $tenant_domain"
            return
        fi
        print_color $GREEN "$CHECK_MARK Tenant ID: $tenant_id"
    else
        tenant_id=$tenant_domain
    fi
    
    # Check if tenant already exists
    if [ -n "$CONFIGURED_TENANTS" ] && echo "$CONFIGURED_TENANTS" | grep -q "^$tenant_id$"; then
        print_color $YELLOW "$WARNING Tenant already configured"
        return
    fi
    
    # Generate admin consent URL
    local redirect_uri="https://portal.azure.com"
    local consent_url="https://login.microsoftonline.com/$tenant_id/adminconsent?client_id=$APP_ID&redirect_uri=$redirect_uri"
    
    print_color $GREEN "\n$CHECK_MARK Tenant configuration prepared"
    print_color $CYAN "\nAdmin consent required for tenant: $tenant_name"
    print_color $CYAN "════════════════════════════════════════════════════════════════"
    
    # Save tenant as pending
    save_tenant "$tenant_id" "$tenant_name" "pending"
    
    # Open browser automatically
    print_color $YELLOW "\n$INFO Opening browser for admin consent..."
    print_color $YELLOW "Please sign in as a Global Administrator and approve the permissions."
    
    open_browser "$consent_url"
    
    print_color $WHITE "\nConsent URL (if browser didn't open):"
    print_color $BLUE "$consent_url"
    
    echo
    read -p "Press Enter after completing the consent process..."
    
    # Update tenant status
    save_tenant "$tenant_id" "$tenant_name" "active"
    
    # Store credentials in Key Vault
    print_color $CYAN "$GEAR Storing tenant configuration in Key Vault..."
    
    # Create secret name
    secret_name="tenant-${tenant_id//-/}"
    
    # Store tenant info
    az keyvault secret set \
        --vault-name "$KEY_VAULT" \
        --name "$secret_name" \
        --value "{\"tenant_id\":\"$tenant_id\",\"tenant_name\":\"$tenant_name\",\"app_id\":\"$APP_ID\"}" \
        --output none
    
    print_color $GREEN "$CHECK_MARK Tenant '$tenant_name' successfully configured!"
    
    # Reload tenants
    load_tenants
}

# Function to resend consent URL
resend_consent() {
    print_section "Re-send Consent URL"
    
    if [ -z "$CONFIGURED_TENANTS" ]; then
        print_color $YELLOW "$WARNING No tenants configured"
        return
    fi
    
    print_color $CYAN "Select tenant:"
    local i=1
    declare -a tenant_array
    
    echo "$CONFIGURED_TENANTS" | while read -r tenant_id; do
        local name=$(jq -r ".\"$tenant_id\".name" "$TENANT_CONFIG_FILE")
        print_color $WHITE "  $i) $name"
        tenant_array[$i]=$tenant_id
        ((i++))
    done
    
    read -p "Select tenant number: " selection
    
    local selected_tenant="${tenant_array[$selection]}"
    if [ -z "$selected_tenant" ]; then
        print_color $RED "Invalid selection"
        return
    fi
    
    local redirect_uri="https://portal.azure.com"
    local consent_url="https://login.microsoftonline.com/$selected_tenant/adminconsent?client_id=$APP_ID&redirect_uri=$redirect_uri"
    
    print_color $YELLOW "\n$INFO Opening browser for admin consent..."
    open_browser "$consent_url"
    
    print_color $WHITE "\nConsent URL:"
    print_color $BLUE "$consent_url"
}

# Function to remove tenant
remove_tenant() {
    print_section "Remove Tenant"
    
    if [ -z "$CONFIGURED_TENANTS" ]; then
        print_color $YELLOW "$WARNING No tenants configured"
        return
    fi
    
    print_color $CYAN "Select tenant to remove:"
    local i=1
    declare -a tenant_array
    
    echo "$CONFIGURED_TENANTS" | while read -r tenant_id; do
        local name=$(jq -r ".\"$tenant_id\".name" "$TENANT_CONFIG_FILE")
        print_color $WHITE "  $i) $name"
        tenant_array[$i]=$tenant_id
        ((i++))
    done
    
    read -p "Select tenant number: " selection
    
    local selected_tenant="${tenant_array[$selection]}"
    if [ -z "$selected_tenant" ]; then
        print_color $RED "Invalid selection"
        return
    fi
    
    local tenant_name=$(jq -r ".\"$selected_tenant\".name" "$TENANT_CONFIG_FILE")
    
    print_color $YELLOW "$WARNING This will remove tenant '$tenant_name' from configuration"
    read -p "Are you sure? (y/N): " confirm
    
    if [ "$confirm" = "y" ] || [ "$confirm" = "Y" ]; then
        # Remove from config file
        local temp_file=$(mktemp)
        jq "del(.\"$selected_tenant\")" "$TENANT_CONFIG_FILE" > "$temp_file"
        mv "$temp_file" "$TENANT_CONFIG_FILE"
        
        # Remove from Key Vault
        secret_name="tenant-${selected_tenant//-/}"
        az keyvault secret delete --vault-name "$KEY_VAULT" --name "$secret_name" --output none 2>/dev/null || true
        
        print_color $GREEN "$CHECK_MARK Tenant removed successfully"
        load_tenants
    else
        print_color $YELLOW "Cancelled"
    fi
}

# Function to test tenant connection
test_tenant() {
    print_section "Test Tenant Connection"
    
    if [ -z "$CONFIGURED_TENANTS" ]; then
        print_color $YELLOW "$WARNING No tenants configured"
        return
    fi
    
    print_color $CYAN "Select tenant to test:"
    local i=1
    declare -a tenant_array
    
    echo "$CONFIGURED_TENANTS" | while read -r tenant_id; do
        local name=$(jq -r ".\"$tenant_id\".name" "$TENANT_CONFIG_FILE")
        print_color $WHITE "  $i) $name"
        tenant_array[$i]=$tenant_id
        ((i++))
    done
    
    read -p "Select tenant number: " selection
    
    local selected_tenant="${tenant_array[$selection]}"
    if [ -z "$selected_tenant" ]; then
        print_color $RED "Invalid selection"
        return
    fi
    
    local tenant_name=$(jq -r ".\"$selected_tenant\".name" "$TENANT_CONFIG_FILE")
    
    print_color $CYAN "$GEAR Testing connection to tenant: $tenant_name"
    
    # Try to get an access token
    print_color $CYAN "  Attempting to acquire token..."
    
    local token_response=$(curl -s -X POST \
        "https://login.microsoftonline.com/$selected_tenant/oauth2/v2.0/token" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "client_id=$APP_ID" \
        -d "scope=https://graph.microsoft.com/.default" \
        -d "grant_type=client_credentials")
    
    if echo "$token_response" | jq -e '.access_token' >/dev/null 2>&1; then
        print_color $GREEN "  $CHECK_MARK Successfully acquired token"
        print_color $GREEN "  $CHECK_MARK Tenant connection is working!"
    else
        local error=$(echo "$token_response" | jq -r '.error_description // .error' 2>/dev/null)
        print_color $RED "  $CROSS_MARK Failed to acquire token"
        print_color $RED "  Error: $error"
        print_color $YELLOW "\n  $INFO You may need to complete admin consent for this tenant"
    fi
}

# Main menu
main_menu() {
    while true; do
        print_section "Main Menu"
        
        print_color $WHITE "Deployment Status:"
        if [ -n "$EXISTING_RESOURCES" ]; then
            local resource_count=$(echo "$EXISTING_RESOURCES" | tr ',' '\n' | grep -v '^$' | wc -l)
            print_color $GREEN "  $CHECK_MARK $resource_count resources deployed"
        fi
        
        if [ -n "$CONFIGURED_TENANTS" ]; then
            local tenant_count=$(echo "$CONFIGURED_TENANTS" | wc -l)
            print_color $GREEN "  $CHECK_MARK $tenant_count tenant(s) configured"
        else
            print_color $YELLOW "  $INFO No tenants configured"
        fi
        
        echo
        print_color $WHITE "Options:"
        print_color $WHITE "  1) Run deployment inventory"
        print_color $WHITE "  2) Deploy/Update resources"
        print_color $WHITE "  3) Configure tenants"
        print_color $WHITE "  4) View deployment details"
        print_color $WHITE "  5) Export configuration"
        print_color $WHITE "  6) Exit"
        echo
        read -p "Select option (1-6): " choice
        
        case $choice in
            1)
                inventory_check
                ;;
            2)
                deploy_resources
                ;;
            3)
                tenant_menu
                ;;
            4)
                view_details
                ;;
            5)
                export_config
                ;;
            6)
                print_color $GREEN "\n$CHECK_MARK Thank you for using M365 Brain Crawl Deployment System!"
                exit 0
                ;;
            *)
                print_color $RED "Invalid option"
                ;;
        esac
    done
}

# Function to view deployment details
view_details() {
    print_section "Deployment Details"
    
    if [ -f "$CONFIG_FILE" ]; then
        print_color $CYAN "Resource Configuration:"
        jq -r 'to_entries[] | "  \(.key): \(.value)"' "$CONFIG_FILE"
    else
        print_color $YELLOW "$WARNING No deployment configuration found"
    fi
    
    echo
    print_color $CYAN "Configured Tenants:"
    if [ -f "$TENANT_CONFIG_FILE" ] && [ -n "$CONFIGURED_TENANTS" ]; then
        jq -r 'to_entries[] | "  \(.value.name) (\(.key)): \(.value.status)"' "$TENANT_CONFIG_FILE"
    else
        print_color $YELLOW "  No tenants configured"
    fi
    
    echo
    read -p "Press Enter to continue..."
}

# Function to export configuration
export_config() {
    print_section "Export Configuration"
    
    local export_file="m365-brain-export-$(date +%Y%m%d-%H%M%S).json"
    
    print_color $CYAN "$GEAR Exporting configuration to $export_file..."
    
    local export_data=$(jq -n \
        --slurpfile config "$CONFIG_FILE" \
        --slurpfile tenants "$TENANT_CONFIG_FILE" \
        '{
            deployment: $config[0],
            tenants: $tenants[0],
            export_date: now | strftime("%Y-%m-%dT%H:%M:%S%Z")
        }')
    
    echo "$export_data" | jq '.' > "$export_file"
    
    print_color $GREEN "$CHECK_MARK Configuration exported to $export_file"
    
    # Also create connection strings file
    local conn_file="m365-brain-connections-$(date +%Y%m%d-%H%M%S).txt"
    
    {
        echo "M365 Brain Crawl - Connection Information"
        echo "=========================================="
        echo
        echo "Function App URL: https://${FUNCTION_APP}.azurewebsites.net"
        echo "App Registration ID: $APP_ID"
        echo "Tenant ID: $TENANT_ID"
        echo
        echo "Key Vault: $KEY_VAULT"
        echo "Cosmos DB: $COSMOS_ACCOUNT"
        echo "Storage Account: $STORAGE_ACCOUNT"
        echo
        echo "Admin Consent URL Template:"
        echo "https://login.microsoftonline.com/{TENANT_ID}/adminconsent?client_id=$APP_ID"
        echo
        echo "Configured Tenants:"
        
        if [ -f "$TENANT_CONFIG_FILE" ] && [ -n "$CONFIGURED_TENANTS" ]; then
            jq -r 'to_entries[] | "  - \(.value.name): \(.key)"' "$TENANT_CONFIG_FILE"
        else
            echo "  None"
        fi
    } > "$conn_file"
    
    print_color $GREEN "$CHECK_MARK Connection details exported to $conn_file"
    
    echo
    read -p "Press Enter to continue..."
}

# Initialize script
initialize() {
    print_header
    check_prerequisites
    
    # Try to load existing configuration
    if load_configuration; then
        print_color $GREEN "$CHECK_MARK Loaded existing configuration"
        inventory_check
    else
        print_color $CYAN "$INFO No existing configuration found. Starting fresh deployment."
        
        # Get deployment parameters
        print_section "Deployment Configuration"
        
        read -p "Resource Group Name [m365-brain-rg]: " RESOURCE_GROUP
        RESOURCE_GROUP=${RESOURCE_GROUP:-"m365-brain-rg"}
        
        read -p "Location [eastus]: " LOCATION
        LOCATION=${LOCATION:-"eastus"}
        
        # Generate unique names
        UNIQUE_SUFFIX=$(head /dev/urandom | tr -dc 'a-z0-9' | head -c 8)
        
        read -p "Storage Account Name [m365brain$UNIQUE_SUFFIX]: " STORAGE_ACCOUNT
        STORAGE_ACCOUNT=${STORAGE_ACCOUNT:-"m365brain$UNIQUE_SUFFIX"}
        
        read -p "Cosmos DB Account Name [m365brain-cosmos-$UNIQUE_SUFFIX]: " COSMOS_ACCOUNT
        COSMOS_ACCOUNT=${COSMOS_ACCOUNT:-"m365brain-cosmos-$UNIQUE_SUFFIX"}
        
        read -p "Function App Name [m365brain-func-$UNIQUE_SUFFIX]: " FUNCTION_APP
        FUNCTION_APP=${FUNCTION_APP:-"m365brain-func-$UNIQUE_SUFFIX"}
        
        read -p "Key Vault Name [m365brain-kv-$UNIQUE_SUFFIX]: " KEY_VAULT
        KEY_VAULT=${KEY_VAULT:-"m365brain-kv-$UNIQUE_SUFFIX"}
        
        APP_SERVICE_PLAN="m365brain-plan-$UNIQUE_SUFFIX"
        APP_INSIGHTS="m365brain-insights-$UNIQUE_SUFFIX"
        
        save_configuration
        inventory_check
    fi
    
    # Load tenant configuration
    load_tenants
}

# Main execution
main() {
    initialize
    main_menu
}

# Run main function
main