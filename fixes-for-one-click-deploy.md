# Comprehensive Fixes for one-click-deploy.sh

## Critical Issues Found and Fixed

### 1. Cosmos DB Creation Syntax Error (Line 417-425)
**Issue**: Using deprecated `--location` parameter instead of `--locations` with proper syntax
**Error**: "list index out of range" in Azure CLI

**Current Code (BROKEN):**
```bash
az cosmosdb create \
    --name "$COSMOS_ACCOUNT" \
    --resource-group "$RG_NAME" \
    --location "$LOCATION" \
    --kind GlobalDocumentDB \
    --default-consistency-level Session \
    --enable-automatic-failover false \
    --enable-multiple-write-locations false \
    --output none
```

**Fixed Code:**
```bash
az cosmosdb create \
    --name "$COSMOS_ACCOUNT" \
    --resource-group "$RG_NAME" \
    --locations regionName="$LOCATION" failoverPriority=0 isZoneRedundant=False \
    --kind GlobalDocumentDB \
    --default-consistency-level Session \
    --enable-automatic-failover false \
    --enable-multiple-write-locations false \
    --output none
```

### 2. Additional Azure CLI Issues to Fix

#### Storage Account Creation (Lines around 380-400)
- Add `--allow-blob-public-access false` for security
- Add `--min-tls-version TLS1_2`
- Add `--https-only true`

#### Key Vault Creation (Lines around 504)
- Add `--enable-rbac-authorization true` for better security
- Add `--network-acls-default-action Deny` with proper exceptions
- Add `--enable-purge-protection true`

#### Function App Creation (Lines around 680)
- Add `--https-only true`
- Add `--min-tls-version 1.2`
- Update runtime version specifications

### 3. Security Vulnerabilities

#### Credentials in Environment Variables
- Never echo sensitive values
- Use Key Vault references for all secrets
- Implement proper secret rotation

#### Missing Network Security
- Add private endpoints where possible
- Implement IP restrictions
- Enable firewall rules

### 4. Error Handling Improvements

#### Enhanced Retry Logic
```bash
retry_with_backoff() {
    local max_attempts=5
    local timeout=60
    local attempt=1
    local exitCode=0
    local wait_time=5

    while [[ $attempt -le $max_attempts ]]; do
        if "$@"; then
            return 0
        else
            exitCode=$?
        fi

        echo "Attempt $attempt failed! Retrying in $wait_time seconds..."
        sleep $wait_time
        attempt=$(( attempt + 1 ))
        wait_time=$(( wait_time * 2 ))
    done

    echo "Command failed after $max_attempts attempts"
    return $exitCode
}
```

### 5. Logging Improvements

#### Structured Logging
```bash
# Add timestamp and severity to all logs
log_info() {
    echo "[$(date -u +"%Y-%m-%d %H:%M:%S UTC")] [INFO] $*" | tee -a "$LOG_FILE"
}

log_error() {
    echo "[$(date -u +"%Y-%m-%d %H:%M:%S UTC")] [ERROR] $*" >&2 | tee -a "$LOG_FILE"
}

log_debug() {
    if [[ "${DEBUG:-false}" == "true" ]]; then
        echo "[$(date -u +"%Y-%m-%d %H:%M:%S UTC")] [DEBUG] $*" | tee -a "$LOG_FILE"
    fi
}
```

### 6. Resource Validation Enhancements

#### Pre-deployment Checks
```bash
validate_prerequisites() {
    # Check Azure CLI version
    local az_version=$(az version --query '"azure-cli"' -o tsv)
    if [[ ! "$az_version" =~ ^2\.(5[0-9]|[6-9][0-9]) ]]; then
        error "Azure CLI version 2.50+ required. Current: $az_version"
        exit 1
    fi

    # Check subscription quota
    local cores_usage=$(az vm list-usage --location "$LOCATION" --query "[?name.value=='cores'].currentValue" -o tsv)
    if [[ $cores_usage -gt 90 ]]; then
        warn "High core usage in region: $cores_usage%. Consider another region."
    fi

    # Validate region availability
    if ! az account list-locations --query "[?name=='$LOCATION']" -o tsv | grep -q "$LOCATION"; then
        error "Invalid Azure region: $LOCATION"
        exit 1
    fi
}
```

### 7. Deployment State Management

#### State File for Idempotency
```bash
STATE_FILE="${HOME}/.m365brain/deployment.state"
mkdir -p "$(dirname "$STATE_FILE")"

save_state() {
    local step=$1
    local status=$2
    echo "$(date -u +%s)|$step|$status" >> "$STATE_FILE"
}

check_state() {
    local step=$1
    if grep -q "|$step|completed" "$STATE_FILE" 2>/dev/null; then
        return 0
    fi
    return 1
}
```

### 8. Cleanup and Rollback

#### Safe Cleanup Function
```bash
cleanup_on_failure() {
    local exit_code=$?
    if [[ $exit_code -ne 0 ]]; then
        error "Deployment failed with exit code: $exit_code"
        
        read -p "Do you want to clean up partially created resources? (y/n): " -r
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            log_info "Starting cleanup..."
            
            # Delete resource group (cascades to all resources)
            if az group exists --name "$RG_NAME" 2>/dev/null; then
                az group delete --name "$RG_NAME" --yes --no-wait
                log_info "Resource group deletion initiated"
            fi
            
            # Clean up app registration if created
            if [[ -n "${APP_ID:-}" ]]; then
                az ad app delete --id "$APP_ID" 2>/dev/null || true
                log_info "App registration cleaned up"
            fi
        fi
    fi
}

trap cleanup_on_failure EXIT
```

### 9. Performance Optimizations

#### Parallel Resource Creation
```bash
# Create resources in parallel where possible
create_resources_parallel() {
    local pids=()
    
    # Start storage account creation
    (create_storage_account) & pids+=($!)
    
    # Start Key Vault creation
    (create_keyvault) & pids+=($!)
    
    # Start Service Bus creation  
    (create_servicebus) & pids+=($!)
    
    # Wait for all parallel jobs
    for pid in "${pids[@]}"; do
        if ! wait "$pid"; then
            error "Parallel resource creation failed"
            return 1
        fi
    done
}
```

### 10. Production-Ready Enhancements

#### Health Checks
```bash
verify_deployment() {
    local failed_checks=0
    
    # Check Cosmos DB
    if ! az cosmosdb show --name "$COSMOS_ACCOUNT" --resource-group "$RG_NAME" &>/dev/null; then
        error "Cosmos DB verification failed"
        ((failed_checks++))
    fi
    
    # Check Function App
    if ! az functionapp show --name "$FUNCAPP_NAME" --resource-group "$RG_NAME" &>/dev/null; then
        error "Function App verification failed"
        ((failed_checks++))
    fi
    
    # Check Key Vault
    if ! az keyvault show --name "$KEYVAULT_NAME" --resource-group "$RG_NAME" &>/dev/null; then
        error "Key Vault verification failed"
        ((failed_checks++))
    fi
    
    if [[ $failed_checks -gt 0 ]]; then
        error "Deployment verification failed with $failed_checks errors"
        return 1
    fi
    
    success "All resources verified successfully"
}
```

## Implementation Priority

1. **CRITICAL**: Fix Cosmos DB --locations parameter (prevents deployment)
2. **HIGH**: Add proper error handling and retry logic
3. **HIGH**: Fix security vulnerabilities
4. **MEDIUM**: Improve logging and monitoring
5. **MEDIUM**: Add deployment state management
6. **LOW**: Performance optimizations

## Testing Recommendations

1. Test in a dev subscription first
2. Use --dry-run flag for validation
3. Implement unit tests for functions
4. Add integration tests for Azure resources
5. Monitor with Application Insights

## Next Steps

1. Apply the Cosmos DB fix immediately
2. Review and apply security fixes
3. Test thoroughly in non-production
4. Add monitoring and alerting
5. Document all changes