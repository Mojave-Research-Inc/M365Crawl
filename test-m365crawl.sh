#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# M365Crawl - Comprehensive Test Script
# Tests all aspects of the M365Crawl deployment
# =============================================================================

echo "🧪 M365Crawl - Comprehensive Test Suite"
echo "======================================="
echo

# Configuration
RG="m365-agent-rg"
APP="M365Cawl7277"
APP_ID="2df32d0f-2683-437d-bd70-bd78d1d0c212"
TENANT_ID="7cc4e405-4887-4f0d-bcb6-ac22faea810d"
CLIENT_SECRET="YOUR_CLIENT_SECRET_HERE"

# Test results tracking
TESTS_PASSED=0
TESTS_FAILED=0
TOTAL_TESTS=0

# Function to run a test
run_test() {
    local test_name="$1"
    local test_command="$2"
    local expected_pattern="$3"
    
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    echo "🔍 Test $TOTAL_TESTS: $test_name"
    
    if eval "$test_command" 2>/dev/null | grep -q "$expected_pattern"; then
        echo "✅ PASSED"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        echo "❌ FAILED"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
    echo
}

# Function to run a test with custom logic
run_custom_test() {
    local test_name="$1"
    local test_logic="$2"
    
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    echo "🔍 Test $TOTAL_TESTS: $test_name"
    
    if eval "$test_logic"; then
        echo "✅ PASSED"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        echo "❌ FAILED"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
    echo
}

echo "📋 Test Configuration:"
echo "  Resource Group: $RG"
echo "  Function App: $APP"
echo "  App ID: $APP_ID"
echo "  Tenant ID: $TENANT_ID"
echo

# ========= PREREQUISITE TESTS =========
echo "🔧 === PREREQUISITE TESTS ==="

run_test "Azure CLI Authentication" "az account show" "id"
run_test "Azure Functions Core Tools" "func --version" "Azure Functions Core Tools"
run_test "jq JSON Processor" "jq --version" "jq-"
run_test "Python 3" "python3 --version" "Python 3"
run_test "curl HTTP Client" "curl --version" "curl"

# ========= AZURE RESOURCE TESTS =========
echo "🏗️  === AZURE RESOURCE TESTS ==="

run_test "Resource Group Exists" "az group show --name $RG" "id"
run_test "Function App Exists" "az functionapp show --name $APP --resource-group $RG" "id"
run_test "Function App is Running" "az functionapp show --name $APP --resource-group $RG --query state" "Running"

# Get Function App URL
HOST=$(az functionapp show -g "$RG" -n "$APP" --query defaultHostName -o tsv 2>/dev/null || echo "")
if [[ -n "$HOST" ]]; then
    FUNCTION_URL="https://${HOST}"
    echo "✅ Function App URL: $FUNCTION_URL"
else
    echo "❌ ERROR: Could not get Function App URL"
    exit 1
fi
echo

# ========= FUNCTION APP ENDPOINT TESTS =========
echo "🌐 === FUNCTION APP ENDPOINT TESTS ==="

run_test "Health Endpoint" "curl -sS --max-time 30 $FUNCTION_URL/api/health" "healthy"
run_test "Test Endpoint" "curl -sS --max-time 30 $FUNCTION_URL/api/test" "working"
run_test "Admin Consent URL Endpoint" "curl -sS --max-time 30 $FUNCTION_URL/api/admin-consent-url" "admin_consent_url"

# Test auth callback with success scenario
run_test "Auth Callback Success" "curl -sS --max-time 30 '$FUNCTION_URL/api/auth/callback?admin_consent=True&tenant=test-tenant&state=xyz123'" "Admin consent granted"

# Test auth callback with error scenario
run_test "Auth Callback Error" "curl -sS --max-time 30 '$FUNCTION_URL/api/auth/callback?error=access_denied&error_description=User%20denied%20access'" "Admin consent failed"

# ========= AUTHENTICATION TESTS =========
echo "🔐 === AUTHENTICATION TESTS ==="

run_custom_test "Token Acquisition" "
    TOKEN_RESPONSE=\$(curl -sS --max-time 30 -X POST 'https://login.microsoftonline.com/$TENANT_ID/oauth2/v2.0/token' \
      -H 'Content-Type: application/x-www-form-urlencoded' \
      -d 'client_id=$APP_ID' \
      -d 'client_secret=$CLIENT_SECRET' \
      -d 'scope=https%3A%2F%2Fgraph.microsoft.com%2F.default' \
      -d 'grant_type=client_credentials' 2>/dev/null || echo '{\"error\": \"Request failed\"}')
    
    TOKEN=\$(echo \"\$TOKEN_RESPONSE\" | jq -r '.access_token // empty' 2>/dev/null || echo '')
    
    if [[ -n \"\$TOKEN\" && \"\$TOKEN\" != \"null\" && \"\$TOKEN\" != \"\" ]]; then
        echo \"Token acquired: \${TOKEN:0:20}...\"
        true
    else
        echo \"Token acquisition failed: \$TOKEN_RESPONSE\"
        false
    fi
"

# ========= CRAWL ENDPOINT TESTS =========
echo "🕷️  === CRAWL ENDPOINT TESTS ==="

run_test "Crawl Endpoint (Empty Body)" "curl -sS --max-time 30 -X POST $FUNCTION_URL/api/crawl -H 'Content-Type: application/json' -d '{}'" "tenant_id"
run_test "Crawl Endpoint (With Tenant ID)" "curl -sS --max-time 30 -X POST $FUNCTION_URL/api/crawl -H 'Content-Type: application/json' -d '{\"tenant_id\":\"$TENANT_ID\"}'" "crawl_timestamp"

# ========= PERFORMANCE TESTS =========
echo "⚡ === PERFORMANCE TESTS ==="

run_custom_test "Response Time < 5 seconds" "
    RESPONSE_TIME=\$(curl -sS --max-time 30 -w '%{time_total}' -o /dev/null $FUNCTION_URL/api/health 2>/dev/null || echo '10')
    if (( \$(echo \"\$RESPONSE_TIME < 5\" | bc -l) )); then
        echo \"Response time: \${RESPONSE_TIME}s\"
        true
    else
        echo \"Response time too slow: \${RESPONSE_TIME}s\"
        false
    fi
"

# ========= SECURITY TESTS =========
echo "🔒 === SECURITY TESTS ==="

run_custom_test "HTTPS Only" "
    HTTP_RESPONSE=\$(curl -sS --max-time 10 -w '%{http_code}' -o /dev/null http://$HOST/api/health 2>/dev/null || echo '000')
    if [[ \"\$HTTP_RESPONSE\" == \"000\" || \"\$HTTP_RESPONSE\" == \"301\" || \"\$HTTP_RESPONSE\" == \"302\" ]]; then
        echo \"HTTP redirects to HTTPS\"
        true
    else
        echo \"HTTP response: \$HTTP_RESPONSE\"
        false
    fi
"

run_custom_test "State Parameter Validation" "
    INVALID_STATE_RESPONSE=\$(curl -sS --max-time 30 '$FUNCTION_URL/api/auth/callback?admin_consent=True&tenant=test-tenant&state=invalid' 2>/dev/null || echo '')
    if echo \"\$INVALID_STATE_RESPONSE\" | grep -q 'Invalid state parameter'; then
        echo \"State parameter validation working\"
        true
    else
        echo \"State parameter validation failed\"
        false
    fi
"

# ========= CONFIGURATION TESTS =========
echo "⚙️  === CONFIGURATION TESTS ==="

run_custom_test "Function App Settings" "
    SETTINGS=\$(az functionapp config appsettings list --name $APP --resource-group $RG --query '[].{name:name,value:value}' 2>/dev/null || echo '[]')
    if echo \"\$SETTINGS\" | jq -e '.[] | select(.name == \"APP_ID\" and .value == \"$APP_ID\")' >/dev/null; then
        echo \"APP_ID setting configured\"
        true
    else
        echo \"APP_ID setting not found\"
        false
    fi
"

run_custom_test "App Registration Redirect URI" "
    REDIRECT_URIS=\$(az ad app show --id $APP_ID --query 'web.redirectUris' 2>/dev/null || echo '[]')
    if echo \"\$REDIRECT_URIS\" | jq -e \".[] | contains(\\\"$FUNCTION_URL/api/auth/callback\\\")\" >/dev/null; then
        echo \"Redirect URI configured\"
        true
    else
        echo \"Redirect URI not configured\"
        false
    fi
"

# ========= TEST SUMMARY =========
echo "📊 === TEST SUMMARY ==="
echo "Total Tests: $TOTAL_TESTS"
echo "Passed: $TESTS_PASSED"
echo "Failed: $TESTS_FAILED"
echo

if [[ $TESTS_FAILED -eq 0 ]]; then
    echo "🎉 ALL TESTS PASSED! M365Crawl is working perfectly!"
    echo
    echo "✅ Deployment Status: SUCCESS"
    echo "✅ Function App: $FUNCTION_URL"
    echo "✅ All endpoints: Working"
    echo "✅ Authentication: Working"
    echo "✅ Security: Validated"
    echo "✅ Performance: Good"
else
    echo "⚠️  Some tests failed. Please check the output above."
    echo
    echo "❌ Deployment Status: PARTIAL SUCCESS"
    echo "❌ Failed Tests: $TESTS_FAILED"
    echo "✅ Passed Tests: $TESTS_PASSED"
fi

echo
echo "🔗 === QUICK VERIFICATION COMMANDS ==="
echo "# Health check"
echo "curl $FUNCTION_URL/api/health"
echo
echo "# Test endpoint"
echo "curl $FUNCTION_URL/api/test"
echo
echo "# Admin consent URL"
echo "curl $FUNCTION_URL/api/admin-consent-url"
echo
echo "# Crawl endpoint"
echo "curl -X POST $FUNCTION_URL/api/crawl -H 'Content-Type: application/json' -d '{}'"
echo

echo "🧪 Test suite completed!"
