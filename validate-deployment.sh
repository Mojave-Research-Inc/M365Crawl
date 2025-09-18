#!/usr/bin/env bash
set -euo pipefail

########################################
# M365 Brain Crawl - Deployment Validator
# Validates the one-click-deploy.sh script fixes
########################################

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Test functions
test_pass() {
    TESTS_PASSED=$((TESTS_PASSED + 1))
    echo -e "${GREEN}✓${NC} $1"
}

test_fail() {
    TESTS_FAILED=$((TESTS_FAILED + 1))
    echo -e "${RED}✗${NC} $1"
    echo "  Error: $2"
}

run_test() {
    TESTS_RUN=$((TESTS_RUN + 1))
    echo -n "Testing: $1... "
}

echo "======================================================================"
echo "           M365 BRAIN CRAWL - DEPLOYMENT VALIDATOR"
echo "======================================================================"
echo ""

# Test 1: Check if script exists
run_test "Script existence"
if [[ -f "one-click-deploy.sh" ]]; then
    test_pass "one-click-deploy.sh exists"
else
    test_fail "one-click-deploy.sh not found" "Script file missing"
fi

# Test 2: Check bash syntax
run_test "Bash syntax validation"
if bash -n one-click-deploy.sh 2>/dev/null; then
    test_pass "No bash syntax errors"
else
    test_fail "Bash syntax errors found" "$(bash -n one-click-deploy.sh 2>&1)"
fi

# Test 3: Check for Cosmos DB fix
run_test "Cosmos DB --locations parameter fix"
if grep -q 'regionName="\$LOCATION" failoverPriority=0' one-click-deploy.sh; then
    test_pass "Cosmos DB creation uses correct --locations syntax"
else
    test_fail "Cosmos DB still using old syntax" "Missing regionName= format"
fi

# Test 4: Check for enhanced error handling
run_test "Enhanced error handling functions"
if grep -q "retry_with_backoff()" one-click-deploy.sh; then
    test_pass "retry_with_backoff function found"
else
    test_fail "Enhanced retry logic missing" "retry_with_backoff not found"
fi

# Test 5: Check for structured logging
run_test "Structured logging functions"
if grep -q "log_info()" one-click-deploy.sh && grep -q "log_error()" one-click-deploy.sh; then
    test_pass "Structured logging functions present"
else
    test_fail "Structured logging missing" "log_info/log_error not found"
fi

# Test 6: Check for state management
run_test "State management functions"
if grep -q "save_state()" one-click-deploy.sh && grep -q "check_state()" one-click-deploy.sh; then
    test_pass "State management functions present"
else
    test_fail "State management missing" "save_state/check_state not found"
fi

# Test 7: Check storage account security settings
run_test "Storage account security enhancements"
if grep -q -- "--min-tls-version TLS1_2" one-click-deploy.sh; then
    test_pass "Storage account has TLS 1.2 minimum"
else
    test_fail "Storage account missing TLS 1.2 setting" "Add --min-tls-version TLS1_2"
fi

# Test 8: Check Key Vault security settings
run_test "Key Vault security enhancements"
if grep -q -- "--enable-soft-delete true" one-click-deploy.sh; then
    test_pass "Key Vault has soft-delete enabled"
else
    test_fail "Key Vault missing soft-delete" "Add --enable-soft-delete true"
fi

# Test 9: Check for potential security issues
run_test "Security: No hardcoded credentials"
if grep -qE "(password|secret|key)=['\"].*['\"]" one-click-deploy.sh; then
    test_fail "Potential hardcoded credentials found" "Review for exposed secrets"
else
    test_pass "No obvious hardcoded credentials"
fi

# Test 10: Check for proper variable quoting
run_test "Variable quoting"
UNQUOTED_VARS=$(grep -E '\$[A-Z_]+[^"{}]' one-click-deploy.sh | grep -v '^\s*#' | wc -l)
if [[ $UNQUOTED_VARS -lt 10 ]]; then
    test_pass "Most variables appear properly quoted"
else
    echo -e "${YELLOW}⚠${NC} Some variables may need quoting (found $UNQUOTED_VARS potential issues)"
fi

# Test 11: Check Azure CLI command structure
run_test "Azure CLI command validation"
if grep -q "az.*--output none" one-click-deploy.sh; then
    test_pass "Azure CLI commands use --output none for clean output"
else
    echo -e "${YELLOW}⚠${NC} Some Azure CLI commands may produce unwanted output"
fi

# Test 12: Check for error trapping
run_test "Error trapping"
if grep -q "set -euo pipefail" one-click-deploy.sh; then
    test_pass "Script has proper error trapping (set -euo pipefail)"
else
    test_fail "Missing error trapping" "Add 'set -euo pipefail' at script start"
fi

# Test 13: Validate resource naming
run_test "Resource name validation logic"
if grep -q "validate_resource_name()" one-click-deploy.sh; then
    test_pass "Resource name validation function exists"
else
    echo -e "${YELLOW}⚠${NC} Resource name validation could be improved"
fi

# Test 14: Check for deployment prerequisites
run_test "Deployment prerequisites check"
if grep -q "command -v az" one-click-deploy.sh; then
    test_pass "Azure CLI availability check present"
else
    echo -e "${YELLOW}⚠${NC} Should verify Azure CLI is installed"
fi

# Test 15: Check for cleanup functions
run_test "Cleanup and rollback functions"
if grep -q "cleanup" one-click-deploy.sh; then
    test_pass "Cleanup functions present"
else
    echo -e "${YELLOW}⚠${NC} Consider adding cleanup on failure"
fi

echo ""
echo "======================================================================"
echo "                          TEST SUMMARY"
echo "======================================================================"
echo "Tests Run:    $TESTS_RUN"
echo -e "Tests Passed: ${GREEN}$TESTS_PASSED${NC}"
echo -e "Tests Failed: ${RED}$TESTS_FAILED${NC}"

if [[ $TESTS_FAILED -eq 0 ]]; then
    echo ""
    echo -e "${GREEN}✅ All critical fixes have been applied successfully!${NC}"
    echo ""
    echo "The script is ready for deployment testing."
    exit 0
else
    echo ""
    echo -e "${RED}❌ Some tests failed. Please review the issues above.${NC}"
    echo ""
    echo "Critical fixes needed before deployment:"
    echo "1. Cosmos DB --locations parameter must use regionName= syntax"
    echo "2. Enhanced error handling functions must be present"
    echo "3. Security settings must be properly configured"
    exit 1
fi