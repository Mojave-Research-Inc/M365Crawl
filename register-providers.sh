# Quick fix - run this command to register the Cosmos DB provider:
az provider register --namespace Microsoft.DocumentDB --wait

# Or register all required providers:
for provider in Microsoft.DocumentDB Microsoft.Storage Microsoft.Web Microsoft.KeyVault; do
    echo "Registering $provider..."
    az provider register --namespace "$provider"
done

# Check registration status:
az provider show --namespace Microsoft.DocumentDB --query registrationState -o tsv
